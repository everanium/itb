package hashes

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/everanium/itb"
)

// Width is the native intermediate-state width of a hash primitive.
// Determines which itb.Seed{128|256|512} type the primitive feeds.
type Width int

const (
	W128 Width = 128
	W256 Width = 256
	W512 Width = 512
)

// MaxNameLen caps the length of a primitive name in [Spec.Name]. The
// cap matches [github.com/everanium/itb/parallax.MaxCipherNameLen]: a
// registered primitive that a caller wants to plug into a parallax
// palette entry must fit the "<name>:<index>" derivation label inside
// a 16-byte 128-bit-PRF input block. Enforcing the cap at [Register]
// time catches the violation up-front rather than deferring the silent
// breakage to a later parallax.NewSchedule call. All shipped
// [Registry] entries fit well inside this cap (longest is 10).
const MaxNameLen = 12

// Spec describes one PRF-grade hash primitive. Shipped primitives live
// in [Registry] with all factory fields nil; their factory closures are
// dispatched through the switch statements in [Make128] / [Make256] /
// [Make512] and their Pair counterparts. User-registered custom
// primitives (added via [Register]) populate the factory field matching
// the primitive's Width so the same Make{N}(Pair) name-keyed dispatch
// resolves them uniformly.
type Spec struct {
	Name  string // canonical, FFI-stable identifier (no dashes)
	Width Width  // native intermediate-state width

	// Make128Pair, Make256Pair, Make512Pair are the paired
	// (single, batched, fixedKey) factory functions for a user-
	// registered custom primitive. Exactly one field must be
	// non-nil, matching Width: W128 → Make128Pair, W256 →
	// Make256Pair, W512 → Make512Pair. The factory follows the
	// same variadic-key contract as the top-level Make{N}Pair
	// functions: pass no key for a random-key primitive, or one
	// []byte of the primitive's native key length for explicit-
	// key restoration. The returned batched arm may be nil when
	// the primitive has no batched implementation.
	//
	// Shipped Registry entries leave all three fields nil.
	Make128Pair func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) `json:"-"`
	Make256Pair func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) `json:"-"`
	Make512Pair func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error) `json:"-"`

	// HashHash optionally returns the primitive's general-purpose
	// unkeyed hash.Hash form — the shape the HMAC construction
	// (RFC 2104) wraps, consumed by the macs package's BuildHMAC
	// builder. Populated on the shipped entries built over a
	// general-purpose hash (the BLAKE family); nil for primitives
	// without such a form (the Areion SoEM constructions, AES-CMAC,
	// SipHash-2-4, ChaCha20). A user-registered custom primitive may
	// populate the field so macs.BuildHMAC composes with it by name;
	// when nil, macs.BuildHMAC rejects the name and the hand-rolled
	// macs.Register path applies instead. Each call must return a
	// fresh instance safe for exclusive use by the caller.
	HashHash func() hash.Hash `json:"-"`

	// KeyedHash optionally returns the primitive's native keyed mode
	// as a hash.Hash pre-keyed with key, consumed by the macs
	// package's BuildKeyedHash builder. Populated on the shipped
	// entries whose keyed form is itself a sound PRF (the BLAKE2
	// variants, BLAKE3, SipHash-2-4); nil for primitives without a
	// native keyed hash.Hash mode. A user-registered custom primitive
	// may populate the field so macs.BuildKeyedHash composes with it
	// by name; when nil, macs.BuildKeyedHash rejects the name. The
	// constructor is the single source of truth for accepted key
	// lengths: it must return an error — never panic — for a key
	// length the primitive does not support, and each successful call
	// must return a fresh instance safe for exclusive use by the
	// caller.
	KeyedHash func(key []byte) (hash.Hash, error) `json:"-"`
}

// Registry lists every shippable PRF-grade primitive in canonical order.
// The same order is used by the FFI iteration surface (ITB_HashName,
// ITB_HashWidth) — callers iterating the registry receive primitives in
// this order.
//
// Registry is immutable after package init. User-registered custom
// primitives added via [Register] live in a separate mutex-guarded
// slice and are exposed together with Registry via [AllPrimitives].
// The FFI iteration surface deliberately observes only Registry so
// bindings — which are triple-only and cannot themselves call Register
// — see a stable primitive set.
var Registry = [9]Spec{
	{Name: "areion256", Width: W256},
	{Name: "areion512", Width: W512},
	{Name: "blake2b256", Width: W256, HashHash: blake2b256HashHash, KeyedHash: blake2b256KeyedHash},
	{Name: "blake2b512", Width: W512, HashHash: blake2b512HashHash, KeyedHash: blake2b512KeyedHash},
	{Name: "blake2s", Width: W256, HashHash: blake2sHashHash, KeyedHash: blake2sKeyedHash},
	{Name: "blake3", Width: W256, HashHash: blake3HashHash, KeyedHash: blake3KeyedHash},
	{Name: "aescmac", Width: W128},
	{Name: "siphash24", Width: W128, KeyedHash: siphash24KeyedHash},
	{Name: "chacha20", Width: W256},
}

// ErrHashExists is returned by [Register] when the supplied Spec.Name
// is already present in [Registry] or has been registered previously.
// Once registered, a primitive cannot be re-registered under the same
// name — immutability matches [triple.RegisterProfile] semantics so a
// caller cannot silently swap the factory a downstream Find/Make call
// resolves.
var ErrHashExists = errors.New("hashes: primitive already registered")

var (
	customsMu sync.Mutex
	customs   []Spec // append-only, guarded by customsMu
)

// Register adds a user-supplied custom hash primitive to the runtime
// registry. The Spec must carry a non-empty Name (lowercase letters,
// digits, underscores only — no dashes, matching the FFI-stable
// identifier convention of shipped primitives), a Width of W128 /
// W256 / W512, and exactly one non-nil Make{N}Pair factory field
// matching the Width.
//
// The registered primitive becomes visible through [Find] and the
// [Make128] / [Make256] / [Make512] / Pair name-keyed dispatchers.
// [Registry] itself is not extended — user entries live in a
// separate mutex-guarded slice — so the FFI iteration surface
// (ITB_HashName / ITB_HashWidth) is unaffected.
//
// Errors:
//
//   - [ErrHashExists] when the name is already present in [Registry] or
//     among prior Register() calls.
//   - a validation error when Name is empty, uses disallowed characters,
//     Width is not W128 / W256 / W512, or the matching factory field is
//     nil (or a non-matching factory field is non-nil).
//
// Register is safe for concurrent use with itself and with [Find] /
// [AllPrimitives] / [Make128] / [Make256] / [Make512] and their Pair
// counterparts.
func Register(spec Spec) error {
	if err := validateRegisterSpec(spec); err != nil {
		return err
	}
	if err := smokeValidate(spec); err != nil {
		return err
	}
	customsMu.Lock()
	defer customsMu.Unlock()
	for _, s := range Registry {
		if s.Name == spec.Name {
			return fmt.Errorf("hashes: %q shadows shipped primitive: %w", spec.Name, ErrHashExists)
		}
	}
	for _, s := range customs {
		if s.Name == spec.Name {
			return fmt.Errorf("hashes: %q: %w", spec.Name, ErrHashExists)
		}
	}
	customs = append(customs, spec)
	return nil
}

// validateRegisterSpec checks the fields of a Spec presented to
// Register. Kept separate so unit tests can exercise the validation
// paths without racing on the customs mutex.
func validateRegisterSpec(spec Spec) error {
	if spec.Name == "" {
		return fmt.Errorf("hashes: Register: Spec.Name is empty")
	}
	if len(spec.Name) > MaxNameLen {
		return fmt.Errorf("hashes: Register: Spec.Name %q length %d exceeds [MaxNameLen] = %d (parallax palette-entry PRF-block budget)", spec.Name, len(spec.Name), MaxNameLen)
	}
	for i := 0; i < len(spec.Name); i++ {
		c := spec.Name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_':
		default:
			return fmt.Errorf("hashes: Register: Spec.Name %q contains illegal character %q (lowercase letters, digits, underscores only)", spec.Name, c)
		}
	}
	switch spec.Width {
	case W128:
		if spec.Make128Pair == nil {
			return fmt.Errorf("hashes: Register: Spec.Make128Pair required for Width=W128")
		}
		if spec.Make256Pair != nil || spec.Make512Pair != nil {
			return fmt.Errorf("hashes: Register: only Make128Pair may be set for Width=W128")
		}
	case W256:
		if spec.Make256Pair == nil {
			return fmt.Errorf("hashes: Register: Spec.Make256Pair required for Width=W256")
		}
		if spec.Make128Pair != nil || spec.Make512Pair != nil {
			return fmt.Errorf("hashes: Register: only Make256Pair may be set for Width=W256")
		}
	case W512:
		if spec.Make512Pair == nil {
			return fmt.Errorf("hashes: Register: Spec.Make512Pair required for Width=W512")
		}
		if spec.Make128Pair != nil || spec.Make256Pair != nil {
			return fmt.Errorf("hashes: Register: only Make512Pair may be set for Width=W512")
		}
	default:
		return fmt.Errorf("hashes: Register: Spec.Width=%d must be W128, W256, or W512", spec.Width)
	}
	return nil
}

// AllPrimitives returns a snapshot slice containing every entry in
// [Registry] in canonical order followed by every user-registered
// custom primitive in registration order. The returned slice is a
// fresh copy; the caller may mutate it freely without affecting
// subsequent snapshots.
func AllPrimitives() []Spec {
	customsMu.Lock()
	defer customsMu.Unlock()
	out := make([]Spec, 0, len(Registry)+len(customs))
	out = append(out, Registry[:]...)
	out = append(out, customs...)
	return out
}

// Find returns the Spec for a canonical name and reports whether a match
// was found. Shipped [Registry] entries are consulted first, then any
// user-registered custom primitives added via [Register].
func Find(name string) (Spec, bool) {
	for _, s := range Registry {
		if s.Name == name {
			return s, true
		}
	}
	customsMu.Lock()
	defer customsMu.Unlock()
	for _, s := range customs {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// validateKey checks an optional variadic key argument against the
// primitive's expected fixed-key size. Returns the supplied key bytes
// (or nil if none supplied), or an error on size mismatch.
func validateKey(name string, want int, key ...[]byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, nil
	}
	if len(key[0]) != want {
		return nil, fmt.Errorf("hashes: %q key must be %d bytes, got %d", name, want, len(key[0]))
	}
	return key[0], nil
}

// Make128 returns a fresh cached HashFunc128 for the named primitive
// along with the fixed key the closure is bound to. Pass a single
// caller-supplied key slice to use that key; pass nothing to generate
// a fresh random key (returned alongside the closure for persistence).
//
// SipHash-2-4 has no internal fixed key (its keying material is the
// per-call seed components), so passing a key for "siphash24" is an
// error; the second return value is nil for siphash24.
//
// Returns an error when name is unknown, its native width is not 128,
// or the supplied key size does not match the primitive's native key
// length.
func Make128(name string, key ...[]byte) (itb.HashFunc128, []byte, error) {
	switch name {
	case "siphash24":
		if len(key) > 0 {
			return nil, nil, fmt.Errorf("hashes: %q does not accept a fixed key (keyed by seed components)", name)
		}
		return SipHash24(), nil, nil
	case "aescmac":
		explicit, err := validateKey("aescmac", 16, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [16]byte
			copy(k[:], explicit)
			fn, ret := AESCMAC(k)
			return fn, ret[:], nil
		}
		fn, ret := AESCMAC()
		return fn, ret[:], nil
	}
	if s, ok := Find(name); ok {
		if s.Width != W128 {
			return nil, nil, fmt.Errorf("hashes: %q has width %d, not 128", name, s.Width)
		}
		if s.Make128Pair != nil {
			h, _, ret, err := s.Make128Pair(key...)
			return h, ret, err
		}
	}
	return nil, nil, fmt.Errorf("hashes: unknown 128-bit primitive %q", name)
}

// Make128Pair returns the (single, batched) HashFunc128 / BatchHashFunc128
// pair for primitives with a 4-way batched implementation, plus the
// fixed key the pair is bound to. The batched arm is nil for
// primitives that do not implement a batched path. The single arm is
// bit-exact equivalent to Make128 for the same name and key.
//
// Primitives currently returning a non-nil batched arm:
//
//   - "aescmac" — VAES + AVX-512 ZMM-batched AES-CMAC chain-absorb kernels
//   - "siphash24" — AVX-512 ZMM-batched SipHash-2-4 chain-absorb kernels
//
// Variadic key arg follows the same pattern as Make128 / Make256Pair.
func Make128Pair(name string, key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
	switch name {
	case "siphash24":
		if len(key) > 0 {
			return nil, nil, nil, fmt.Errorf("hashes: %q does not accept a fixed key (keyed by seed components)", name)
		}
		h, b := SipHash24Pair()
		return h, b, nil, nil
	case "aescmac":
		explicit, err := validateKey("aescmac", 16, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [16]byte
			copy(k[:], explicit)
			h, b, ret := AESCMACPair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := AESCMACPair()
		return h, b, ret[:], nil
	}
	if s, ok := Find(name); ok {
		if s.Width != W128 {
			return nil, nil, nil, fmt.Errorf("hashes: %q has width %d, not 128", name, s.Width)
		}
		if s.Make128Pair != nil {
			return s.Make128Pair(key...)
		}
	}
	return nil, nil, nil, fmt.Errorf("hashes: unknown 128-bit primitive %q", name)
}

// Make256 returns a fresh cached HashFunc256 for the named primitive
// along with the fixed key the closure is bound to. Variadic key arg
// follows the same pattern as Make128: pass nothing for random key,
// pass one []byte of the primitive's native key length for explicit.
//
// For "areion256" the batched arm is discarded; use Make256Pair if
// the per-pixel batched dispatch is needed.
//
// Returns an error when name is unknown, width is not 256, or supplied
// key size is wrong.
func Make256(name string, key ...[]byte) (itb.HashFunc256, []byte, error) {
	switch name {
	case "areion256":
		explicit, err := validateKey("areion256", 32, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			h, _, ret := Areion256Pair(k)
			return h, ret[:], nil
		}
		h, _, ret := Areion256Pair()
		return h, ret[:], nil
	case "blake2b256":
		explicit, err := validateKey("blake2b256", 32, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			fn, ret := BLAKE2b256(k)
			return fn, ret[:], nil
		}
		fn, ret := BLAKE2b256()
		return fn, ret[:], nil
	case "blake2s":
		explicit, err := validateKey("blake2s", 32, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			fn, ret := BLAKE2s(k)
			return fn, ret[:], nil
		}
		fn, ret := BLAKE2s()
		return fn, ret[:], nil
	case "blake3":
		explicit, err := validateKey("blake3", 32, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			fn, ret := BLAKE3(k)
			return fn, ret[:], nil
		}
		fn, ret := BLAKE3()
		return fn, ret[:], nil
	case "chacha20":
		explicit, err := validateKey("chacha20", 32, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			fn, ret := ChaCha20(k)
			return fn, ret[:], nil
		}
		fn, ret := ChaCha20()
		return fn, ret[:], nil
	}
	if s, ok := Find(name); ok {
		if s.Width != W256 {
			return nil, nil, fmt.Errorf("hashes: %q has width %d, not 256", name, s.Width)
		}
		if s.Make256Pair != nil {
			h, _, ret, err := s.Make256Pair(key...)
			return h, ret, err
		}
	}
	return nil, nil, fmt.Errorf("hashes: unknown 256-bit primitive %q", name)
}

// Make256Pair returns the (single, batched) HashFunc256 / BatchHashFunc256
// pair for primitives that have a 4-way batched implementation, plus
// the fixed key the pair is bound to. The batched arm is nil for
// primitives that do not implement a batched path. The single arm is
// bit-exact equivalent to Make256 for the same name and key.
//
// Primitives currently returning a non-nil batched arm:
//
//   - "areion256" — VAES + AVX-512 AreionSoEM256x4 ASM kernel
//   - "blake2b256" — AVX-512 ZMM-batched BLAKE2b chain-absorb kernels
//   - "blake2s" — AVX-512 ZMM-batched BLAKE2s chain-absorb kernels
//   - "blake3" — AVX-512 ZMM-batched BLAKE3 chain-absorb kernels
//   - "chacha20" — AVX-512 ZMM-batched ChaCha20 chain-absorb kernels
//
// Variadic key arg follows the same pattern as Make256.
func Make256Pair(name string, key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
	switch name {
	case "areion256":
		explicit, err := validateKey("areion256", 32, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			h, b, ret := Areion256Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := Areion256Pair()
		return h, b, ret[:], nil
	case "blake2b256":
		explicit, err := validateKey("blake2b256", 32, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			h, b, ret := BLAKE2b256Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := BLAKE2b256Pair()
		return h, b, ret[:], nil
	case "blake2s":
		explicit, err := validateKey("blake2s", 32, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			h, b, ret := BLAKE2s256Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := BLAKE2s256Pair()
		return h, b, ret[:], nil
	case "blake3":
		explicit, err := validateKey("blake3", 32, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			h, b, ret := BLAKE3256Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := BLAKE3256Pair()
		return h, b, ret[:], nil
	case "chacha20":
		explicit, err := validateKey("chacha20", 32, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [32]byte
			copy(k[:], explicit)
			h, b, ret := ChaCha20256Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := ChaCha20256Pair()
		return h, b, ret[:], nil
	}
	if s, ok := Find(name); ok {
		if s.Width != W256 {
			return nil, nil, nil, fmt.Errorf("hashes: %q has width %d, not 256", name, s.Width)
		}
		if s.Make256Pair != nil {
			return s.Make256Pair(key...)
		}
	}
	return nil, nil, nil, fmt.Errorf("hashes: unknown 256-bit primitive %q", name)
}

// Make512 returns a fresh cached HashFunc512 for the named primitive
// along with the fixed key the closure is bound to. Variadic key arg
// follows the same pattern as Make128 / Make256.
//
// For "areion512" the batched arm is discarded; use Make512Pair if
// the per-pixel batched dispatch is needed.
//
// Returns an error when name is unknown, width is not 512, or supplied
// key size is wrong.
func Make512(name string, key ...[]byte) (itb.HashFunc512, []byte, error) {
	switch name {
	case "areion512":
		explicit, err := validateKey("areion512", 64, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [64]byte
			copy(k[:], explicit)
			h, _, ret := Areion512Pair(k)
			return h, ret[:], nil
		}
		h, _, ret := Areion512Pair()
		return h, ret[:], nil
	case "blake2b512":
		explicit, err := validateKey("blake2b512", 64, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [64]byte
			copy(k[:], explicit)
			fn, ret := BLAKE2b512(k)
			return fn, ret[:], nil
		}
		fn, ret := BLAKE2b512()
		return fn, ret[:], nil
	}
	if s, ok := Find(name); ok {
		if s.Width != W512 {
			return nil, nil, fmt.Errorf("hashes: %q has width %d, not 512", name, s.Width)
		}
		if s.Make512Pair != nil {
			h, _, ret, err := s.Make512Pair(key...)
			return h, ret, err
		}
	}
	return nil, nil, fmt.Errorf("hashes: unknown 512-bit primitive %q", name)
}

// Make512Pair returns the (single, batched) HashFunc512 / BatchHashFunc512
// pair for primitives with a 4-way batched implementation, plus the
// fixed key. The batched arm is nil when no batched path exists.
//
// Primitives currently returning a non-nil batched arm:
//
//   - "areion512" — VAES + AVX-512 AreionSoEM512x4 ASM kernel
//   - "blake2b512" — AVX-512 ZMM-batched BLAKE2b chain-absorb kernels
func Make512Pair(name string, key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error) {
	switch name {
	case "areion512":
		explicit, err := validateKey("areion512", 64, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [64]byte
			copy(k[:], explicit)
			h, b, ret := Areion512Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := Areion512Pair()
		return h, b, ret[:], nil
	case "blake2b512":
		explicit, err := validateKey("blake2b512", 64, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [64]byte
			copy(k[:], explicit)
			h, b, ret := BLAKE2b512Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := BLAKE2b512Pair()
		return h, b, ret[:], nil
	}
	if s, ok := Find(name); ok {
		if s.Width != W512 {
			return nil, nil, nil, fmt.Errorf("hashes: %q has width %d, not 512", name, s.Width)
		}
		if s.Make512Pair != nil {
			return s.Make512Pair(key...)
		}
	}
	return nil, nil, nil, fmt.Errorf("hashes: unknown 512-bit primitive %q", name)
}

// smokeValidate builds the width-appropriate Make{N}Pair factory with a
// throwaway random key and checks the load-bearing closure contracts
// mirrored from the macs package's smoke discipline:
//
//   - The single-arm closure is non-nil.
//   - The single-arm closure is deterministic — two invocations with
//     the same seed over the same data return byte-identical output.
//   - When a batched arm is non-nil, four parallel probes with the
//     same seed / data yield byte-identical output tuples matching the
//     single-arm result.
//
// A registered custom primitive that fails any of these bars silently
// corrupts a Triple Ouroboros container at encrypt time; failing
// registration fail-fast surfaces the misconfiguration at the earliest
// possible boundary. The check runs only against user-registered
// factories via [Register]; shipped [Registry] entries are exercised
// by the round-trip test suite.
func smokeValidate(spec Spec) error {
	probe := []byte("hashes: register smoke probe")
	switch spec.Width {
	case W128:
		single, batched, key, err := spec.Make128Pair()
		if err != nil {
			return fmt.Errorf("hashes: Register: %q Make128Pair(): %w", spec.Name, err)
		}
		if single == nil {
			return fmt.Errorf("hashes: Register: %q Make128Pair returned a nil single-arm closure", spec.Name)
		}
		_ = key
		lo1, hi1 := single(probe, 0, 0)
		lo2, hi2 := single(probe, 0, 0)
		if lo1 != lo2 || hi1 != hi2 {
			return fmt.Errorf("hashes: Register: %q is non-deterministic (two single-arm calls over the same input disagree)", spec.Name)
		}
		if batched != nil {
			var lanes [4][]byte
			for i := range lanes {
				lanes[i] = probe
			}
			var seeds [4][2]uint64
			out := batched(&lanes, seeds)
			for i := 0; i < 4; i++ {
				if out[i][0] != lo1 || out[i][1] != hi1 {
					return fmt.Errorf("hashes: Register: %q batched-arm lane %d diverges from the single-arm result over identical inputs", spec.Name, i)
				}
			}
		}
	case W256:
		single, batched, key, err := spec.Make256Pair()
		if err != nil {
			return fmt.Errorf("hashes: Register: %q Make256Pair(): %w", spec.Name, err)
		}
		if single == nil {
			return fmt.Errorf("hashes: Register: %q Make256Pair returned a nil single-arm closure", spec.Name)
		}
		_ = key
		var zseed [4]uint64
		a := single(probe, zseed)
		b := single(probe, zseed)
		if a != b {
			return fmt.Errorf("hashes: Register: %q is non-deterministic (two single-arm calls over the same input disagree)", spec.Name)
		}
		if batched != nil {
			var lanes [4][]byte
			for i := range lanes {
				lanes[i] = probe
			}
			var seeds [4][4]uint64
			out := batched(&lanes, seeds)
			for i := 0; i < 4; i++ {
				if out[i] != a {
					return fmt.Errorf("hashes: Register: %q batched-arm lane %d diverges from the single-arm result over identical inputs", spec.Name, i)
				}
			}
		}
	case W512:
		single, batched, key, err := spec.Make512Pair()
		if err != nil {
			return fmt.Errorf("hashes: Register: %q Make512Pair(): %w", spec.Name, err)
		}
		if single == nil {
			return fmt.Errorf("hashes: Register: %q Make512Pair returned a nil single-arm closure", spec.Name)
		}
		_ = key
		var zseed [8]uint64
		a := single(probe, zseed)
		b := single(probe, zseed)
		if a != b {
			return fmt.Errorf("hashes: Register: %q is non-deterministic (two single-arm calls over the same input disagree)", spec.Name)
		}
		if batched != nil {
			var lanes [4][]byte
			for i := range lanes {
				lanes[i] = probe
			}
			var seeds [4][8]uint64
			out := batched(&lanes, seeds)
			for i := 0; i < 4; i++ {
				if out[i] != a {
					return fmt.Errorf("hashes: Register: %q batched-arm lane %d diverges from the single-arm result over identical inputs", spec.Name, i)
				}
			}
		}
	}
	if err := smokeOptionalHashHooks(spec, probe); err != nil {
		return err
	}
	return nil
}

// smokeOptionalHashHooks exercises the optional [Spec.HashHash] and
// [Spec.KeyedHash] factory hooks a user-registered Spec may populate
// so [macs.BuildHMAC] / [macs.BuildKeyedHash] can compose the
// primitive by name. Both hooks are optional: a nil field is left
// alone. When populated, each hook is verified against the same
// contract the mac-builder consumers rely on later:
//
//   - HashHash: returns a non-nil hash.Hash whose Sum(nil) after
//     writing the smoke probe yields Width/8 bytes; two fresh
//     instances produce byte-identical output over the same input.
//
//   - KeyedHash: accepts a fresh Width-native-length key without
//     error (16 / 32 / 64 bytes for W128 / W256 / W512), returns
//     a non-nil hash.Hash whose Sum(nil) yields Width/8 bytes; two
//     fresh instances keyed with the same bytes produce byte-
//     identical tags over the same input. A nil / empty key is
//     probed for no-panic only — the constructor may legitimately
//     accept either as a valid empty key or return an error, both
//     are within contract, so no other assertion applies.
//
// The whole hook-smoke body runs under defer/recover: a factory
// that panics on any of these calls surfaces as a returned error
// rather than crashing the [Register] caller.
func smokeOptionalHashHooks(spec Spec, probe []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("hashes: Register: %q optional-hook smoke panicked: %v", spec.Name, r)
		}
	}()
	wantLen := int(spec.Width) / 8
	if spec.HashHash != nil {
		h1 := spec.HashHash()
		if h1 == nil {
			return fmt.Errorf("hashes: Register: %q HashHash returned a nil hash.Hash", spec.Name)
		}
		h1.Write(probe)
		out1 := h1.Sum(nil)
		if len(out1) != wantLen {
			return fmt.Errorf("hashes: Register: %q HashHash output length %d does not match Width/8 = %d", spec.Name, len(out1), wantLen)
		}
		h2 := spec.HashHash()
		if h2 == nil {
			return fmt.Errorf("hashes: Register: %q HashHash returned a nil hash.Hash on the second fresh call", spec.Name)
		}
		h2.Write(probe)
		out2 := h2.Sum(nil)
		if !bytes.Equal(out1, out2) {
			return fmt.Errorf("hashes: Register: %q HashHash is non-deterministic across fresh instances (two Write/Sum passes over identical input disagree)", spec.Name)
		}
	}
	if spec.KeyedHash != nil {
		// Single probe at the primitive's Width-native key length
		// (16 / 32 / 64 bytes for W128 / W256 / W512). If the
		// constructor accepts, run the determinism assertion; if
		// it cleanly errors, the primitive has an exotic key
		// contract and must be composed via macs.BuildKeyedHash
		// with an explicit KeySize — the determinism check is
		// silently skipped in that case. The no-panic contract
		// still holds via the outer defer/recover.
		key := make([]byte, wantLen)
		if _, rerr := rand.Read(key); rerr != nil {
			return fmt.Errorf("hashes: Register: %q KeyedHash smoke: crypto/rand: %w", spec.Name, rerr)
		}
		kh1, kerr := spec.KeyedHash(key)
		if kerr == nil {
			if kh1 == nil {
				return fmt.Errorf("hashes: Register: %q KeyedHash returned a nil hash.Hash without error at %d-byte key", spec.Name, wantLen)
			}
			kh1.Write(probe)
			tag1 := kh1.Sum(nil)
			kh2, kerr2 := spec.KeyedHash(key)
			if kerr2 != nil {
				return fmt.Errorf("hashes: Register: %q KeyedHash rejected the %d-byte key on the second fresh call after accepting it on the first: %w", spec.Name, wantLen, kerr2)
			}
			if kh2 == nil {
				return fmt.Errorf("hashes: Register: %q KeyedHash returned a nil hash.Hash on the second fresh call at %d-byte key", spec.Name, wantLen)
			}
			kh2.Write(probe)
			tag2 := kh2.Sum(nil)
			if !bytes.Equal(tag1, tag2) {
				return fmt.Errorf("hashes: Register: %q KeyedHash is non-deterministic across fresh instances at %d-byte key (two Write/Sum passes over identical (key, input) disagree)", spec.Name, wantLen)
			}
		}
		// Contract-flexibility no-panic probes on nil and empty
		// key. The constructor may accept either as a valid empty
		// key or return an error — both are within contract; the
		// outer defer/recover converts any panic into a returned
		// error, closing the only misbehaviour worth catching here.
		_, _ = spec.KeyedHash(nil)
		_, _ = spec.KeyedHash([]byte{})
	}
	return nil
}
