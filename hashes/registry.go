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

// Class is the outer cipher dispatch class of a registry primitive.
// The ctr / kdf / wrapper / parallax packages route a primitive name
// through structurally different code paths depending on its class.
type Class uint8

const (
	// ClassNone is the zero value: the primitive carries no outer
	// cipher dispatch class and MUST NOT be routed through the
	// ctr / kdf / wrapper / parallax keystream path. Two populations
	// carry this value:
	//
	//   - Shipped Registry entries that are inner-PRF-only by design.
	//     AES-ITB is the canonical example — a reduced-round AES
	//     construction that is intentionally weak standalone and safe
	//     only under ITB's compound inner-PRF defence stack
	//     (ChainHash cascade + Interlocked Barrier + Part 2
	//     absorption). Wiring such a primitive as a wrapper outer
	//     cipher or parallax palette entry would expose the raw
	//     2-round core as user-selectable keystream material.
	//   - User-registered Specs, which carry this value by default.
	//
	// The outer-cipher consumers (ctr, kdf, wrapper, parallax) treat
	// ClassNone as "not a keystream candidate": [KeystreamNames]
	// filters these entries out of the canonical outer-cipher name
	// list, and the ctr / kdf dispatch tables reject them at the
	// switch level with an unknown-cipher error.
	ClassNone Class = 0

	// ClassNativeStream marks a primitive that owns a native
	// keystream mode (AES-128-CTR, SipHash-2-4 CTR, ChaCha20).
	ClassNativeStream Class = 1

	// ClassPRFCounter marks a hash primitive used as the keyed PRF
	// core of a PRF-counter keystream / SP 800-108 counter-mode KDF.
	ClassPRFCounter Class = 2
)

// Spec describes one PRF-grade hash primitive. Shipped primitives live
// in [Registry] with all factory fields nil; their factory closures are
// dispatched through the switch statements in [Make128] / [Make256] /
// [Make512] and their Pair counterparts. User-registered custom
// primitives (added via [Register]) populate the factory field matching
// the primitive's Width so the same Make{N}(Pair) name-keyed dispatch
// resolves them uniformly. Every shipped entry additionally carries its
// outer cipher dispatch [Class].
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

	// Class is the outer cipher dispatch class (see [Class]). Populated
	// on every shipped Registry entry; ignored on user-registered Specs —
	// [ClassOf] consults Registry only, and ctr / kdf construct keystreams
	// and KDFs for shipped names only.
	Class Class

	// FusedChainHash128 optionally builds the whole-cascade evaluators a
	// width-128 primitive can offer for [itb.Seed128.FusedChain] /
	// [itb.Seed128.BatchFusedChain] (see [itb.FusedChainHashFunc128]).
	// key is the primitive's fixed key exactly as returned by the
	// Make128Pair factory that built the seed's Hash / BatchHash arms.
	// nil (every entry without a fused cascade) leaves the seed on the
	// sequential per-round loop; a populated factory must return
	// evaluators bit-exact with that loop. Shipped: aesitb128, aescmac, siphash24.
	FusedChainHash128 func(key []byte) (itb.FusedChainHashFunc128, itb.BatchFusedChainHashFunc128, error) `json:"-"`

	// InterlockFillBatch16 optionally builds the batch-16 Interlocked
	// Barrier fill kernel installed through
	// [itb.Seed128.SetInterlockBatch16] (see [itb.InterlockFillFunc16]).
	// key is the primitive's fixed key exactly as returned by the
	// Make128Pair factory. nil (every entry without batch-16 support)
	// leaves the seed filling the cascade through its four-lane and
	// single-lane arms. A populated factory must return a kernel
	// bit-exact with sixteen sequential cascades over the same
	// components; the kernel is a performance path and never changes the
	// wire. Shipped: aesitb128, aescmac, siphash24.
	InterlockFillBatch16 func(key []byte) (itb.InterlockFillFunc16, error) `json:"-"`

	// FusedChainHash256 and FusedChainHash512 are the width-256 and
	// width-512 counterparts of FusedChainHash128: whole-cascade
	// evaluators for [itb.Seed256.FusedChain] / [itb.Seed256.BatchFusedChain]
	// and [itb.Seed512.FusedChain] / [itb.Seed512.BatchFusedChain],
	// installed through [AttachFused256] / [AttachFused512]. key is the
	// primitive's fixed key exactly as returned by the Make256Pair /
	// Make512Pair factory that built the seed's arms. nil leaves the seed
	// on the sequential per-round loop, which is the cascade definition
	// at every width; a populated factory must return evaluators
	// bit-exact with that loop. Every shipped entry currently leaves both
	// fields nil.
	FusedChainHash256 func(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) `json:"-"`
	FusedChainHash512 func(key []byte) (itb.FusedChainHashFunc512, itb.BatchFusedChainHashFunc512, error) `json:"-"`

	// InterlockFillBatch16x256 and InterlockFillBatch16x512 are the
	// width-256 and width-512 counterparts of InterlockFillBatch16: the
	// batch-16 Interlocked Barrier fill kernels installed through
	// [AttachInterlockBatch16x256] / [AttachInterlockBatch16x512] (see
	// [itb.InterlockFillFunc16x256] and [itb.InterlockFillFunc16x512] for
	// the group count one call covers at each width). key is the
	// primitive's fixed key exactly as returned by the Make256Pair /
	// Make512Pair factory. nil leaves the seed filling the cascade through
	// its four-lane and single-lane arms; a populated factory must return
	// a kernel bit-exact with the sequential cascades over the same
	// components. Every shipped entry currently leaves both fields nil.
	InterlockFillBatch16x256 func(key []byte) (itb.InterlockFillFunc16x256, error) `json:"-"`
	InterlockFillBatch16x512 func(key []byte) (itb.InterlockFillFunc16x512, error) `json:"-"`

	// FusedChainHash256x8 and FusedChainHash512x8 optionally build the
	// eight-lane fused cascade evaluators installed through
	// [AttachFused256] / [AttachFused512] on [itb.Seed256.SetBatchFusedChain8]
	// / [itb.Seed512.SetBatchFusedChain8] (see
	// [itb.BatchFusedChainHashFunc256x8] / [itb.BatchFusedChainHashFunc512x8]):
	// the pixel pipeline's eight-pixel stride at the two wide widths. key
	// is the primitive's fixed key exactly as returned by the Make256Pair
	// / Make512Pair factory. A factory returns a nil evaluator on hosts
	// whose selected tier carries no eight-lane kernel, which leaves the
	// seed on the four-pixel stride; a populated evaluator must be
	// bit-exact with two four-lane evaluations over the lane halves (and
	// hence with the sequential loop). The hooks are performance paths
	// only and never change the wire. Every shipped entry currently
	// leaves both fields nil.
	FusedChainHash256x8 func(key []byte) (itb.BatchFusedChainHashFunc256x8, error) `json:"-"`
	FusedChainHash512x8 func(key []byte) (itb.BatchFusedChainHashFunc512x8, error) `json:"-"`

	// InterlockFillBatch32x256 and InterlockFillBatch32x512 optionally
	// build the batch-32 Interlocked Barrier fill kernels installed
	// through [AttachInterlockBatch32x256] / [AttachInterlockBatch32x512]
	// (see [itb.InterlockFillFunc32x256] and [itb.InterlockFillFunc32x512]
	// for the group count one call covers at each width: 16 groups at
	// width 256, 8 at width 512, 32 chunks either way). key is the
	// primitive's fixed key exactly as returned by the Make256Pair /
	// Make512Pair factory. A factory returns a nil kernel on hosts whose
	// selected tier carries no batch-32 kernel, which leaves the fill on
	// the batch-16 hook and the four-lane / single-lane arms; a populated
	// kernel must be bit-exact with the sequential cascades over the same
	// components. Every shipped entry currently leaves both fields nil.
	InterlockFillBatch32x256 func(key []byte) (itb.InterlockFillFunc32x256, error) `json:"-"`
	InterlockFillBatch32x512 func(key []byte) (itb.InterlockFillFunc32x512, error) `json:"-"`
}

// Canonical shipped primitive names. Every registry consumer (ctr, kdf,
// wrapper, parallax, triple, cmd/itb3) refers to these identifiers; the
// string values are the FFI-stable names exposed through ITB_HashName.
const (
	// CipherAESITB128 names the AES-ITB primitive — an ITB-native
	// short-input keyed hash built from reduced-round AES (one AES round
	// per absorbed 16-byte block plus two finalising rounds: three rounds
	// at the one-block shapes, 4 / 5 / 7 at the 20 / 36 / 68-byte per-pixel
	// shapes). Standalone-weak by design (see HARNESS.md § 3.10 for the
	// shipped primitive and § 3.7 for the reduced-AES pattern); safe only
	// under ITB's compound defence stack (ChainHash cascade + Interlocked
	// Barrier + Part 2 absorption). Ships first in the canonical order to
	// signal its ITB-native status.
	CipherAESITB128  = "aesitb128"
	CipherAreion256  = "areion256"
	CipherAreion512  = "areion512"
	CipherBLAKE2b256 = "blake2b256"
	CipherBLAKE2b512 = "blake2b512"
	CipherBLAKE2s    = "blake2s"
	CipherBLAKE3     = "blake3"
	// CipherAES128CTR names the "aescmac" registry row. As InnerHash
	// the row is AES-CMAC; as OuterCipher / ParallaxPalette entry the
	// same name selects AES-128-CTR.
	CipherAES128CTR = "aescmac"
	CipherSipHash24 = "siphash24"
	CipherChaCha20  = "chacha20"
)

// Registry lists every shippable PRF-grade primitive in canonical
// order (with AES-ITB-128 as the ITB-native inner-PRF-only exception —
// see [ClassNone]). Entries with Class == ClassNone are safe only
// within ITB's compound inner-PRF stack — see the [ClassNone]
// docstring for the taxonomy.
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
var Registry = [10]Spec{
	{Name: CipherAESITB128, Width: W128, Class: ClassNone, FusedChainHash128: aesITB128FusedChainHash, InterlockFillBatch16: aesITB128InterlockFillBatch16},
	{Name: CipherAreion256, Width: W256, Class: ClassPRFCounter, FusedChainHash256: areion256FusedChainHash, FusedChainHash256x8: areion256FusedChainHash8, InterlockFillBatch16x256: areion256InterlockFillBatch16},
	{Name: CipherAreion512, Width: W512, Class: ClassPRFCounter, FusedChainHash512: areion512FusedChainHash, FusedChainHash512x8: areion512FusedChainHash8, InterlockFillBatch16x512: areion512InterlockFillBatch16, InterlockFillBatch32x512: areion512InterlockFillBatch32},
	{Name: CipherBLAKE2b256, Width: W256, Class: ClassPRFCounter, HashHash: blake2b256HashHash, KeyedHash: blake2b256KeyedHash, FusedChainHash256: blake2b256FusedChainHash, FusedChainHash256x8: blake2b256FusedChainHash8, InterlockFillBatch16x256: blake2b256InterlockFillBatch16},
	{Name: CipherBLAKE2b512, Width: W512, Class: ClassPRFCounter, HashHash: blake2b512HashHash, KeyedHash: blake2b512KeyedHash, FusedChainHash512: blake2b512FusedChainHash, FusedChainHash512x8: blake2b512FusedChainHash8, InterlockFillBatch16x512: blake2b512InterlockFillBatch16, InterlockFillBatch32x512: blake2b512InterlockFillBatch32},
	{Name: CipherBLAKE2s, Width: W256, Class: ClassPRFCounter, HashHash: blake2sHashHash, KeyedHash: blake2sKeyedHash, FusedChainHash256: blake2sFusedChainHash, FusedChainHash256x8: blake2sFusedChainHash8, InterlockFillBatch16x256: blake2sInterlockFillBatch16},
	{Name: CipherBLAKE3, Width: W256, Class: ClassPRFCounter, HashHash: blake3HashHash, KeyedHash: blake3KeyedHash, FusedChainHash256: blake3FusedChainHash, FusedChainHash256x8: blake3FusedChainHash8, InterlockFillBatch16x256: blake3InterlockFillBatch16},
	{Name: CipherAES128CTR, Width: W128, Class: ClassNativeStream, FusedChainHash128: aesCMACFusedChainHash, InterlockFillBatch16: aesCMACInterlockFillBatch16},
	{Name: CipherSipHash24, Width: W128, Class: ClassNativeStream, KeyedHash: siphash24KeyedHash, FusedChainHash128: sipHash24FusedChainHash, InterlockFillBatch16: sipHash24InterlockFillBatch16},
	{Name: CipherChaCha20, Width: W256, Class: ClassNativeStream, FusedChainHash256: chacha20FusedChainHash, FusedChainHash256x8: chacha20FusedChainHash8, InterlockFillBatch16x256: chacha20InterlockFillBatch16},
}

// ErrHashExists is returned by [Register] when the supplied Spec.Name
// is already present in [Registry] or has been registered previously.
// Once registered, a primitive cannot be re-registered under the same
// name — immutability matches [triple.Register] semantics so a
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
	case "aesitb128":
		explicit, err := validateKey("aesitb128", 16, key...)
		if err != nil {
			return nil, nil, err
		}
		if explicit != nil {
			var k [16]byte
			copy(k[:], explicit)
			h, _, ret := AESITB128Pair(k)
			return h, ret[:], nil
		}
		h, _, ret := AESITB128Pair()
		return h, ret[:], nil
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
//   - "aesitb128" — 4-lane chain-absorb kernels (AES-NI XMM on amd64,
//     NEON on arm64; VAES YMM / ZMM kernels built and force-selectable)
//     for the 13 / 20 / 36 / 68-byte per-pixel shapes, scalar reference
//     elsewhere
//   - "aescmac" — four single-arm calls per lane; the assembly kernels of
//     the primitive evaluate the whole ChainHash cascade
//     (hashes/internal/aescmacasm) and are reached through the fused
//     hooks AttachFused128 / AttachInterlockBatch16 install
//   - "siphash24" — AVX-512 ZMM-batched SipHash-2-4 chain-absorb kernels
//
// Variadic key arg follows the same pattern as Make128 / Make256Pair.
func Make128Pair(name string, key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
	switch name {
	case "aesitb128":
		explicit, err := validateKey("aesitb128", 16, key...)
		if err != nil {
			return nil, nil, nil, err
		}
		if explicit != nil {
			var k [16]byte
			copy(k[:], explicit)
			h, b, ret := AESITB128Pair(k)
			return h, b, ret[:], nil
		}
		h, b, ret := AESITB128Pair()
		return h, b, ret[:], nil
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
//   - "areion256" — always: the four-lane AreionSoEM256x4 arm (VAES
//     ZMM / YMM, AES-NI XMM or ARM Crypto Extension kernels where
//     present, the four-way Go permutation elsewhere); the fused cascade
//     kernels of the primitive (internal/areionasm) are reached through
//     the hooks AttachFused256 / AttachInterlockBatch16x256 install
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
//   - "areion512" — always: the four-lane AreionSoEM512x4 arm (VAES
//     ZMM / YMM, AES-NI XMM or ARM Crypto Extension kernels where
//     present, the four-way Go permutation elsewhere); the fused cascade
//     kernels of the primitive (internal/areionasm) are reached through
//     the hooks AttachFused512 / AttachInterlockBatch16x512 install
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
		if spec.FusedChainHash128 != nil {
			if err := smokeFusedChainHash128(spec, single, key); err != nil {
				return err
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
		if spec.FusedChainHash256 != nil {
			if err := smokeFusedChainHash256(spec, single, key); err != nil {
				return err
			}
		}
		if err := smokeWideHooks256(spec, single, key); err != nil {
			return err
		}
	case W512:
		single, batched, key, err := spec.Make512Pair()
		if err != nil {
			return fmt.Errorf("hashes: Register: %q Make512Pair(): %w", spec.Name, err)
		}
		if single == nil {
			return fmt.Errorf("hashes: Register: %q Make512Pair returned a nil single-arm closure", spec.Name)
		}
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
		if spec.FusedChainHash512 != nil {
			if err := smokeFusedChainHash512(spec, single, key); err != nil {
				return err
			}
		}
		if err := smokeWideHooks512(spec, single, key); err != nil {
			return err
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

// smokeFusedChainHash128 exercises the optional [Spec.FusedChainHash128]
// factory hook a user-registered W128 Spec may populate so that a
// [itb.Seed128] built through the primitive can offer the whole-cascade
// evaluators via [AttachFused128]. The check runs only when the field is
// non-nil; the fixed key passed to the factory is the same key returned
// by the Spec's Make128Pair factory so both sides bind identical
// primitive state.
//
// The contract enforced here:
//
//   - The factory returns without error. A factory that reports an
//     error at Register time is a misconfiguration surfaced fail-fast.
//
//   - A (nil, nil) evaluator return is a valid opt-out (matches the
//     shipped ITB_FORCE_CHAINHASH_SEQ path); no further probing runs
//     in that case.
//
//   - For each probe length (the four AES-ITB per-pixel shapes cover
//     the shipped implementation; a user-registered fused kernel that
//     accepts none of them silently passes the smoke — its production
//     use will run the sequential loop until it opts in on its own
//     accepted lengths), whenever the single-arm evaluator reports
//     ok = true its (lo, hi) output must be bit-exact with the
//     sequential HashFunc128 loop over the same (components, data)
//     tuple. The batched-arm evaluator is verified lane-by-lane against
//     the same sequential reference.
//
// A bit-mismatch at any accepted probe length rejects the Spec with a
// descriptive error, mirroring the fail-fast discipline of the other
// smoke checks.
func smokeFusedChainHash128(spec Spec, single itb.HashFunc128, key []byte) error {
	fSingle, fBatched, ferr := spec.FusedChainHash128(key)
	if ferr != nil {
		return fmt.Errorf("hashes: Register: %q FusedChainHash128(key): %w", spec.Name, ferr)
	}
	if fSingle == nil && fBatched == nil {
		return nil
	}
	// A modest even-count component array matching the shipping minimum
	// (8 uint64 = 512-bit key). Values are deterministic so a failure
	// reproduces without a seeded RNG.
	var comps [8]uint64
	for i := range comps {
		comps[i] = 0x0123456789abcdef ^ uint64(i)*0x9e3779b97f4a7c15
	}
	seqChain := func(data []byte) (uint64, uint64) {
		hLo, hHi := single(data, comps[0], comps[1])
		for i := 2; i < len(comps); i += 2 {
			hLo, hHi = single(data, comps[i]^hLo, comps[i+1]^hHi)
		}
		return hLo, hHi
	}
	for _, n := range [...]int{13, 20, 36, 68} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i)
		}
		if fSingle != nil {
			lo, hi, ok := fSingle(comps[:], data)
			if ok {
				wantLo, wantHi := seqChain(data)
				if lo != wantLo || hi != wantHi {
					return fmt.Errorf("hashes: Register: %q FusedChainHash128 single arm diverges from the sequential HashFunc128 loop at len=%d", spec.Name, n)
				}
			}
		}
		if fBatched != nil {
			var lanes [4][]byte
			for l := range lanes {
				lanes[l] = make([]byte, n)
				for i := range lanes[l] {
					lanes[l][i] = byte(i + l*7)
				}
			}
			out, ok := fBatched(comps[:], &lanes)
			if ok {
				for l := 0; l < 4; l++ {
					wantLo, wantHi := seqChain(lanes[l])
					if out[l][0] != wantLo || out[l][1] != wantHi {
						return fmt.Errorf("hashes: Register: %q FusedChainHash128 batched arm lane %d diverges from the sequential HashFunc128 loop at len=%d", spec.Name, l, n)
					}
				}
			}
		}
	}
	return nil
}
