package macs

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/everanium/itb"
)

// MaxNameLen caps the length of a custom MAC primitive name in
// [Spec.Name] presented to [Register]. Matches the identifier budget
// of the hashes package's runtime registration surface so a custom
// hash / custom MAC pair can share one naming convention.
const MaxNameLen = 12

// ErrMACExists is returned by [Register] when the supplied Spec.Name
// is already present in [Registry] or has been registered previously.
// Once registered, a primitive cannot be re-registered under the same
// name — a caller cannot silently swap the factory a downstream
// Find / Make call resolves.
var ErrMACExists = errors.New("macs: MAC already registered")

var (
	customsMu sync.RWMutex
	customs   []Spec // append-only, guarded by customsMu
)

// Register adds a user-supplied custom MAC primitive to the runtime
// registry. The Spec must carry a non-empty Name (lowercase letters,
// digits, underscores only — no dashes — at most [MaxNameLen] bytes),
// KeySize >= MinKeyBytes >= 16, TagSize in [16, 64], and a non-nil MakeMAC
// factory. MakeIncrementalMAC is optional: when nil, Register
// synthesizes a concatenate-then-MAC wrapper around MakeMAC
// (byte-for-byte equivalent per the itb.MACIncrementalFunc contract,
// at one concat copy per call).
//
// The registered primitive becomes visible through [Find], [Make],
// [MakeIncremental], and [MakeMACPair], and — transitively — through
// every consumer that resolves MACs by name, including triple profile
// MacName resolution. [Registry] itself is not extended — user
// entries live in a separate mutex-guarded slice — so the FFI
// iteration surface (ITB_MACCount / ITB_MACName) is unaffected.
//
// Closure contracts every registered factory must honour (the shipped
// builders [BuildHMAC] / [BuildKeyedHash] honour them by
// construction):
//
//   - Determinism: same key + same input → same tag, byte-for-byte.
//   - Constant tag length: exactly TagSize bytes on every call,
//     independent of input length.
//   - Cross-arm equivalence: the incremental arm over any chunk split
//     emits the same tag as the one-shot arm over the concatenation.
//   - Parallel-safety: concurrent goroutines may call the returned
//     closures simultaneously.
//   - Fresh output slice: every call returns a newly allocated tag,
//     never a shared buffer.
//
// Register smoke-validates the first three contracts with a throwaway
// random key before accepting the Spec: tag length on two input
// lengths, determinism across repeated calls, and incremental /
// one-shot equivalence on a fixed two-chunk split. Violations fail
// registration loudly instead of corrupting authenticated containers
// at encrypt time.
//
// Errors:
//
//   - [ErrMACExists] when the name is already present in [Registry]
//     or among prior Register calls.
//   - a validation error when Name is empty, uses disallowed
//     characters, exceeds [MaxNameLen], the size fields fall outside
//     their accepted ranges, MakeMAC is nil, or smoke validation
//     fails.
//
// Register is safe for concurrent use with itself and with [Find] /
// [Make] / [MakeIncremental] / [MakeMACPair].
func Register(spec Spec) error {
	if err := validateRegisterSpec(spec); err != nil {
		return err
	}
	if spec.MakeIncrementalMAC == nil {
		spec.MakeIncrementalMAC = synthesizeIncremental(spec.MakeMAC)
	}
	if err := smokeValidate(spec); err != nil {
		return err
	}
	customsMu.Lock()
	defer customsMu.Unlock()
	for _, s := range Registry {
		if s.Name == spec.Name {
			return fmt.Errorf("macs: %q shadows shipped primitive: %w", spec.Name, ErrMACExists)
		}
	}
	for _, s := range customs {
		if s.Name == spec.Name {
			return fmt.Errorf("macs: %q: %w", spec.Name, ErrMACExists)
		}
	}
	customs = append(customs, spec)
	return nil
}

// findCustom scans the user-registered customs under a read lock.
// Backing arm of [Find] after the shipped [Registry] scan misses.
func findCustom(name string) (Spec, bool) {
	customsMu.RLock()
	defer customsMu.RUnlock()
	for _, s := range customs {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// validateRegisterSpec checks the static fields of a Spec presented
// to [Register]. Kept separate so the validation paths run without
// touching the customs mutex.
func validateRegisterSpec(spec Spec) error {
	if spec.Name == "" {
		return fmt.Errorf("macs: Register: Spec.Name is empty")
	}
	if len(spec.Name) > MaxNameLen {
		return fmt.Errorf("macs: Register: Spec.Name %q length %d exceeds [MaxNameLen] = %d",
			spec.Name, len(spec.Name), MaxNameLen)
	}
	for i := 0; i < len(spec.Name); i++ {
		c := spec.Name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_':
		default:
			return fmt.Errorf("macs: Register: Spec.Name %q contains illegal character %q (lowercase letters, digits, underscores only)",
				spec.Name, c)
		}
	}
	if spec.MinKeyBytes < 16 {
		return fmt.Errorf("macs: Register: Spec.MinKeyBytes = %d below floor 16", spec.MinKeyBytes)
	}
	if spec.KeySize < spec.MinKeyBytes {
		return fmt.Errorf("macs: Register: Spec.KeySize = %d below Spec.MinKeyBytes = %d",
			spec.KeySize, spec.MinKeyBytes)
	}
	if spec.TagSize < 16 {
		return fmt.Errorf("macs: Register: Spec.TagSize = %d below floor 16", spec.TagSize)
	}
	if spec.TagSize > 64 {
		// The ceiling covers the longest realistic MAC tag (64 bytes,
		// e.g. HMAC-SHA-512) and keeps the tag-size range symmetric
		// with the wire-shape pinning knobs (itb.Config.TagStubSize /
		// triple.Profile.TagStubSize / triple.Opts.TagStubSize), so
		// every registrable tag length has a pinnable No MAC stub.
		return fmt.Errorf("macs: Register: Spec.TagSize = %d above ceiling 64", spec.TagSize)
	}
	if spec.MakeMAC == nil {
		return fmt.Errorf("macs: Register: Spec.MakeMAC is nil")
	}
	return nil
}

// synthesizeIncremental wraps a one-shot MAC factory into a
// concatenate-then-MAC incremental factory. Equivalence with the
// one-shot arm holds by construction; the cost is one concat copy of
// the chunk total per call.
func synthesizeIncremental(makeMAC func(key []byte) (itb.MACFunc, error)) func(key []byte) (itb.MACIncrementalFunc, error) {
	return func(key []byte) (itb.MACIncrementalFunc, error) {
		mac, err := makeMAC(key)
		if err != nil {
			return nil, err
		}
		return func(chunks ...[]byte) []byte {
			total := 0
			for _, c := range chunks {
				total += len(c)
			}
			buf := make([]byte, 0, total)
			for _, c := range chunks {
				buf = append(buf, c...)
			}
			return mac(buf)
		}, nil
	}
}

// smokeValidate builds both arms with a throwaway random key and
// checks the load-bearing closure contracts: constant tag length
// (probed on two input lengths — the Low-Level auth paths size the
// authenticated container from len(mac([]byte{}))), determinism
// (decrypt recomputes the tag and compares), and incremental /
// one-shot equivalence on a fixed two-chunk split.
func smokeValidate(spec Spec) error {
	key := make([]byte, spec.KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("macs: Register: smoke key generation: %w", err)
	}
	mac, err := spec.MakeMAC(key)
	if err != nil {
		return fmt.Errorf("macs: Register: %q MakeMAC(%d-byte key): %w", spec.Name, len(key), err)
	}
	if mac == nil {
		return fmt.Errorf("macs: Register: %q MakeMAC returned a nil closure", spec.Name)
	}
	inc, err := spec.MakeIncrementalMAC(key)
	if err != nil {
		return fmt.Errorf("macs: Register: %q MakeIncrementalMAC(%d-byte key): %w", spec.Name, len(key), err)
	}
	if inc == nil {
		return fmt.Errorf("macs: Register: %q MakeIncrementalMAC returned a nil closure", spec.Name)
	}
	tagEmpty := mac([]byte{})
	if len(tagEmpty) != spec.TagSize {
		return fmt.Errorf("macs: Register: %q tag length %d over empty input != Spec.TagSize %d",
			spec.Name, len(tagEmpty), spec.TagSize)
	}
	if !bytes.Equal(mac(nil), mac(nil)) {
		return fmt.Errorf("macs: Register: %q is non-deterministic (two calls over the same input disagree)", spec.Name)
	}
	msg := []byte("macs: register smoke probe")
	if got := len(mac(msg)); got != spec.TagSize {
		return fmt.Errorf("macs: Register: %q tag length %d over %d-byte input != Spec.TagSize %d (tag length must be input-independent)",
			spec.Name, got, len(msg), spec.TagSize)
	}
	if !bytes.Equal(inc([]byte("foo"), []byte("bar")), mac([]byte("foobar"))) {
		return fmt.Errorf("macs: Register: %q incremental arm diverges from the one-shot arm over a two-chunk split", spec.Name)
	}
	return nil
}

// MakeMACPair resolves both arms of the named primitive in one call:
// the one-shot itb.MACFunc, the incremental itb.MACIncrementalFunc,
// and the resolved [Spec]. Convenience dispatcher over [Find] +
// [Make] + [MakeIncremental] with identical name and key validation;
// works for shipped and user-registered primitives alike.
func MakeMACPair(name string, key []byte) (itb.MACFunc, itb.MACIncrementalFunc, Spec, error) {
	spec, ok := Find(name)
	if !ok {
		return nil, nil, Spec{}, fmt.Errorf("macs: unknown MAC %q", name)
	}
	mac, err := Make(name, key)
	if err != nil {
		return nil, nil, Spec{}, err
	}
	inc, err := MakeIncremental(name, key)
	if err != nil {
		return nil, nil, Spec{}, err
	}
	return mac, inc, spec, nil
}
