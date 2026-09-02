package macs

import (
	"fmt"

	"github.com/everanium/itb"
)

// Spec describes one MAC primitive: either a shipped [Registry] entry
// or a user-supplied custom primitive presented to [Register].
type Spec struct {
	Name        string // canonical FFI-stable identifier
	KeySize     int    // recommended key size in bytes
	TagSize     int    // tag size in bytes (constant per primitive)
	MinKeyBytes int    // minimum acceptable key length (for HMAC variants)

	// MakeMAC is the one-shot factory for a user-registered custom
	// MAC primitive: it pre-keys the primitive with key and returns
	// the tag-emitting closure. Shipped [Registry] entries leave the
	// field nil — their factories dispatch by name inside [Make].
	// Required by [Register]; see the [Register] documentation for
	// the closure contracts (constant tag length, determinism,
	// parallel-safety, fresh output slice per call).
	MakeMAC func(key []byte) (itb.MACFunc, error)

	// MakeIncrementalMAC is the multi-slice arm factory for a
	// user-registered custom MAC primitive: the returned closure
	// must emit the same tag as the MakeMAC-built closure over the
	// concatenation of its chunks, byte-for-byte. Optional at
	// [Register] time — when nil, Register synthesizes a
	// concatenate-then-MAC wrapper around MakeMAC (equivalent by
	// construction, at one concat copy per call). Shipped [Registry]
	// entries leave the field nil.
	MakeIncrementalMAC func(key []byte) (itb.MACIncrementalFunc, error)
}

// Registry lists every shippable PRF-grade MAC primitive in canonical
// order. The same order is used by the FFI iteration surface
// (ITB_MACName, ITB_MACTagSize) so that index 0..2 is stable across
// releases.
var Registry = [3]Spec{
	{Name: "kmac256", KeySize: 32, TagSize: 32, MinKeyBytes: 16},
	{Name: "hmac-sha256", KeySize: 32, TagSize: 32, MinKeyBytes: 16},
	{Name: "hmac-blake3", KeySize: 32, TagSize: 32, MinKeyBytes: 32},
}

// Find returns the Spec for a canonical name and reports whether a
// match was found. Shipped [Registry] entries are consulted first,
// then any user-registered custom primitives added via [Register].
func Find(name string) (Spec, bool) {
	for _, s := range Registry {
		if s.Name == name {
			return s, true
		}
	}
	return findCustom(name)
}

// Make returns a fresh cached itb.MACFunc for the named primitive,
// keyed by key. Returns an error when name is unknown or key is
// shorter than the primitive's MinKeyBytes. Shipped [Registry]
// primitives dispatch to their built-in factories; user-registered
// custom primitives dispatch through their Spec.MakeMAC factory.
func Make(name string, key []byte) (itb.MACFunc, error) {
	spec, ok := Find(name)
	if !ok {
		return nil, fmt.Errorf("macs: unknown MAC %q", name)
	}
	if len(key) < spec.MinKeyBytes {
		return nil, fmt.Errorf("macs: %s key too short: %d bytes (min %d)",
			name, len(key), spec.MinKeyBytes)
	}
	switch name {
	case "kmac256":
		return KMAC256(key)
	case "hmac-sha256":
		return HMACSHA256(key)
	case "hmac-blake3":
		return HMACBLAKE3(key)
	}
	if spec.MakeMAC != nil {
		return spec.MakeMAC(key)
	}
	return nil, fmt.Errorf("macs: dispatcher missing %q", name)
}

// MakeIncremental returns the multi-slice arm for the named primitive
// keyed by key: an itb.MACIncrementalFunc emitting the same tag as
// the Make-built itb.MACFunc over the concatenation of its chunks,
// byte-for-byte. Same name and key validation as [Make]. Every
// shipped primitive provides the incremental arm; user-registered
// custom primitives dispatch through their Spec.MakeIncrementalMAC
// factory ([Register] synthesizes one when the registrant supplied
// only the one-shot arm).
func MakeIncremental(name string, key []byte) (itb.MACIncrementalFunc, error) {
	spec, ok := Find(name)
	if !ok {
		return nil, fmt.Errorf("macs: unknown MAC %q", name)
	}
	if len(key) < spec.MinKeyBytes {
		return nil, fmt.Errorf("macs: %s key too short: %d bytes (min %d)",
			name, len(key), spec.MinKeyBytes)
	}
	switch name {
	case "kmac256":
		return KMAC256Incremental(key)
	case "hmac-sha256":
		return HMACSHA256Incremental(key)
	case "hmac-blake3":
		return HMACBLAKE3Incremental(key)
	}
	if spec.MakeIncrementalMAC != nil {
		return spec.MakeIncrementalMAC(key)
	}
	return nil, fmt.Errorf("macs: dispatcher missing %q", name)
}
