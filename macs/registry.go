package macs

import (
	"fmt"

	"github.com/everanium/itb"
)

// Spec describes one shipped MAC primitive.
type Spec struct {
	Name        string // canonical FFI-stable identifier
	KeySize     int    // recommended key size in bytes
	TagSize     int    // tag size in bytes (constant per primitive)
	MinKeyBytes int    // minimum acceptable key length (for HMAC variants)
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
// match was found.
func Find(name string) (Spec, bool) {
	for _, s := range Registry {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// Make returns a fresh cached itb.MACFunc for the named primitive,
// keyed by key. Returns an error when name is unknown or key is
// shorter than the primitive's MinKeyBytes.
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
	return nil, fmt.Errorf("macs: dispatcher missing %q", name)
}
