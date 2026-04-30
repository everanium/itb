package hashes

import (
	"fmt"

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

// Spec describes one PRF-grade hash primitive shipped with this package.
type Spec struct {
	Name  string // canonical, FFI-stable identifier (no dashes)
	Width Width  // native intermediate-state width
}

// Registry lists every shippable PRF-grade primitive in canonical order.
// The same order is used by the FFI iteration surface (ITB_HashName,
// ITB_HashWidth) so that index 0..8 is stable across releases.
var Registry = [9]Spec{
	{"areion256", W256},
	{"areion512", W512},
	{"siphash24", W128},
	{"aescmac", W128},
	{"blake2b256", W256},
	{"blake2b512", W512},
	{"blake2s", W256},
	{"blake3", W256},
	{"chacha20", W256},
}

// Find returns the Spec for a canonical name and reports whether a match
// was found.
func Find(name string) (Spec, bool) {
	for _, s := range Registry {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// Make128 returns a fresh cached HashFunc128 for the named primitive.
// Returns an error when name is unknown or its native width is not 128.
func Make128(name string) (itb.HashFunc128, error) {
	switch name {
	case "siphash24":
		return SipHash24(), nil
	case "aescmac":
		return AESCMAC(), nil
	}
	if s, ok := Find(name); ok && s.Width != W128 {
		return nil, fmt.Errorf("hashes: %q has width %d, not 128", name, s.Width)
	}
	return nil, fmt.Errorf("hashes: unknown 128-bit primitive %q", name)
}

// Make256 returns a fresh cached HashFunc256 for the named primitive.
// Returns an error when name is unknown or its native width is not 256.
func Make256(name string) (itb.HashFunc256, error) {
	switch name {
	case "areion256":
		h, _ := Areion256Pair()
		return h, nil
	case "blake2b256":
		return BLAKE2b256(), nil
	case "blake2s":
		return BLAKE2s(), nil
	case "blake3":
		return BLAKE3(), nil
	case "chacha20":
		return ChaCha20(), nil
	}
	if s, ok := Find(name); ok && s.Width != W256 {
		return nil, fmt.Errorf("hashes: %q has width %d, not 256", name, s.Width)
	}
	return nil, fmt.Errorf("hashes: unknown 256-bit primitive %q", name)
}

// Make256Pair returns the (single, batched) HashFunc256 / BatchHashFunc256
// pair for primitives that have a 4-way batched implementation; the
// returned BatchHashFunc256 is nil for primitives that do not implement
// a batched path. The single arm is bit-exact equivalent to the value
// returned by Make256 for the same name.
//
// At present only "areion256" returns a non-nil batched arm (driven by
// the VAES + AVX-512 AreionSoEM256x4 ASM path).
func Make256Pair(name string) (itb.HashFunc256, itb.BatchHashFunc256, error) {
	switch name {
	case "areion256":
		h, b := Areion256Pair()
		return h, b, nil
	}
	h, err := Make256(name)
	if err != nil {
		return nil, nil, err
	}
	return h, nil, nil
}

// Make512 returns a fresh cached HashFunc512 for the named primitive.
// Returns an error when name is unknown or its native width is not 512.
func Make512(name string) (itb.HashFunc512, error) {
	switch name {
	case "areion512":
		h, _ := Areion512Pair()
		return h, nil
	case "blake2b512":
		return BLAKE2b512(), nil
	}
	if s, ok := Find(name); ok && s.Width != W512 {
		return nil, fmt.Errorf("hashes: %q has width %d, not 512", name, s.Width)
	}
	return nil, fmt.Errorf("hashes: unknown 512-bit primitive %q", name)
}

// Make512Pair returns the (single, batched) HashFunc512 / BatchHashFunc512
// pair for primitives that have a 4-way batched implementation. The
// returned BatchHashFunc512 is nil when no batched path exists.
//
// At present only "areion512" returns a non-nil batched arm.
func Make512Pair(name string) (itb.HashFunc512, itb.BatchHashFunc512, error) {
	switch name {
	case "areion512":
		h, b := Areion512Pair()
		return h, b, nil
	}
	h, err := Make512(name)
	if err != nil {
		return nil, nil, err
	}
	return h, nil, nil
}
