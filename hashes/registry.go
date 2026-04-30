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
	if s, ok := Find(name); ok && s.Width != W128 {
		return nil, nil, fmt.Errorf("hashes: %q has width %d, not 128", name, s.Width)
	}
	return nil, nil, fmt.Errorf("hashes: unknown 128-bit primitive %q", name)
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
	if s, ok := Find(name); ok && s.Width != W256 {
		return nil, nil, fmt.Errorf("hashes: %q has width %d, not 256", name, s.Width)
	}
	return nil, nil, fmt.Errorf("hashes: unknown 256-bit primitive %q", name)
}

// Make256Pair returns the (single, batched) HashFunc256 / BatchHashFunc256
// pair for primitives that have a 4-way batched implementation, plus
// the fixed key the pair is bound to. The batched arm is nil for
// primitives that do not implement a batched path. The single arm is
// bit-exact equivalent to Make256 for the same name and key.
//
// At present only "areion256" returns a non-nil batched arm (driven by
// the VAES + AVX-512 AreionSoEM256x4 ASM path). Variadic key arg
// follows the same pattern as Make256.
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
	}
	h, ret, err := Make256(name, key...)
	if err != nil {
		return nil, nil, nil, err
	}
	return h, nil, ret, nil
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
	if s, ok := Find(name); ok && s.Width != W512 {
		return nil, nil, fmt.Errorf("hashes: %q has width %d, not 512", name, s.Width)
	}
	return nil, nil, fmt.Errorf("hashes: unknown 512-bit primitive %q", name)
}

// Make512Pair returns the (single, batched) HashFunc512 / BatchHashFunc512
// pair for primitives with a 4-way batched implementation, plus the
// fixed key. The batched arm is nil when no batched path exists.
//
// At present only "areion512" returns a non-nil batched arm.
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
	}
	h, ret, err := Make512(name, key...)
	if err != nil {
		return nil, nil, nil, err
	}
	return h, nil, ret, nil
}
