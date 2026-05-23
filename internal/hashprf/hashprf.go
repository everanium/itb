// Package hashprf builds keyed pseudo-random functions over six hash-based
// ITB registry primitives, exposing each as a fixed-output-width PRF.
//
// The six primitives split into two families:
//
//   - Areion family ("areion256", "areion512") — keyed via the ITB
//     registry HashFunc factories (hashes.Areion256PairWithKey /
//     hashes.Areion512PairWithKey). The PRF hashes the input under a
//     zero seed and serialises the resulting uint64 words little-endian.
//   - BLAKE family ("blake2b256", "blake2s", "blake3", "blake2b512") —
//     keyed via the upstream keyed-hash mode. The PRF output is the
//     leading blockSize bytes of the keyed digest over the input.
//
// The package is a shared dependency of the ctr and kdf packages, which
// import it for their keyed-PRF and SP 800-108 counter-mode constructions
// respectively. It imports the BLAKE upstream packages and the ITB hashes
// package; it does not import ctr or kdf, so no import cycle arises.
package hashprf

import (
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb/hashes"
)

// Registry names accepted by New, KeySize, and BlockSize.
const (
	Areion256  = "areion256"
	Areion512  = "areion512"
	BLAKE2b256 = "blake2b256"
	BLAKE2b512 = "blake2b512"
	BLAKE2s    = "blake2s"
	BLAKE3     = "blake3"
)

// spec holds the key length and PRF output width of one primitive.
type spec struct {
	keySize   int
	blockSize int
}

// specs maps each supported name to its key and output widths.
var specs = map[string]spec{
	Areion256:  {keySize: 32, blockSize: 32},
	Areion512:  {keySize: 64, blockSize: 64},
	BLAKE2b256: {keySize: 32, blockSize: 32},
	BLAKE2b512: {keySize: 32, blockSize: 64},
	BLAKE2s:    {keySize: 32, blockSize: 32},
	BLAKE3:     {keySize: 32, blockSize: 32},
}

// KeySize returns the byte length of the key for the named primitive.
func KeySize(name string) (int, error) {
	s, ok := specs[name]
	if !ok {
		return 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	return s.keySize, nil
}

// BlockSize returns the PRF output width in bytes for the named primitive.
func BlockSize(name string) (int, error) {
	s, ok := specs[name]
	if !ok {
		return 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	return s.blockSize, nil
}

// New returns a keyed PRF for one of the six hash-based primitives and its
// output block size. The key length must equal the primitive's key size; a
// mismatched length or an unknown name is an error.
//
// The returned prf writes exactly blockSize bytes into dst[:blockSize], so
// dst must have len(dst) >= blockSize. The returned prf is not safe for
// concurrent use; it reuses internal hasher state and is intended for
// serial, single-stream use.
func New(name string, key []byte) (prf func(dst, in []byte), blockSize int, err error) {
	s, ok := specs[name]
	if !ok {
		return nil, 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	if len(key) != s.keySize {
		return nil, 0, fmt.Errorf("hashprf: %s key must be %d bytes, got %d", name, s.keySize, len(key))
	}

	switch name {
	case Areion256:
		return newAreion256PRF(key), s.blockSize, nil
	case Areion512:
		return newAreion512PRF(key), s.blockSize, nil
	case BLAKE2b256:
		return newBlake2bPRF(key, 32), s.blockSize, nil
	case BLAKE2b512:
		return newBlake2bPRF(key, 64), s.blockSize, nil
	case BLAKE2s:
		return newBlake2sPRF(key), s.blockSize, nil
	case BLAKE3:
		return newBlake3PRF(key), s.blockSize, nil
	default:
		// Unreachable: specs and the switch are kept in lock-step.
		return nil, 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
}

// newAreion256PRF builds a keyed Areion-SoEM-256 HashFunc256 and returns
// a PRF that hashes the input under a zero seed and serialises the four
// resulting uint64 words little-endian into 32 bytes.
func newAreion256PRF(key []byte) func(dst, in []byte) {
	var k [32]byte
	copy(k[:], key)
	hf, _ := hashes.Areion256PairWithKey(k)
	var zero [4]uint64
	return func(dst, in []byte) {
		out := hf(in, zero)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(dst[i*8:], out[i])
		}
	}
}

// newAreion512PRF builds a keyed Areion-SoEM-512 HashFunc512 and returns
// a PRF that hashes the input under a zero seed and serialises the eight
// resulting uint64 words little-endian into 64 bytes.
func newAreion512PRF(key []byte) func(dst, in []byte) {
	var k [64]byte
	copy(k[:], key)
	hf, _ := hashes.Areion512PairWithKey(k)
	var zero [8]uint64
	return func(dst, in []byte) {
		out := hf(in, zero)
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(dst[i*8:], out[i])
		}
	}
}

// newBlake2bPRF keys a BLAKE2b hasher (output size 32 or 64) and returns
// a PRF that resets and re-hashes the input per call. The keyed hasher is
// created once; each call resets its state, so the hasher is not
// reallocated per call.
func newBlake2bPRF(key []byte, size int) func(dst, in []byte) {
	var h hash.Hash
	var err error
	if size == 32 {
		h, err = blake2b.New256(key)
	} else {
		h, err = blake2b.New512(key)
	}
	if err != nil {
		// A valid 32-byte key never fails for BLAKE2b; New has already
		// validated the key length, so any error here is a bug.
		panic(fmt.Sprintf("hashprf: blake2b keying: %v", err))
	}
	var scratch [64]byte
	return func(dst, in []byte) {
		h.Reset()
		h.Write(in)
		out := h.Sum(scratch[:0])
		copy(dst[:size], out[:size])
	}
}

// newBlake2sPRF keys a BLAKE2s-256 hasher and returns a PRF over the
// reset/re-hash cycle.
func newBlake2sPRF(key []byte) func(dst, in []byte) {
	h, err := blake2s.New256(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake2s keying: %v", err))
	}
	var scratch [32]byte
	return func(dst, in []byte) {
		h.Reset()
		h.Write(in)
		out := h.Sum(scratch[:0])
		copy(dst[:32], out[:32])
	}
}

// newBlake3PRF builds a keyed BLAKE3 template and returns a PRF that
// clones the template per call (the clone idiom from hashes/blake3.go),
// avoiding a Reset() data race and re-keying cost.
func newBlake3PRF(key []byte) func(dst, in []byte) {
	template, err := blake3.NewKeyed(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake3 keying: %v", err))
	}
	return func(dst, in []byte) {
		h := template.Clone()
		h.Write(in)
		var buf [32]byte
		h.Sum(buf[:0])
		copy(dst[:32], buf[:])
	}
}
