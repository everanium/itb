package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
)

// NonceSize is the per-message nonce size in bytes (128 bits).
// Birthday collision after ~2^64 messages; negligible up to ~2^48 messages.
const NonceSize = 16

// MaxKeyBits is the maximum supported key size in bits.
// Effective security depends on hash function's internal state width.
const MaxKeyBits = 2048

// HashFunc is the pluggable hash function interface.
//
// The function must accept arbitrary-length data and a uint64 seed,
// returning a uint64 output. The output must be deterministic for
// identical inputs.
//
// The construction requires five properties from the hash function
// (PRF/PRP/PRG relaxed under the random-container model; PRF recommended).
// All five apply universally to all modes:
// (1) full input sensitivity, (2) chain survival, (3) non-affine mixing,
// (4) avalanche, (5) non-invertibility.
//
// The excluded class: (1) constant functions, (2) XOR-cancelling
// functions, (3) partial-input functions, (4) affine functions,
// (5) functions without avalanche, (6) invertible functions.
// See SCIENCE.md Definition 2 for details.
//
// Example wrappers:
//
//	// XXH3 (github.com/zeebo/xxh3) — 64-bit, fastest
//	func xxh3Hash(data []byte, seed uint64) uint64 {
//	    return xxh3.HashSeed(data, seed)
//	}
//
//	// SipHash-2-4 (github.com/dchest/siphash) — 64-bit, cryptographic PRF
//	func sipHash(data []byte, seed uint64) uint64 {
//	    return siphash.Hash(seed, 0, data)
//	}
//
//	// BLAKE3 keyed (github.com/zeebo/blake3) — 256-bit internal state
//	func blake3Hash(data []byte, seed uint64) uint64 {
//	    var key [32]byte
//	    binary.LittleEndian.PutUint64(key[:], seed)
//	    h := blake3.DeriveKey(key, data)
//	    return binary.LittleEndian.Uint64(h[:8])
//	}
type HashFunc func(data []byte, seed uint64) uint64

// Seed holds a dynamically-sized symmetric key with a pluggable hash function.
//
// Key size is len(Components) * 64 bits. Each component is an independent
// uint64 generated from crypto/rand. Components are consumed by ChainHash
// in sequence — no algebraic relationship between components,
// reducing related-key attack surface.
//
// Effective security bound:
//
//	min(keyBits, hashInternalState * numRounds)
//
// For XXH3 (64-bit state):    effective max = 512 bits
// For SipHash/AES (128-bit):  effective max = 1024 bits
// For BLAKE3 (256-bit):       effective max = 2048 bits
type Seed struct {
	Components []uint64
	Hash       HashFunc
}

// NewSeed creates a new seed with cryptographically random components.
//
// bits must be a multiple of 64, in range [512, 2048].
// Minimum 512 bits (8 components) is intended to provide sufficient
// ChainHash mixing for non-cryptographic hash functions.
// hashFunc is the pluggable hash function (see [HashFunc] documentation).
//
// Example:
//
//	seed, err := itb.NewSeed(512, xxh3.HashSeed)
//	seed, err := itb.NewSeed(1024, mySipHashWrapper)
//	seed, err := itb.NewSeed(2048, myBlake3Wrapper)
func NewSeed(bits int, hashFunc HashFunc) (*Seed, error) {
	if bits < 512 || bits > MaxKeyBits || bits%64 != 0 {
		return nil, fmt.Errorf("itb: seed bits must be 512-%d and multiple of 64, got %d", MaxKeyBits, bits)
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}

	n := bits / 64
	s := &Seed{
		Components: make([]uint64, n),
		Hash:       hashFunc,
	}

	buf := make([]byte, n*8)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	for i := 0; i < n; i++ {
		s.Components[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	return s, nil
}

// SeedFromComponents creates a seed from existing uint64 values.
//
// This is useful for deterministic testing or when key material comes
// from an external key exchange (e.g., ML-KEM, X25519, HKDF).
//
// components length must be in range [8, 32] (512-2048 bits).
// Minimum 8 components is intended to provide sufficient ChainHash mixing.
//
// Example:
//
//	seed, err := itb.SeedFromComponents(xxh3.HashSeed,
//	    0xc07724706ed0758b,
//	    0x0489964ee29ad754,
//	    0x97819a4b77e0fd0a,
//	    0xd9b9322f08f9eb5c,
//	    0x9d8dc0b866e92b87,
//	    0xaf7f4a99914da68b,
//	    0x51101868dab807ae,
//	    0xbc6e07a2a5067689,
//	)
func SeedFromComponents(hashFunc HashFunc, components ...uint64) (*Seed, error) {
	if len(components) < 8 || len(components) > MaxKeyBits/64 {
		return nil, fmt.Errorf("itb: components count must be 8-%d, got %d", MaxKeyBits/64, len(components))
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}
	c := make([]uint64, len(components))
	copy(c, components)
	return &Seed{
		Components: c,
		Hash:       hashFunc,
	}, nil
}

// Bits returns the key size in bits.
func (s *Seed) Bits() int {
	return len(s.Components) * 64
}

// MinPixels returns minimum pixel count for information-theoretic
// security under the random-container model. Sized so the noise barrier
// (2^(Channels*P)) strictly exceeds the key space (2^keyBits), ensuring
// the barrier exceeds the key space. Uses Channels-1 as divisor to guarantee
// the barrier exceeds (not just equals) the key space.
func (s *Seed) MinPixels() int {
	return (s.Bits() + Channels - 2) / (Channels - 1)
}

// MinSide returns minimum square container side length for full key utilization.
func (s *Seed) MinSide() int {
	mp := s.MinPixels()
	side := 1
	for side*side < mp {
		side++
	}
	return side
}

// ChainHash computes chained hash across all seed components.
//
// Each round feeds the previous output XOR'd with the next component:
//
//	h = Hash(data, components[0])
//	h = Hash(data, components[1] ^ h)
//	h = Hash(data, components[2] ^ h)
//	...
//
// All components participate sequentially. No component can be attacked
// independently — meet-in-the-middle is resisted because intermediate
// state h is not directly observable by the attacker.
func (s *Seed) ChainHash(buf []byte) uint64 {
	h := s.Hash(buf, s.Components[0])
	for i := 1; i < len(s.Components); i++ {
		h = s.Hash(buf, s.Components[i]^h)
	}
	return h
}

// generateNonce returns a fresh 128-bit cryptographic nonce.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nonce, nil
}

// secureWipe zeroes a byte slice to minimize sensitive data exposure in memory.
// runtime.KeepAlive prevents the compiler from optimizing away the zero-fill.
func secureWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// generateRandomBytes returns n cryptographically random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return b, nil
}

