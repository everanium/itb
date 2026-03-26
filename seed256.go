package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// HashFunc256 is the pluggable 256-bit hash function interface.
//
// The function accepts arbitrary-length data and a [4]uint64 seed (256 bits),
// returning a [4]uint64 output. The 256-bit intermediate state enables
// effective key sizes up to 2048 bits through ChainHash256.
//
// PRF-grade hash functions are required (see Definition 2 in SCIENCE.md).
//
// Example wrapper:
//
//	// BLAKE3 keyed (256-bit, AVX-512 acceleration)
//	func blake3Hash256(data []byte, seed [4]uint64) [4]uint64 {
//	    var key [32]byte
//	    binary.LittleEndian.PutUint64(key[0:], seed[0])
//	    binary.LittleEndian.PutUint64(key[8:], seed[1])
//	    binary.LittleEndian.PutUint64(key[16:], seed[2])
//	    binary.LittleEndian.PutUint64(key[24:], seed[3])
//	    h := blake3.DeriveKey(key, data)
//	    var out [4]uint64
//	    for i := range out {
//	        out[i] = binary.LittleEndian.Uint64(h[i*8:])
//	    }
//	    return out
//	}
type HashFunc256 func(data []byte, seed [4]uint64) [4]uint64

// Seed256 holds a dynamically-sized symmetric key with a pluggable 256-bit hash function.
//
// Components are consumed 4 per round by ChainHash256, giving 256-bit
// intermediate state. For 2048-bit key (32 components, 8 rounds):
// effective security = 2048 bits.
type Seed256 struct {
	Components []uint64
	Hash       HashFunc256
}

// NewSeed256 creates a new 256-bit seed with cryptographically random components.
//
// bits must be a multiple of 256, in range [512, 2048].
// Components count must be a multiple of 4 (4 per ChainHash256 round).
//
// Example:
//
//	seed, err := itb.NewSeed256(2048, blake3Hash256)
func NewSeed256(bits int, hashFunc HashFunc256) (*Seed256, error) {
	if bits < 512 || bits > MaxKeyBits || bits%256 != 0 {
		return nil, fmt.Errorf("itb: seed256 bits must be 512-%d and multiple of 256, got %d", MaxKeyBits, bits)
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}

	n := bits / 64
	s := &Seed256{
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

// SeedFromComponents256 creates a 256-bit seed from existing uint64 values.
//
// components length must be in range [8, 32] and a multiple of 4.
func SeedFromComponents256(hashFunc HashFunc256, components ...uint64) (*Seed256, error) {
	if len(components) < 8 || len(components) > MaxKeyBits/64 {
		return nil, fmt.Errorf("itb: components count must be 8-%d, got %d", MaxKeyBits/64, len(components))
	}
	if len(components)%4 != 0 {
		return nil, fmt.Errorf("itb: seed256 components must be multiple of 4, got %d", len(components))
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}
	c := make([]uint64, len(components))
	copy(c, components)
	return &Seed256{Components: c, Hash: hashFunc}, nil
}

// Bits returns the key size in bits.
func (s *Seed256) Bits() int {
	return len(s.Components) * 64
}

// MinPixels returns minimum pixel count ensuring encoding ambiguity (56^P)
// exceeds key space (2^keyBits). Formula: ceil(keyBits / log2(56)).
func (s *Seed256) MinPixels() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor56 - 1) / minPixelsDivisor56
}

// MinPixelsAuth returns minimum pixel count ensuring encoding ambiguity (7^P)
// exceeds key space (2^keyBits) even under CCA. Formula: ceil(keyBits / log2(7)).
func (s *Seed256) MinPixelsAuth() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor7 - 1) / minPixelsDivisor7
}

// MinSide returns minimum square container side length.
func (s *Seed256) MinSide() int {
	mp := s.MinPixels()
	side := 1
	for side*side < mp {
		side++
	}
	return side
}

// ChainHash256 computes chained hash across all seed components with 256-bit state.
//
// Each round consumes 4 components and the previous 256-bit output:
//
//	h = Hash256(data, [s[0], s[1], s[2], s[3]])
//	h = Hash256(data, [s[4]^h[0], s[5]^h[1], s[6]^h[2], s[7]^h[3]])
//	...
func (s *Seed256) ChainHash256(buf []byte) [4]uint64 {
	var seed [4]uint64
	copy(seed[:], s.Components[0:4])
	h := s.Hash(buf, seed)
	for i := 4; i < len(s.Components); i += 4 {
		seed[0] = s.Components[i] ^ h[0]
		seed[1] = s.Components[i+1] ^ h[1]
		seed[2] = s.Components[i+2] ^ h[2]
		seed[3] = s.Components[i+3] ^ h[3]
		h = s.Hash(buf, seed)
	}
	return h
}

// blockHash256 computes 256-bit hash for a single pixel.
func (s *Seed256) blockHash256(buf []byte, blockIdx int) [4]uint64 {
	binary.LittleEndian.PutUint32(buf, uint32(blockIdx))
	return s.ChainHash256(buf)
}

// deriveStartPixel computes seed+nonce-dependent pixel offset.
func (s *Seed256) deriveStartPixel(nonce []byte, totalPixels int) int {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x02
	copy(buf[1:], nonce)
	h := s.ChainHash256(buf)
	return int(h[0] % uint64(totalPixels))
}
