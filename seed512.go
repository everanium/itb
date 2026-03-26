package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// HashFunc512 is the pluggable 512-bit hash function interface.
//
// The function accepts arbitrary-length data and a [8]uint64 seed (512 bits),
// returning a [8]uint64 output. The 512-bit intermediate state enables
// effective key sizes up to 2048 bits (with current MaxKeyBits) through ChainHash512.
//
// PRF-grade hash functions are required (see Definition 2 in SCIENCE.md).
//
// Example wrapper:
//
//	// BLAKE2b-512 keyed (512-bit native key and output)
//	func blake2b512(data []byte, seed [8]uint64) [8]uint64 {
//	    var key [64]byte
//	    for i := 0; i < 8; i++ {
//	        binary.LittleEndian.PutUint64(key[i*8:], seed[i])
//	    }
//	    h, _ := blake2b.New512(key[:])
//	    h.Write(data)
//	    var digest [64]byte
//	    h.Sum(digest[:0])
//	    var out [8]uint64
//	    for i := range out {
//	        out[i] = binary.LittleEndian.Uint64(digest[i*8:])
//	    }
//	    return out
//	}
type HashFunc512 func(data []byte, seed [8]uint64) [8]uint64

// Seed512 holds a dynamically-sized symmetric key with a pluggable 512-bit hash function.
//
// Components are consumed 8 per round by ChainHash512, giving 512-bit
// intermediate state. For 2048-bit key (32 components, 4 rounds):
// effective security = 2048 bits.
type Seed512 struct {
	Components []uint64
	Hash       HashFunc512
}

// NewSeed512 creates a new 512-bit seed with cryptographically random components.
//
// bits must be a multiple of 512, in range [512, 2048].
// Components count must be a multiple of 8 (8 per ChainHash512 round).
//
// Example:
//
//	seed, err := itb.NewSeed512(2048, blake2b512)
func NewSeed512(bits int, hashFunc HashFunc512) (*Seed512, error) {
	if bits < 512 || bits > MaxKeyBits || bits%512 != 0 {
		return nil, fmt.Errorf("itb: seed512 bits must be 512-%d and multiple of 512, got %d", MaxKeyBits, bits)
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}

	n := bits / 64
	s := &Seed512{
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

// SeedFromComponents512 creates a 512-bit seed from existing uint64 values.
//
// components length must be in range [8, 32] and a multiple of 8.
func SeedFromComponents512(hashFunc HashFunc512, components ...uint64) (*Seed512, error) {
	if len(components) < 8 || len(components) > MaxKeyBits/64 {
		return nil, fmt.Errorf("itb: components count must be 8-%d, got %d", MaxKeyBits/64, len(components))
	}
	if len(components)%8 != 0 {
		return nil, fmt.Errorf("itb: seed512 components must be multiple of 8, got %d", len(components))
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}
	c := make([]uint64, len(components))
	copy(c, components)
	return &Seed512{Components: c, Hash: hashFunc}, nil
}

// Bits returns the key size in bits.
func (s *Seed512) Bits() int {
	return len(s.Components) * 64
}

// MinPixels returns minimum pixel count ensuring encoding ambiguity (56^P)
// exceeds key space (2^keyBits). Formula: ceil(keyBits / log2(56)).
func (s *Seed512) MinPixels() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor56 - 1) / minPixelsDivisor56
}

// MinPixelsAuth returns minimum pixel count ensuring encoding ambiguity (7^P)
// exceeds key space (2^keyBits) even under CCA. Formula: ceil(keyBits / log2(7)).
func (s *Seed512) MinPixelsAuth() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor7 - 1) / minPixelsDivisor7
}

// MinSide returns minimum square container side length.
func (s *Seed512) MinSide() int {
	mp := s.MinPixels()
	side := 1
	for side*side < mp {
		side++
	}
	return side
}

// ChainHash512 computes chained hash across all seed components with 512-bit state.
//
// Each round consumes 8 components and the previous 512-bit output:
//
//	h = Hash512(data, [s[0], s[1], ..., s[7]])
//	h = Hash512(data, [s[8]^h[0], s[9]^h[1], ..., s[15]^h[7]])
//	...
func (s *Seed512) ChainHash512(buf []byte) [8]uint64 {
	var seed [8]uint64
	copy(seed[:], s.Components[0:8])
	h := s.Hash(buf, seed)
	for i := 8; i < len(s.Components); i += 8 {
		seed[0] = s.Components[i] ^ h[0]
		seed[1] = s.Components[i+1] ^ h[1]
		seed[2] = s.Components[i+2] ^ h[2]
		seed[3] = s.Components[i+3] ^ h[3]
		seed[4] = s.Components[i+4] ^ h[4]
		seed[5] = s.Components[i+5] ^ h[5]
		seed[6] = s.Components[i+6] ^ h[6]
		seed[7] = s.Components[i+7] ^ h[7]
		h = s.Hash(buf, seed)
	}
	return h
}

// blockHash512 computes 512-bit hash for a single pixel.
func (s *Seed512) blockHash512(buf []byte, blockIdx int) [8]uint64 {
	binary.LittleEndian.PutUint32(buf, uint32(blockIdx))
	return s.ChainHash512(buf)
}

// deriveStartPixel computes seed+nonce-dependent pixel offset.
func (s *Seed512) deriveStartPixel(nonce []byte, totalPixels int) int {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x02
	copy(buf[1:], nonce)
	h := s.ChainHash512(buf)
	return int(h[0] % uint64(totalPixels))
}
