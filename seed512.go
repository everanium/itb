package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
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
	// BatchHash is the optional 4-way batched counterpart of Hash. See
	// seed512_batch.go for the parity invariant and BatchHashFunc512
	// type. nil disables batched dispatch and preserves the legacy
	// single-call code path; non-nil routes processChunk512 through
	// BatchChainHash512 four pixels at a time.
	BatchHash BatchHashFunc512

	// attachedLockSeed is the optional dedicated lockSeed pointer
	// installed via [Seed512.AttachLockSeed]. When non-nil, the
	// bit-permutation derivation in [buildLockPRF512] /
	// [buildPermutePRF512] (and their Cfg counterparts when no
	// cfg-side lockSeed handle is set) routes through the attached
	// lockSeed instead of the receiver, taking BOTH the lockSeed's
	// Components AND its Hash function for the per-chunk PRF closure
	// — keying-material isolation plus algorithm diversity for the
	// bit-permutation channel relative to the noiseSeed-driven
	// noise-injection channel, without changing any public Encrypt /
	// Decrypt signature.
	attachedLockSeed *Seed512

	// firstEncryptCalled records whether this seed has been used in
	// a successful Encrypt path (process512 marks it on the
	// encode=true branch). The AttachLockSeed safeguard reads this
	// flag and panics with [ErrLockSeedAfterEncrypt] if a re-attach
	// attempt happens after the first encrypt — switching the
	// dedicated lockSeed mid-session would break decryptability of
	// pre-switch ciphertext.
	firstEncryptCalled atomic.Bool
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

// deriveInterLockSeed returns the full 512-bit ChainHash output derived from
// the same domain-tagged buffer used by [Seed512.deriveStartPixel].
// deriveStartPixel truncates to a pixel index (~13 bits) of h[0];
// deriveInterLockSeed exposes the full [8]uint64 for consumers that
// need it as PRF seed material — e.g. Lock Soup's per-chunk keystream
// when SetLockSoup(1) is in effect.
//
// Typically called on noiseSeed in the Triple Ouroboros context — the
// only shared seed across the 3 snakes, used as the keying source for
// the cross-snake bit-soup permutation.
func (s *Seed512) deriveInterLockSeed(nonce []byte) [8]uint64 {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x02
	copy(buf[1:], nonce)
	return s.ChainHash512(buf)
}

// AttachLockSeed installs ls as the dedicated lockSeed for this
// noiseSeed. Subsequent Encrypt / Decrypt / EncryptAuthenticated /
// DecryptAuthenticated / EncryptStream / DecryptStream calls that
// take this seed as the noise slot route bit-permutation derivation
// through ls instead of through the receiver — the noise-injection
// channel still consumes the receiver's components and Hash, while
// the bit-permutation channel consumes BOTH ls's Components AND
// ls's Hash function, without changing any public Encrypt / Decrypt
// signature. The PRF primitive on the bit-permutation channel may
// therefore differ from the noise-injection channel's primitive
// within the same native width (the *Seed512 type signature here
// enforces width match), yielding keying-material isolation AND
// algorithm diversity for defence-in-depth on the overlay path.
//
// Anti-conflation safeguards (each panics rather than silently
// degrading the entropy isolation):
//
//   - Self-attach (ls == ns) panics with [ErrLockSeedSelfAttach]:
//     bit-permutation derivation would still consume the receiver's
//     state, defeating the isolation purpose.
//   - Component-aliasing (ls.Components and the receiver's
//     Components share the same backing array — typically because
//     ls was built by copying the slice header rather than the
//     underlying data) panics with [ErrLockSeedComponentAliasing]:
//     a shared backing array means every encrypt-time mutation of
//     either Components slice silently mutates the other, defeating
//     the entropy isolation between the noise-injection and
//     bit-permutation channels. The check is pointer-aliasing on
//     the slice's first element, not value-equality — deep-copied
//     slices that happen to carry identical uint64 values are not
//     caught here.
//   - Post-Encrypt re-attach (this seed has been used in a
//     successful Encrypt) panics with [ErrLockSeedAfterEncrypt]:
//     switching the dedicated lockSeed mid-session breaks
//     decryptability of pre-switch ciphertext.
//
// Idempotent for the same ls (re-attaching the same pointer after
// validation does not panic). Both seeds remain fully independent
// objects — AttachLockSeed does not modify ls and does not copy
// any state between the two; it merely records a single pointer
// field on the receiver.
//
// Not safe for concurrent invocation with an in-flight Encrypt /
// Decrypt on the same noiseSeed — caller serialises the attach
// sequence before dispatching parallel encrypt traffic.
func (s *Seed512) AttachLockSeed(ls *Seed512) {
	if s.firstEncryptCalled.Load() {
		panic(ErrLockSeedAfterEncrypt)
	}
	if ls == s {
		panic(ErrLockSeedSelfAttach)
	}
	if len(s.Components) > 0 && len(ls.Components) > 0 &&
		&s.Components[0] == &ls.Components[0] {
		panic(ErrLockSeedComponentAliasing)
	}
	s.attachedLockSeed = ls
}

// AttachedLockSeed returns the dedicated lockSeed previously
// installed via [Seed512.AttachLockSeed], or nil when no lockSeed
// has been attached. Used internally by the bit-permutation
// derivation builders to route through the dedicated seed when
// present, and by serialization paths to extract the attached
// lockSeed alongside the noiseSeed for persistence.
func (s *Seed512) AttachedLockSeed() *Seed512 {
	return s.attachedLockSeed
}
