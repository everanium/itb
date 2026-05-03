package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
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
	// BatchHash is the optional 4-way batched counterpart of Hash. When
	// non-nil and ITB's runtime detects that both noiseSeed and dataSeed
	// of an Encrypt256 / Decrypt256 invocation expose BatchHash,
	// processChunk256 dispatches per-pixel hashing four pixels at a
	// time via BatchChainHash256 instead of one pixel per ChainHash256
	// call. The Hash field remains the bit-exact reference; BatchHash
	// must agree with Hash on every input (see seed256_batch.go for the
	// parity invariant). nil disables batched dispatch and preserves
	// the legacy single-call code path.
	BatchHash BatchHashFunc256

	// attachedLockSeed is the optional dedicated lockSeed pointer
	// installed via [Seed256.AttachLockSeed]. When non-nil, the
	// bit-permutation derivation in [buildLockPRF256] /
	// [buildPermutePRF256] (and their Cfg counterparts when no
	// cfg-side lockSeed handle is set) routes through the attached
	// lockSeed instead of the receiver, taking BOTH the lockSeed's
	// Components AND its Hash function for the per-chunk PRF closure
	// — keying-material isolation plus algorithm diversity for the
	// bit-permutation channel relative to the noiseSeed-driven
	// noise-injection channel, without changing any public Encrypt /
	// Decrypt signature.
	attachedLockSeed *Seed256

	// firstEncryptCalled records whether this seed has been used in
	// a successful Encrypt path (process256 marks it on the
	// encode=true branch). The AttachLockSeed safeguard reads this
	// flag and panics with [ErrLockSeedAfterEncrypt] if a re-attach
	// attempt happens after the first encrypt — switching the
	// dedicated lockSeed mid-session would break decryptability of
	// pre-switch ciphertext.
	firstEncryptCalled atomic.Bool
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

// deriveInterLockSeed returns the full 256-bit ChainHash output derived from
// the same domain-tagged buffer used by [Seed256.deriveStartPixel].
// deriveStartPixel truncates to a pixel index (~13 bits) of h[0];
// deriveInterLockSeed exposes the full [4]uint64 for consumers that
// need it as PRF seed material — e.g. Lock Soup's per-chunk keystream
// when SetLockSoup(1) is in effect.
//
// Typically called on noiseSeed in the Triple Ouroboros context — the
// only shared seed across the 3 snakes, used as the keying source for
// the cross-snake bit-soup permutation.
func (s *Seed256) deriveInterLockSeed(nonce []byte) [4]uint64 {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x02
	copy(buf[1:], nonce)
	return s.ChainHash256(buf)
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
// within the same native width (the *Seed256 type signature here
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
func (s *Seed256) AttachLockSeed(ls *Seed256) {
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
// installed via [Seed256.AttachLockSeed], or nil when no lockSeed
// has been attached. Used internally by the bit-permutation
// derivation builders to route through the dedicated seed when
// present, and by serialization paths to extract the attached
// lockSeed alongside the noiseSeed for persistence.
func (s *Seed256) AttachedLockSeed() *Seed256 {
	return s.attachedLockSeed
}

// DetachLockSeed removes a previously-installed dedicated lockSeed
// pointer from this noiseSeed. See [Seed128.DetachLockSeed] for the
// full contract.
func (s *Seed256) DetachLockSeed() {
	if s.firstEncryptCalled.Load() {
		panic(ErrLockSeedAfterEncrypt)
	}
	s.attachedLockSeed = nil
}
