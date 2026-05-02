package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

// HashFunc128 is the pluggable 128-bit hash function interface.
//
// The function accepts arbitrary-length data and two uint64 seed values,
// returning two uint64 outputs (128-bit total). The 128-bit intermediate
// state enables effective key sizes up to 1024 bits through ChainHash128.
//
// PRF-grade hash functions are required (see Definition 2 in SCIENCE.md).
//
// Example wrappers:
//
//	// SipHash-2-4 (natural 128-bit keyed hash)
//	func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
//	    return siphash.Hash128(seed0, seed1, data)
//	}
//
//	// AES-CMAC (128-bit, AES-NI hardware acceleration)
//	func aesCMAC128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
//	    var key [16]byte
//	    binary.LittleEndian.PutUint64(key[:8], seed0)
//	    binary.LittleEndian.PutUint64(key[8:], seed1)
//	    // compute CMAC...
//	    return lo, hi
//	}
type HashFunc128 func(data []byte, seed0, seed1 uint64) (lo, hi uint64)

// Seed128 holds a dynamically-sized symmetric key with a pluggable 128-bit hash function.
//
// Key size is len(Components) * 64 bits. Components are consumed 2 per round
// by ChainHash128, giving 128-bit intermediate state. Effective security:
// min(keyBits, 128 * numRounds). For 1024-bit key (16 components, 8 rounds):
// effective security = 1024 bits.
type Seed128 struct {
	Components []uint64
	Hash       HashFunc128
	// BatchHash is the optional 4-way batched counterpart of Hash. When
	// non-nil and ITB's runtime detects that both noiseSeed and dataSeed
	// of an Encrypt128 / Decrypt128 invocation expose BatchHash,
	// processChunk128 dispatches per-pixel hashing four pixels at a
	// time via BatchChainHash128 instead of one pixel per ChainHash128
	// call. The Hash field remains the bit-exact reference; BatchHash
	// must agree with Hash on every input (see seed128_batch.go for the
	// parity invariant). nil disables batched dispatch and preserves
	// the legacy single-call code path.
	BatchHash BatchHashFunc128

	// attachedLockSeed is the optional dedicated lockSeed pointer
	// installed via [Seed128.AttachLockSeed]. When non-nil, the
	// bit-permutation derivation in [buildLockPRF128] /
	// [buildPermutePRF128] (and their Cfg counterparts when no
	// cfg-side lockSeed handle is set) routes through the attached
	// lockSeed instead of the receiver, separating bit-permutation
	// entropy from the noiseSeed-driven noise-injection channel
	// without changing any public Encrypt / Decrypt signature.
	attachedLockSeed *Seed128

	// firstEncryptCalled records whether this seed has been used in
	// a successful Encrypt path (process128 marks it on the
	// encode=true branch). The AttachLockSeed safeguard reads this
	// flag and panics with [ErrLockSeedAfterEncrypt] if a re-attach
	// attempt happens after the first encrypt — switching the
	// dedicated lockSeed mid-session would break decryptability of
	// pre-switch ciphertext.
	firstEncryptCalled atomic.Bool
}

// NewSeed128 creates a new 128-bit seed with cryptographically random components.
//
// bits must be a multiple of 128, in range [512, 2048].
// Components count must be even (2 per ChainHash128 round).
//
// Example:
//
//	seed, err := itb.NewSeed128(1024, sipHash128)
func NewSeed128(bits int, hashFunc HashFunc128) (*Seed128, error) {
	if bits < 512 || bits > MaxKeyBits || bits%128 != 0 {
		return nil, fmt.Errorf("itb: seed128 bits must be 512-%d and multiple of 128, got %d", MaxKeyBits, bits)
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}

	n := bits / 64
	s := &Seed128{
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

// SeedFromComponents128 creates a 128-bit seed from existing uint64 values.
//
// components length must be in range [8, 32] and even.
//
// Example:
//
//	seed, err := itb.SeedFromComponents128(sipHash128,
//	    0xc07724706ed0758b, 0x0489964ee29ad754,
//	    0x97819a4b77e0fd0a, 0xd9b9322f08f9eb5c,
//	    0x9d8dc0b866e92b87, 0xaf7f4a99914da68b,
//	    0x51101868dab807ae, 0xbc6e07a2a5067689,
//	)
func SeedFromComponents128(hashFunc HashFunc128, components ...uint64) (*Seed128, error) {
	if len(components) < 8 || len(components) > MaxKeyBits/64 {
		return nil, fmt.Errorf("itb: components count must be 8-%d, got %d", MaxKeyBits/64, len(components))
	}
	if len(components)%2 != 0 {
		return nil, fmt.Errorf("itb: seed128 components must be even, got %d", len(components))
	}
	if hashFunc == nil {
		return nil, fmt.Errorf("itb: hashFunc must not be nil")
	}
	c := make([]uint64, len(components))
	copy(c, components)
	return &Seed128{Components: c, Hash: hashFunc}, nil
}

// Bits returns the key size in bits.
func (s *Seed128) Bits() int {
	return len(s.Components) * 64
}

// MinPixels returns minimum pixel count ensuring encoding ambiguity (56^P)
// exceeds key space (2^keyBits). Formula: ceil(keyBits / log2(56)).
// Used by Encrypt/Decrypt and Stream functions (Core ITB / MAC + Silent Drop).
func (s *Seed128) MinPixels() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor56 - 1) / minPixelsDivisor56
}

// MinPixelsAuth returns minimum pixel count ensuring encoding ambiguity (7^P)
// exceeds key space (2^keyBits) even under CCA. Formula: ceil(keyBits / log2(7)).
// Used by EncryptAuthenticated/DecryptAuthenticated (MAC + Reveal possible).
func (s *Seed128) MinPixelsAuth() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor7 - 1) / minPixelsDivisor7
}

// MinSide returns minimum square container side length.
func (s *Seed128) MinSide() int {
	mp := s.MinPixels()
	side := 1
	for side*side < mp {
		side++
	}
	return side
}

// ChainHash128 computes chained hash across all seed components with 128-bit state.
//
// Each round consumes 2 components and the previous 128-bit output:
//
//	(hLo, hHi) = Hash128(data, s[0], s[1])
//	(hLo, hHi) = Hash128(data, s[2] ^ hLo, s[3] ^ hHi)
//	...
func (s *Seed128) ChainHash128(buf []byte) (uint64, uint64) {
	hLo, hHi := s.Hash(buf, s.Components[0], s.Components[1])
	for i := 2; i < len(s.Components); i += 2 {
		hLo, hHi = s.Hash(buf, s.Components[i]^hLo, s.Components[i+1]^hHi)
	}
	return hLo, hHi
}

// blockHash128 computes 128-bit hash for a single pixel.
func (s *Seed128) blockHash128(buf []byte, blockIdx int) (uint64, uint64) {
	binary.LittleEndian.PutUint32(buf, uint32(blockIdx))
	return s.ChainHash128(buf)
}

// deriveStartPixel computes seed+nonce-dependent pixel offset.
func (s *Seed128) deriveStartPixel(nonce []byte, totalPixels int) int {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x02
	copy(buf[1:], nonce)
	hLo, _ := s.ChainHash128(buf)
	return int(hLo % uint64(totalPixels))
}

// deriveInterLockSeed returns the full 128-bit ChainHash output derived from
// the same domain-tagged buffer used by [Seed128.deriveStartPixel].
// deriveStartPixel truncates to a pixel index (~13 bits) of hLo;
// deriveInterLockSeed exposes the full (hLo, hHi) pair for consumers that
// need it as PRF seed material — e.g. Lock Soup's per-chunk keystream
// when SetLockSoup(1) is in effect.
//
// Typically called on noiseSeed in the Triple Ouroboros context — the
// only shared seed across the 3 snakes, used as the keying source for
// the cross-snake bit-soup permutation.
func (s *Seed128) deriveInterLockSeed(nonce []byte) (uint64, uint64) {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x02
	copy(buf[1:], nonce)
	return s.ChainHash128(buf)
}

// AttachLockSeed installs ls as the dedicated lockSeed for this
// noiseSeed. Subsequent Encrypt / Decrypt / EncryptAuthenticated /
// DecryptAuthenticated / EncryptStream / DecryptStream calls that
// take this seed as the noise slot route bit-permutation derivation
// through ls instead of through the receiver — the noise-injection
// channel still consumes the receiver's components, but the
// bit-permutation channel consumes ls's components, separating the
// two entropy sources without changing any public Encrypt /
// Decrypt signature.
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
func (s *Seed128) AttachLockSeed(ls *Seed128) {
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
// installed via [Seed128.AttachLockSeed], or nil when no lockSeed
// has been attached. Used internally by the bit-permutation
// derivation builders to route through the dedicated seed when
// present, and by serialization paths to extract the attached
// lockSeed alongside the noiseSeed for persistence.
func (s *Seed128) AttachedLockSeed() *Seed128 {
	return s.attachedLockSeed
}
