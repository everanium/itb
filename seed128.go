package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
	// of an Encrypt3x128Cfg / Decrypt3x128Cfg invocation expose BatchHash,
	// processChunk128 dispatches per-pixel hashing four pixels at a
	// time via BatchChainHash128 instead of one pixel per ChainHash128
	// call. The Hash field remains the bit-exact reference; BatchHash
	// must agree with Hash on every input (see seed128_batch.go for the
	// parity invariant). nil disables batched dispatch and preserves
	// the legacy single-call code path.
	BatchHash BatchHashFunc128

	// FusedChain and BatchFusedChain optionally evaluate the whole
	// ChainHash128 cascade inside the primitive (see
	// [FusedChainHashFunc128]). When non-nil and the implementation
	// reports ok for the input shape, ChainHash128 / BatchChainHash128
	// return the fused result; otherwise they run the sequential loop
	// over Hash / BatchHash. Both paths are bit-exact by contract; the
	// fields are performance hooks, nil disables them.
	FusedChain      FusedChainHashFunc128
	BatchFusedChain BatchFusedChainHashFunc128

	// interlockFillX16 is the batch-16 Interlocked Barrier fill hook for
	// the 13-byte fill shape (the sole shape the overlay uses). When
	// non-nil the lockSeed fills through the ChainHash cascade over the
	// derived pair and its components, a 16-group batch per kernel call
	// — the hook's presence selects that wire, see InterlockFillFunc16;
	// when nil the derived-pair fill runs. Populated via
	// SetInterlockBatch16.
	interlockFillX16 InterlockFillFunc16
}

// NewSeed128 creates a new 128-bit seed with cryptographically random components.
//
// bits must be a multiple of 128, in range [512, 2048].
// Components count must be even (2 per ChainHash128 round).
//
// Example:
//
//	seed, err := itb.NewSeed128(1024, sipHash128)
//
// For automatic attach of the fused ChainHash and batch-16 interlock
// fast paths, see hashes.NewSeed128x16 — the Low-Level Mode symmetric
// of the triple package's auto-attach. Directly-constructed seeds keep
// their optional hooks nil and route hot paths through the sequential
// fallback until hashes.AttachFused128 and hashes.AttachInterlockBatch16
// are called explicitly. For aesitb128 the batch-16 hook is
// wire-affecting — its presence selects the Interlocked Barrier cascade
// fill (see [InterlockFillFunc16]) — so an aesitb128 seed used as
// lockSeed must carry it to interoperate with seeds built through
// hashes.NewSeed128x16 or the triple package.
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
//
// Directly-constructed seeds keep their optional fast-path hooks nil
// and route hot paths through the sequential fallback until
// hashes.AttachFused128 and hashes.AttachInterlockBatch16 are called
// explicitly; see hashes.NewSeed128x16 for the random-components
// constructor that attaches them in one call and
// hashes.SeedFromComponents128x16 for the existing-components
// counterpart of this constructor. For aesitb128 the batch-16 hook is
// wire-affecting — its presence selects the Interlocked Barrier cascade
// fill (see [InterlockFillFunc16]) — so an aesitb128 lockSeed rebuilt
// from components must carry it to decrypt what the exporting side
// encrypted.
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

// MinPixels returns the minimum pixel count ensuring encoding ambiguity
// exceeds the key space (2^keyBits). Aliases [MinPixelsAuth]'s CCA-
// resistant formula (ceil(keyBits / log2(7))) so plain and
// MAC-authenticated modes share one small-message container envelope
// — the envelope no longer distinguishes mode on tiny payloads.
func (s *Seed128) MinPixels() int {
	return s.MinPixelsAuth()
}

// MinPixelsAuth returns the CCA-resistant minimum pixel count. Formula:
// ceil(keyBits / log2(7)). Used by EncryptAuthenticated/DecryptAuthenticated
// (MAC + Reveal possible) and, since the plain-mode floor was unified,
// also by Encrypt/Decrypt and Stream.
func (s *Seed128) MinPixelsAuth() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor7 - 1) / minPixelsDivisor7
}

// ChainHash128 computes chained hash across all seed components with 128-bit state.
//
// Each round consumes 2 components and the previous 128-bit output:
//
//	(hLo, hHi) = Hash128(data, s[0], s[1])
//	(hLo, hHi) = Hash128(data, s[2] ^ hLo, s[3] ^ hHi)
//	...
func (s *Seed128) ChainHash128(buf []byte) (uint64, uint64) {
	if s.FusedChain != nil {
		if lo, hi, ok := s.FusedChain(s.Components, buf); ok {
			return lo, hi
		}
	}
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

// deriveInterLockSeed returns the full 128-bit ChainHash output derived
// from the dedicated interlock domain tag (0x04) over the interlock
// nonce. The tag is distinct from the 0x02 tag of
// [Seed128.deriveStartPixel], keeping the two derivations
// cryptographically decorrelated even for byte-identical seed material.
// deriveInterLockSeed exposes the full (hLo, hHi) pair for consumers that
// need it as PRF seed material — e.g. the Interlocked Barrier overlay's
// per-chunk keystream.
//
// Called on the dedicated lockSeed slot of the Triple Ouroboros 8-seed
// constellation, keying the 48-bit Interlocked Barrier overlay's
// per-chunk bit-permutation derivation independently of the noiseSeed
// material.
func (s *Seed128) deriveInterLockSeed(nonce []byte) (uint64, uint64) {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x04
	copy(buf[1:], nonce)
	return s.ChainHash128(buf)
}

// InterlockFillX16 returns the batch-16 interlock PRF fill hook.
func (s *Seed128) InterlockFillX16() InterlockFillFunc16 {
	return s.interlockFillX16
}

// SetInterlockBatch16 sets the batch-16 interlock PRF fill hook directly.
// Call from hashes.AttachInterlockBatch16 after resolving the factory by name.
func (s *Seed128) SetInterlockBatch16(fn InterlockFillFunc16) {
	s.interlockFillX16 = fn
}
