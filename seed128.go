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

// BatchHashFunc128 is the 4-way batched 128-bit hash interface
// alongside [HashFunc128]. Primitives whose SIMD kernel processes
// four independent (data, seed) tuples per call expose this, through
// the ZMM-batched width-128 registry kernels on amd64 with
// AVX-512 + VAES.
//
// Bit-exact parity invariant: each lane output
// BatchHashFunc128(data, seeds)[i] matches the serial
// HashFunc128(data[i], seeds[i][0], seeds[i][1]) reference.
// Implementations violating this break the PRF assumption on the
// batched dispatch path.
type BatchHashFunc128 func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64

// FusedChainHashFunc128 evaluates the whole [Seed128.ChainHash128]
// cascade in one call: the primitive is applied once per component pair
// with the previous round's (lo, hi) folded into the next pair, exactly
// as the sequential loop does, but with the state kept inside the
// primitive's kernel between rounds.
//
// ok reports whether the implementation handled data; when false the
// caller runs the sequential loop and lo / hi are meaningless. When true
// the result must be bit-exact with the sequential loop over the same
// components and data. Implementations decide by input shape only, so a
// given (components, data) pair is answered the same way on every call.
type FusedChainHashFunc128 func(components []uint64, data []byte) (lo, hi uint64, ok bool)

// BatchFusedChainHashFunc128 is the four-lane counterpart of
// [FusedChainHashFunc128]: every lane runs the cascade over the shared
// components with its own data, matching [Seed128.BatchChainHash128].
type BatchFusedChainHashFunc128 func(components []uint64, data *[4][]byte) (out [4][2]uint64, ok bool)

// BatchFusedChainHashFunc128x8 is the eight-lane counterpart of
// [BatchFusedChainHashFunc128]: every lane runs the whole ChainHash128
// cascade over the shared components with its own data, and the result
// must be bit-exact with two [BatchFusedChainHashFunc128] evaluations
// over the lane halves (and hence with eight sequential cascades). ok
// reports whether the implementation handled data; when false the
// caller runs the four-lane path twice and out is meaningless.
// Implementations decide by input shape only.
//
// The hook is the pixel pipeline's eight-pixel stride: when both the
// noise and the data seed carry it, processChunk128 hashes eight pixels
// per call ahead of the four-pixel and single-pixel tails. Shipped
// primitives attach it only on hosts whose selected tier carries an
// eight-lane kernel (through the hashes package's constructors), so
// every other host keeps the four-lane stride unchanged.
type BatchFusedChainHashFunc128x8 func(components []uint64, data *[8][]byte) (out [8][2]uint64, ok bool)

// InterlockFillFunc16 is the batch-16 Interlocked Barrier fill kernel
// interface at width 128. Every lockSeed fills its rank pairs with the
// whole ChainHash cascade over components — the prepended slice
// [lockLo, lockHi, c[0], c[1], …] the fill builder assembles from the
// nonce-derived pair and the seed's Components — and the hook, when
// attached (by the hashes package's constructors), evaluates that cascade for
// 16 consecutive groups in one kernel call: groupIdxBase is the first
// group index and lane offset i (0..15) produces groupIdx =
// groupIdxBase + i on the fill block [0x03 | LE64(groupIdx) | 4×0x00];
// out receives the 16 × 128-bit rank pairs at [0..15]. The result must
// be bit-exact with sixteen sequential single-lane cascades over the
// same components and blocks. A performance hook only: the cascade
// fill is the wire with or without it.
type InterlockFillFunc16 func(components []uint64, groupIdxBase uint64, out *[16][2]uint64)

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
	// must agree with Hash on every input. nil disables batched
	// dispatch and preserves the legacy single-call code path.
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
	// the 13-byte fill shape (the sole shape the overlay uses): 16
	// groups per kernel call, see InterlockFillFunc16. A performance
	// hook only — the cascade fill is the wire with or without it.
	// Populated via SetInterlockBatch16.
	interlockFillX16 InterlockFillFunc16

	// batchFusedChainX8 is the eight-lane fused cascade hook of the pixel
	// pipeline (see BatchFusedChainHashFunc128x8). When non-nil on both
	// the noise and the data seed, processChunk128 hashes eight pixels
	// per call ahead of the four-pixel stride; nil keeps the four-lane
	// path. A performance hook only — the wire is identical either way.
	// Populated via SetBatchFusedChain8.
	batchFusedChainX8 BatchFusedChainHashFunc128x8
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
// Directly-constructed seeds keep their optional fast-path hooks nil
// and route hot paths through the sequential fallback; the name-keyed
// constructor hashes.NewSeed128 (the path the triple package and the C
// ABI take) attaches them. The
// hooks are performance paths only: a seed produces the same wire with
// and without them, including the Interlocked Barrier cascade fill,
// which every lockSeed runs at every width (see [InterlockFillFunc16]).
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
// and route hot paths through the sequential fallback;
// hashes.SeedFromComponents128 rebuilds a seed of a registry primitive
// with them. The hooks are performance paths only: a seed rebuilt
// from components decrypts what the exporting side encrypted with or
// without them.
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
// resistant formula so plain and MAC-authenticated modes share one
// container envelope on small messages.
func (s *Seed128) MinPixels() int {
	return s.MinPixelsAuth()
}

// MinPixelsAuth returns the CCA-resistant minimum pixel count. Formula:
// ceil(keyBits / log2(7)).
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

// BatchChainHash128 runs the four-way batched ChainHash128 via
// s.BatchHash. Output [i] matches serial ChainHash128(data[i])
// under the same Components. Caller ensures s.BatchHash != nil
// (processChunk128 checks this before invoking).
func (s *Seed128) BatchChainHash128(buf *[4][]byte) [4][2]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(s.Components, buf); ok {
			return out
		}
	}
	var seeds [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = s.Components[0]
		seeds[lane][1] = s.Components[1]
	}
	h := s.BatchHash(buf, seeds)

	for i := 2; i < len(s.Components); i += 2 {
		c0, c1 := s.Components[i], s.Components[i+1]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}

// blockHash128x4 is the four-way counterpart of blockHash128.
// Writes pixelIndices[i] as little-endian uint32 into buf[i]'s
// first four bytes, then runs the batched chain hash.
func (s *Seed128) blockHash128x4(buf *[4][]byte, pixelIndices [4]int) [4][2]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash128(buf)
}

// SetBatchFusedChain8 installs the eight-lane fused cascade hook. nil
// removes it; the pixel pipeline then keeps the four-lane stride. The
// hook is a performance path only: with or without it the seed produces
// the same wire.
func (s *Seed128) SetBatchFusedChain8(fn BatchFusedChainHashFunc128x8) {
	s.batchFusedChainX8 = fn
}

// BatchFusedChain8 returns the installed eight-lane fused cascade hook,
// nil when none is attached.
func (s *Seed128) BatchFusedChain8() BatchFusedChainHashFunc128x8 {
	return s.batchFusedChainX8
}

// batchChainHash128x8 runs the eight-lane batched ChainHash128: the
// eight-lane hook first, otherwise two [Seed128.BatchChainHash128] calls
// over the lane halves. Output [i] matches serial ChainHash128(buf[i])
// under the same Components. Caller ensures s.BatchHash != nil.
func (s *Seed128) batchChainHash128x8(buf *[8][]byte) [8][2]uint64 {
	if s.batchFusedChainX8 != nil {
		if out, ok := s.batchFusedChainX8(s.Components, buf); ok {
			return out
		}
	}
	var out [8][2]uint64
	lo := [4][]byte{buf[0], buf[1], buf[2], buf[3]}
	hi := [4][]byte{buf[4], buf[5], buf[6], buf[7]}
	h := s.BatchChainHash128(&lo)
	copy(out[0:4], h[:])
	h = s.BatchChainHash128(&hi)
	copy(out[4:8], h[:])
	return out
}

// blockHash128x8 is the eight-way counterpart of blockHash128x4. Writes
// pixelIndices[i] as little-endian uint32 into buf[i]'s first four
// bytes, then runs the eight-lane batched chain hash.
func (s *Seed128) blockHash128x8(buf *[8][]byte, pixelIndices [8]int) [8][2]uint64 {
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.batchChainHash128x8(buf)
}

// InterlockFillX16 returns the batch-16 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed128) InterlockFillX16() InterlockFillFunc16 {
	return s.interlockFillX16
}

// SetInterlockBatch16 installs the batch-16 interlock PRF fill hook
// (the hashes package calls it after resolving the factory by name).
// nil removes it; the Interlocked Barrier fill then runs the
// cascade through the four-lane and single-lane arms. The hook is a
// performance path only: with or without it the seed produces the
// same wire.
func (s *Seed128) SetInterlockBatch16(fn InterlockFillFunc16) {
	s.interlockFillX16 = fn
}

// chainHash128With evaluates the ChainHash128 cascade over a
// caller-supplied component slice instead of s.Components — the
// prepended slice of the Interlocked Barrier cascade fill
// ([buildLockBatchPRF48_128]). Evaluation order matches
// [Seed128.ChainHash128]: the fused hook first, the sequential Hash loop
// when the hook is absent or declines. components must hold an even
// count of at least two words.
func (s *Seed128) chainHash128With(components []uint64, buf []byte) (uint64, uint64) {
	if s.FusedChain != nil {
		if lo, hi, ok := s.FusedChain(components, buf); ok {
			return lo, hi
		}
	}
	hLo, hHi := s.Hash(buf, components[0], components[1])
	for i := 2; i < len(components); i += 2 {
		hLo, hHi = s.Hash(buf, components[i]^hLo, components[i+1]^hHi)
	}
	return hLo, hHi
}

// batchChainHash128With is the four-lane counterpart of
// [Seed128.chainHash128With], mirroring [Seed128.BatchChainHash128] over
// the supplied slice: the batched fused hook first, the sequential
// BatchHash loop otherwise. Output [i] matches chainHash128With on
// buf[i]. Caller ensures s.BatchHash != nil.
func (s *Seed128) batchChainHash128With(components []uint64, buf *[4][]byte) [4][2]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(components, buf); ok {
			return out
		}
	}
	var seeds [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = components[0]
		seeds[lane][1] = components[1]
	}
	h := s.BatchHash(buf, seeds)
	for i := 2; i < len(components); i += 2 {
		c0, c1 := components[i], components[i+1]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}
