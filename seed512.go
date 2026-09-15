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

// BatchHashFunc512 is the 4-way batched 512-bit hash interface
// alongside [HashFunc512]. Primitives whose SIMD kernel processes
// four independent (data, seed) tuples per call expose this, through
// the ZMM-batched width-512 registry kernels on amd64 with
// AVX-512 + VAES.
//
// Bit-exact parity invariant: each lane output
// BatchHashFunc512(data, seeds)[i] matches the serial
// HashFunc512(data[i], seeds[i]) reference. Implementations
// violating this break the PRF assumption on the batched dispatch
// path.
type BatchHashFunc512 func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64

// FusedChainHashFunc512 evaluates the whole [Seed512.ChainHash512]
// cascade in one call: the primitive is applied once per component
// octuple with the previous round's output folded into the next
// octuple, exactly as the sequential loop does, but with the state kept
// inside the primitive's kernel between rounds.
//
// ok reports whether the implementation handled data; when false the
// caller runs the sequential loop and out is meaningless. When true the
// result must be bit-exact with the sequential loop over the same
// components and data. Implementations decide by input shape only, so a
// given (components, data) pair is answered the same way on every call.
type FusedChainHashFunc512 func(components []uint64, data []byte) (out [8]uint64, ok bool)

// BatchFusedChainHashFunc512 is the four-lane counterpart of
// [FusedChainHashFunc512]: every lane runs the cascade over the shared
// components with its own data, matching [Seed512.BatchChainHash512].
type BatchFusedChainHashFunc512 func(components []uint64, data *[4][]byte) (out [4][8]uint64, ok bool)

// BatchFusedChainHashFunc512x8 is the eight-lane counterpart of
// [BatchFusedChainHashFunc512]: every lane runs the whole ChainHash512
// cascade over the shared components with its own data, and the result
// must be bit-exact with two [BatchFusedChainHashFunc512] evaluations
// over the lane halves (and hence with eight sequential cascades). ok
// reports whether the implementation handled data; when false the
// caller runs the four-lane path twice and out is meaningless.
// Implementations decide by input shape only.
//
// The hook is the pixel pipeline's eight-pixel stride at width 512:
// when both the noise and the data seed carry it, processChunk512
// hashes eight pixels per call ahead of the four-pixel and single-pixel
// tails. Shipped primitives attach it only on hosts whose selected tier
// carries an eight-lane kernel (through the hashes package's
// constructors), so
// every other host keeps the four-lane stride unchanged.
type BatchFusedChainHashFunc512x8 func(components []uint64, data *[8][]byte) (out [8][8]uint64, ok bool)

// InterlockFillFunc16x512 is the batch-16 Interlocked Barrier fill
// kernel interface at width 512 — the counterpart of
// [InterlockFillFunc16]. One call fills the 4 consecutive groups
// (16 chunks) starting at groupIdxBase: lane offset i (0..3) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash512
// cascade over components; out receives the 4 × 512-bit outputs at
// [0..3]. The result must be bit-exact with four sequential single-lane
// cascades over the same components and blocks. A performance hook
// only: the cascade fill is the wire with or without it (see
// [Seed512.SetInterlockBatch16]).
type InterlockFillFunc16x512 func(components []uint64, groupIdxBase uint64, out *[4][8]uint64)

// InterlockFillFunc32x512 is the batch-32 Interlocked Barrier fill
// kernel interface at width 512 — the wider counterpart of
// [InterlockFillFunc16x512]. One call fills the 8 consecutive groups
// (32 chunks) starting at groupIdxBase: lane offset i (0..7) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash512
// cascade over components; out receives the 8 × 512-bit outputs at
// [0..7]. The result must be bit-exact with eight sequential
// single-lane cascades over the same components and blocks. A
// performance hook only: the cascade fill is the wire with or without
// it (see [Seed512.SetInterlockBatch32]). The fill ladder tries this
// hook first, then the batch-16 hook, then the four-lane and
// single-lane arms.
type InterlockFillFunc32x512 func(components []uint64, groupIdxBase uint64, out *[8][8]uint64)

// Seed512 holds a dynamically-sized symmetric key with a pluggable 512-bit hash function.
//
// Components are consumed 8 per round by ChainHash512, giving 512-bit
// intermediate state. For 2048-bit key (32 components, 4 rounds):
// effective security = 2048 bits.
type Seed512 struct {
	Components []uint64
	Hash       HashFunc512
	// BatchHash is the optional 4-way batched counterpart of Hash. nil
	// disables batched dispatch and preserves the legacy single-call
	// code path; non-nil routes processChunk512 through
	// BatchChainHash512 four pixels at a time.
	BatchHash BatchHashFunc512

	// FusedChain and BatchFusedChain optionally evaluate the whole
	// ChainHash512 cascade inside the primitive (see
	// [FusedChainHashFunc512]). When non-nil and the implementation
	// reports ok for the input shape, ChainHash512 / BatchChainHash512
	// return the fused result; otherwise they run the sequential loop
	// over Hash / BatchHash. Both paths are bit-exact by contract; the
	// fields are performance hooks, nil disables them.
	FusedChain      FusedChainHashFunc512
	BatchFusedChain BatchFusedChainHashFunc512

	// interlockFillX16 is the batch-16 Interlocked Barrier fill hook for
	// the 13-byte fill shape (the sole shape the overlay uses): 4 groups
	// (16 chunks) per kernel call, see [InterlockFillFunc16x512]. A
	// performance hook only — the cascade fill is the wire with or
	// without it. Populated via SetInterlockBatch16.
	interlockFillX16 InterlockFillFunc16x512

	// interlockFillX32 is the batch-32 counterpart of interlockFillX16:
	// 8 groups (32 chunks) per kernel call, see [InterlockFillFunc32x512].
	// The fill ladder tries it ahead of the batch-16 hook. Populated via
	// SetInterlockBatch32.
	interlockFillX32 InterlockFillFunc32x512

	// batchFusedChainX8 is the eight-lane fused cascade hook of the pixel
	// pipeline (see [BatchFusedChainHashFunc512x8]). When non-nil on both
	// seeds of a call, processChunk512 hashes eight pixels per call ahead
	// of the four-pixel stride. A performance hook only: the wire is
	// identical with and without it. Populated via SetBatchFusedChain8.
	batchFusedChainX8 BatchFusedChainHashFunc512x8
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

// MinPixels returns the minimum pixel count ensuring encoding ambiguity
// exceeds the key space (2^keyBits). Aliases [MinPixelsAuth]'s CCA-
// resistant formula so plain and MAC-authenticated modes share one
// container envelope on small messages.
func (s *Seed512) MinPixels() int {
	return s.MinPixelsAuth()
}

// MinPixelsAuth returns the CCA-resistant minimum pixel count. Formula:
// ceil(keyBits / log2(7)).
func (s *Seed512) MinPixelsAuth() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor7 - 1) / minPixelsDivisor7
}

// ChainHash512 computes chained hash across all seed components with 512-bit state.
//
// Each round consumes 8 components and the previous 512-bit output:
//
//	h = Hash512(data, [s[0], s[1], ..., s[7]])
//	h = Hash512(data, [s[8]^h[0], s[9]^h[1], ..., s[15]^h[7]])
//	...
func (s *Seed512) ChainHash512(buf []byte) [8]uint64 {
	if s.FusedChain != nil {
		if out, ok := s.FusedChain(s.Components, buf); ok {
			return out
		}
	}
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

// deriveInterLockSeed returns the full 512-bit ChainHash output derived
// from the dedicated interlock domain tag (0x04) over the interlock
// nonce. The tag is distinct from the 0x02 tag of
// [Seed512.deriveStartPixel], keeping the two derivations
// cryptographically decorrelated even for byte-identical seed material.
// deriveInterLockSeed exposes the full [8]uint64 for consumers that
// need it as PRF seed material — e.g. the Interlocked Barrier overlay's
// per-chunk keystream.
//
// Called on the dedicated lockSeed slot of the Triple Ouroboros 8-seed
// constellation, keying the 48-bit Interlocked Barrier overlay's
// per-chunk bit-permutation derivation independently of the noiseSeed
// material.
func (s *Seed512) deriveInterLockSeed(nonce []byte) [8]uint64 {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x04
	copy(buf[1:], nonce)
	return s.ChainHash512(buf)
}

// BatchChainHash512 runs the four-way batched ChainHash512 via
// s.BatchHash. Output [i] matches serial ChainHash512(data[i])
// under the same Components. Caller ensures s.BatchHash != nil
// (processChunk512 checks this before invoking).
func (s *Seed512) BatchChainHash512(buf *[4][]byte) [4][8]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(s.Components, buf); ok {
			return out
		}
	}
	var seeds [4][8]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = s.Components[0]
		seeds[lane][1] = s.Components[1]
		seeds[lane][2] = s.Components[2]
		seeds[lane][3] = s.Components[3]
		seeds[lane][4] = s.Components[4]
		seeds[lane][5] = s.Components[5]
		seeds[lane][6] = s.Components[6]
		seeds[lane][7] = s.Components[7]
	}
	h := s.BatchHash(buf, seeds)

	for i := 8; i < len(s.Components); i += 8 {
		c0, c1, c2, c3 := s.Components[i], s.Components[i+1], s.Components[i+2], s.Components[i+3]
		c4, c5, c6, c7 := s.Components[i+4], s.Components[i+5], s.Components[i+6], s.Components[i+7]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
			seeds[lane][2] = c2 ^ h[lane][2]
			seeds[lane][3] = c3 ^ h[lane][3]
			seeds[lane][4] = c4 ^ h[lane][4]
			seeds[lane][5] = c5 ^ h[lane][5]
			seeds[lane][6] = c6 ^ h[lane][6]
			seeds[lane][7] = c7 ^ h[lane][7]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}

// blockHash512x4 is the four-way counterpart of blockHash512.
// Writes pixelIndices[i] as little-endian uint32 into buf[i]'s
// first four bytes, then runs the batched chain hash.
func (s *Seed512) blockHash512x4(buf *[4][]byte, pixelIndices [4]int) [4][8]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash512(buf)
}

// SetBatchFusedChain8 installs the eight-lane fused cascade hook. nil
// removes it; the pixel pipeline then keeps the four-lane stride. The
// hook is a performance path only: with or without it the seed produces
// the same wire.
func (s *Seed512) SetBatchFusedChain8(fn BatchFusedChainHashFunc512x8) {
	s.batchFusedChainX8 = fn
}

// BatchFusedChain8 returns the installed eight-lane fused cascade hook,
// nil when none is attached.
func (s *Seed512) BatchFusedChain8() BatchFusedChainHashFunc512x8 {
	return s.batchFusedChainX8
}

// batchChainHash512x8 runs the eight-lane batched ChainHash512: the
// eight-lane hook first, otherwise two [Seed512.BatchChainHash512] calls
// over the lane halves. Output [i] matches serial ChainHash512(buf[i])
// under the same Components. Caller ensures s.BatchHash != nil.
func (s *Seed512) batchChainHash512x8(buf *[8][]byte) [8][8]uint64 {
	if s.batchFusedChainX8 != nil {
		if out, ok := s.batchFusedChainX8(s.Components, buf); ok {
			return out
		}
	}
	var out [8][8]uint64
	lo := [4][]byte{buf[0], buf[1], buf[2], buf[3]}
	hi := [4][]byte{buf[4], buf[5], buf[6], buf[7]}
	h := s.BatchChainHash512(&lo)
	copy(out[0:4], h[:])
	h = s.BatchChainHash512(&hi)
	copy(out[4:8], h[:])
	return out
}

// blockHash512x8 is the eight-way counterpart of blockHash512x4. Writes
// pixelIndices[i] as little-endian uint32 into buf[i]'s first four
// bytes, then runs the eight-lane batched chain hash.
func (s *Seed512) blockHash512x8(buf *[8][]byte, pixelIndices [8]int) [8][8]uint64 {
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.batchChainHash512x8(buf)
}

// InterlockFillX16 returns the batch-16 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed512) InterlockFillX16() InterlockFillFunc16x512 {
	return s.interlockFillX16
}

// SetInterlockBatch16 installs the batch-16 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the four-lane and single-lane arms. The hook is a
// performance path only: with or without it the seed produces the
// same wire.
func (s *Seed512) SetInterlockBatch16(fn InterlockFillFunc16x512) {
	s.interlockFillX16 = fn
}

// InterlockFillX32 returns the batch-32 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed512) InterlockFillX32() InterlockFillFunc32x512 {
	return s.interlockFillX32
}

// SetInterlockBatch32 installs the batch-32 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the batch-16 hook (when attached), the four-lane and the
// single-lane arms. The hook is a performance path only: with or
// without it the seed produces the same wire.
func (s *Seed512) SetInterlockBatch32(fn InterlockFillFunc32x512) {
	s.interlockFillX32 = fn
}

// chainHash512With evaluates the ChainHash512 cascade over a
// caller-supplied component slice instead of s.Components — the
// prepended slice of the Interlocked Barrier cascade fill
// ([buildLockBatchPRF48_512]). Evaluation order matches
// [Seed512.ChainHash512]: the fused hook first, the sequential Hash
// loop when the hook is absent or declines. components must hold a
// multiple of eight words, at least eight.
func (s *Seed512) chainHash512With(components []uint64, buf []byte) [8]uint64 {
	if s.FusedChain != nil {
		if out, ok := s.FusedChain(components, buf); ok {
			return out
		}
	}
	var seed [8]uint64
	copy(seed[:], components[0:8])
	h := s.Hash(buf, seed)
	for i := 8; i < len(components); i += 8 {
		for j := 0; j < 8; j++ {
			seed[j] = components[i+j] ^ h[j]
		}
		h = s.Hash(buf, seed)
	}
	return h
}

// batchChainHash512With is the four-lane counterpart of
// [Seed512.chainHash512With], mirroring [Seed512.BatchChainHash512]
// over the supplied slice: the batched fused hook first, the
// sequential BatchHash loop otherwise. Output [i] matches
// chainHash512With on buf[i]. Caller ensures s.BatchHash != nil.
func (s *Seed512) batchChainHash512With(components []uint64, buf *[4][]byte) [4][8]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(components, buf); ok {
			return out
		}
	}
	var seeds [4][8]uint64
	for lane := 0; lane < 4; lane++ {
		copy(seeds[lane][:], components[0:8])
	}
	h := s.BatchHash(buf, seeds)
	for i := 8; i < len(components); i += 8 {
		for lane := 0; lane < 4; lane++ {
			for j := 0; j < 8; j++ {
				seeds[lane][j] = components[i+j] ^ h[lane][j]
			}
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}
