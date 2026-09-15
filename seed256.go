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

// BatchHashFunc256 is the 4-way batched 256-bit hash interface
// alongside [HashFunc256]. Primitives whose SIMD kernel processes
// four independent (data, seed) tuples per call expose this, through
// the ZMM-batched width-256 registry kernels on amd64 with
// AVX-512 + VAES.
//
// Bit-exact parity invariant: each lane output
// BatchHashFunc256(data, seeds)[i] matches the serial
// HashFunc256(data[i], seeds[i]) reference. Implementations
// violating this break the PRF assumption on the batched dispatch
// path.
type BatchHashFunc256 func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64

// FusedChainHashFunc256 evaluates the whole [Seed256.ChainHash256]
// cascade in one call: the primitive is applied once per component
// quadruple with the previous round's output folded into the next
// quadruple, exactly as the sequential loop does, but with the state
// kept inside the primitive's kernel between rounds.
//
// ok reports whether the implementation handled data; when false the
// caller runs the sequential loop and out is meaningless. When true the
// result must be bit-exact with the sequential loop over the same
// components and data. Implementations decide by input shape only, so a
// given (components, data) pair is answered the same way on every call.
type FusedChainHashFunc256 func(components []uint64, data []byte) (out [4]uint64, ok bool)

// BatchFusedChainHashFunc256 is the four-lane counterpart of
// [FusedChainHashFunc256]: every lane runs the cascade over the shared
// components with its own data, matching [Seed256.BatchChainHash256].
type BatchFusedChainHashFunc256 func(components []uint64, data *[4][]byte) (out [4][4]uint64, ok bool)

// BatchFusedChainHashFunc256x8 is the eight-lane counterpart of
// [BatchFusedChainHashFunc256]: every lane runs the whole ChainHash256
// cascade over the shared components with its own data, and the result
// must be bit-exact with two [BatchFusedChainHashFunc256] evaluations
// over the lane halves (and hence with eight sequential cascades). ok
// reports whether the implementation handled data; when false the
// caller runs the four-lane path twice and out is meaningless.
// Implementations decide by input shape only.
//
// The hook is the pixel pipeline's eight-pixel stride at width 256:
// when both the noise and the data seed carry it, processChunk256
// hashes eight pixels per call ahead of the four-pixel and single-pixel
// tails. Shipped primitives attach it only on hosts whose selected
// tier carries an eight-lane kernel (through the hashes package's
// constructors),
// so every other host keeps the four-lane stride unchanged.
type BatchFusedChainHashFunc256x8 func(components []uint64, data *[8][]byte) (out [8][4]uint64, ok bool)

// InterlockFillFunc16x256 is the batch-16 Interlocked Barrier fill
// kernel interface at width 256 — the counterpart of
// [InterlockFillFunc16]. One call fills the 8 consecutive groups
// (16 chunks) starting at groupIdxBase: lane offset i (0..7) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash256
// cascade over components; out receives the 8 × 256-bit outputs at
// [0..7]. The result must be bit-exact with eight sequential
// single-lane cascades over the same components and blocks. A
// performance hook only: the cascade fill is the wire with or without
// it (see [Seed256.SetInterlockBatch16]).
type InterlockFillFunc16x256 func(components []uint64, groupIdxBase uint64, out *[8][4]uint64)

// InterlockFillFunc32x256 is the batch-32 Interlocked Barrier fill
// kernel interface at width 256 — the wider counterpart of
// [InterlockFillFunc16x256]. One call fills the 16 consecutive groups
// (32 chunks) starting at groupIdxBase: lane offset i (0..15) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash256
// cascade over components; out receives the 16 × 256-bit outputs at
// [0..15]. The result must be bit-exact with sixteen sequential
// single-lane cascades over the same components and blocks. A
// performance hook only: the cascade fill is the wire with or without
// it (see [Seed256.SetInterlockBatch32]). The fill ladder tries this
// hook first, then the batch-16 hook, then the four-lane and
// single-lane arms.
type InterlockFillFunc32x256 func(components []uint64, groupIdxBase uint64, out *[16][4]uint64)

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
	// of an Encrypt3x256Cfg / Decrypt3x256Cfg invocation expose BatchHash,
	// processChunk256 dispatches per-pixel hashing four pixels at a
	// time via BatchChainHash256 instead of one pixel per ChainHash256
	// call. The Hash field remains the bit-exact reference; BatchHash
	// must agree with Hash on every input. nil disables batched
	// dispatch and preserves the legacy single-call code path.
	BatchHash BatchHashFunc256

	// FusedChain and BatchFusedChain optionally evaluate the whole
	// ChainHash256 cascade inside the primitive (see
	// [FusedChainHashFunc256]). When non-nil and the implementation
	// reports ok for the input shape, ChainHash256 / BatchChainHash256
	// return the fused result; otherwise they run the sequential loop
	// over Hash / BatchHash. Both paths are bit-exact by contract; the
	// fields are performance hooks, nil disables them.
	FusedChain      FusedChainHashFunc256
	BatchFusedChain BatchFusedChainHashFunc256

	// interlockFillX16 is the batch-16 Interlocked Barrier fill hook for
	// the 13-byte fill shape (the sole shape the overlay uses): 8 groups
	// (16 chunks) per kernel call, see [InterlockFillFunc16x256]. A
	// performance hook only — the cascade fill is the wire with or
	// without it. Populated via SetInterlockBatch16.
	interlockFillX16 InterlockFillFunc16x256

	// interlockFillX32 is the batch-32 counterpart of interlockFillX16:
	// 16 groups (32 chunks) per kernel call, see [InterlockFillFunc32x256].
	// The fill ladder tries it ahead of the batch-16 hook. Populated via
	// SetInterlockBatch32.
	interlockFillX32 InterlockFillFunc32x256

	// batchFusedChainX8 is the eight-lane fused cascade hook of the pixel
	// pipeline (see [BatchFusedChainHashFunc256x8]). When non-nil on both
	// seeds of a call, processChunk256 hashes eight pixels per call ahead
	// of the four-pixel stride. A performance hook only: the wire is
	// identical with and without it. Populated via SetBatchFusedChain8.
	batchFusedChainX8 BatchFusedChainHashFunc256x8
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

// MinPixels returns the minimum pixel count ensuring encoding ambiguity
// exceeds the key space (2^keyBits). Aliases [MinPixelsAuth]'s CCA-
// resistant formula so plain and MAC-authenticated modes share one
// container envelope on small messages.
func (s *Seed256) MinPixels() int {
	return s.MinPixelsAuth()
}

// MinPixelsAuth returns the CCA-resistant minimum pixel count. Formula:
// ceil(keyBits / log2(7)).
func (s *Seed256) MinPixelsAuth() int {
	return (s.Bits()*minPixelsScale + minPixelsDivisor7 - 1) / minPixelsDivisor7
}

// ChainHash256 computes chained hash across all seed components with 256-bit state.
//
// Each round consumes 4 components and the previous 256-bit output:
//
//	h = Hash256(data, [s[0], s[1], s[2], s[3]])
//	h = Hash256(data, [s[4]^h[0], s[5]^h[1], s[6]^h[2], s[7]^h[3]])
//	...
func (s *Seed256) ChainHash256(buf []byte) [4]uint64 {
	if s.FusedChain != nil {
		if out, ok := s.FusedChain(s.Components, buf); ok {
			return out
		}
	}
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

// deriveInterLockSeed returns the full 256-bit ChainHash output derived
// from the dedicated interlock domain tag (0x04) over the interlock
// nonce. The tag is distinct from the 0x02 tag of
// [Seed256.deriveStartPixel], keeping the two derivations
// cryptographically decorrelated even for byte-identical seed material.
// deriveInterLockSeed exposes the full [4]uint64 for consumers that
// need it as PRF seed material — e.g. the Interlocked Barrier overlay's
// per-chunk keystream.
//
// Called on the dedicated lockSeed slot of the Triple Ouroboros 8-seed
// constellation, keying the 48-bit Interlocked Barrier overlay's
// per-chunk bit-permutation derivation independently of the noiseSeed
// material.
func (s *Seed256) deriveInterLockSeed(nonce []byte) [4]uint64 {
	buf := make([]byte, 1+len(nonce))
	buf[0] = 0x04
	copy(buf[1:], nonce)
	return s.ChainHash256(buf)
}

// BatchChainHash256 runs the four-way batched ChainHash256 via
// s.BatchHash. Output [i] matches serial ChainHash256(data[i])
// under the same Components. Caller ensures s.BatchHash != nil
// (processChunk256 checks this before invoking).
func (s *Seed256) BatchChainHash256(buf *[4][]byte) [4][4]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(s.Components, buf); ok {
			return out
		}
	}
	var seeds [4][4]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = s.Components[0]
		seeds[lane][1] = s.Components[1]
		seeds[lane][2] = s.Components[2]
		seeds[lane][3] = s.Components[3]
	}
	h := s.BatchHash(buf, seeds)

	for i := 4; i < len(s.Components); i += 4 {
		c0, c1, c2, c3 := s.Components[i], s.Components[i+1], s.Components[i+2], s.Components[i+3]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
			seeds[lane][2] = c2 ^ h[lane][2]
			seeds[lane][3] = c3 ^ h[lane][3]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}

// blockHash256x4 is the four-way counterpart of blockHash256.
// Writes pixelIndices[i] as little-endian uint32 into buf[i]'s
// first four bytes, then runs the batched chain hash.
func (s *Seed256) blockHash256x4(buf *[4][]byte, pixelIndices [4]int) [4][4]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash256(buf)
}

// SetBatchFusedChain8 installs the eight-lane fused cascade hook. nil
// removes it; the pixel pipeline then keeps the four-lane stride. The
// hook is a performance path only: with or without it the seed produces
// the same wire.
func (s *Seed256) SetBatchFusedChain8(fn BatchFusedChainHashFunc256x8) {
	s.batchFusedChainX8 = fn
}

// BatchFusedChain8 returns the installed eight-lane fused cascade hook,
// nil when none is attached.
func (s *Seed256) BatchFusedChain8() BatchFusedChainHashFunc256x8 {
	return s.batchFusedChainX8
}

// batchChainHash256x8 runs the eight-lane batched ChainHash256: the
// eight-lane hook first, otherwise two [Seed256.BatchChainHash256] calls
// over the lane halves. Output [i] matches serial ChainHash256(buf[i])
// under the same Components. Caller ensures s.BatchHash != nil.
func (s *Seed256) batchChainHash256x8(buf *[8][]byte) [8][4]uint64 {
	if s.batchFusedChainX8 != nil {
		if out, ok := s.batchFusedChainX8(s.Components, buf); ok {
			return out
		}
	}
	var out [8][4]uint64
	lo := [4][]byte{buf[0], buf[1], buf[2], buf[3]}
	hi := [4][]byte{buf[4], buf[5], buf[6], buf[7]}
	h := s.BatchChainHash256(&lo)
	copy(out[0:4], h[:])
	h = s.BatchChainHash256(&hi)
	copy(out[4:8], h[:])
	return out
}

// blockHash256x8 is the eight-way counterpart of blockHash256x4. Writes
// pixelIndices[i] as little-endian uint32 into buf[i]'s first four
// bytes, then runs the eight-lane batched chain hash.
func (s *Seed256) blockHash256x8(buf *[8][]byte, pixelIndices [8]int) [8][4]uint64 {
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.batchChainHash256x8(buf)
}

// InterlockFillX16 returns the batch-16 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed256) InterlockFillX16() InterlockFillFunc16x256 {
	return s.interlockFillX16
}

// SetInterlockBatch16 installs the batch-16 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the four-lane and single-lane arms. The hook is a
// performance path only: with or without it the seed produces the
// same wire.
func (s *Seed256) SetInterlockBatch16(fn InterlockFillFunc16x256) {
	s.interlockFillX16 = fn
}

// InterlockFillX32 returns the batch-32 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed256) InterlockFillX32() InterlockFillFunc32x256 {
	return s.interlockFillX32
}

// SetInterlockBatch32 installs the batch-32 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the batch-16 hook (when attached), the four-lane and the
// single-lane arms. The hook is a performance path only: with or
// without it the seed produces the same wire.
func (s *Seed256) SetInterlockBatch32(fn InterlockFillFunc32x256) {
	s.interlockFillX32 = fn
}

// chainHash256With evaluates the ChainHash256 cascade over a
// caller-supplied component slice instead of s.Components — the
// prepended slice of the Interlocked Barrier cascade fill
// ([buildLockBatchPRF48_256]). Evaluation order matches
// [Seed256.ChainHash256]: the fused hook first, the sequential Hash
// loop when the hook is absent or declines. components must hold a
// multiple of four words, at least four.
func (s *Seed256) chainHash256With(components []uint64, buf []byte) [4]uint64 {
	if s.FusedChain != nil {
		if out, ok := s.FusedChain(components, buf); ok {
			return out
		}
	}
	var seed [4]uint64
	copy(seed[:], components[0:4])
	h := s.Hash(buf, seed)
	for i := 4; i < len(components); i += 4 {
		seed[0] = components[i] ^ h[0]
		seed[1] = components[i+1] ^ h[1]
		seed[2] = components[i+2] ^ h[2]
		seed[3] = components[i+3] ^ h[3]
		h = s.Hash(buf, seed)
	}
	return h
}

// batchChainHash256With is the four-lane counterpart of
// [Seed256.chainHash256With], mirroring [Seed256.BatchChainHash256]
// over the supplied slice: the batched fused hook first, the
// sequential BatchHash loop otherwise. Output [i] matches
// chainHash256With on buf[i]. Caller ensures s.BatchHash != nil.
func (s *Seed256) batchChainHash256With(components []uint64, buf *[4][]byte) [4][4]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(components, buf); ok {
			return out
		}
	}
	var seeds [4][4]uint64
	for lane := 0; lane < 4; lane++ {
		copy(seeds[lane][:], components[0:4])
	}
	h := s.BatchHash(buf, seeds)
	for i := 4; i < len(components); i += 4 {
		c0, c1, c2, c3 := components[i], components[i+1], components[i+2], components[i+3]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
			seeds[lane][2] = c2 ^ h[lane][2]
			seeds[lane][3] = c3 ^ h[lane][3]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}
