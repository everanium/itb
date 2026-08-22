package itb

import (
	"encoding/binary"
	"math/bits"
	"runtime"
	"sync"

	"github.com/everanium/itb/internal/interlock"
)

// ============================================================================
// 48-bit Interlock — Go reference kernels
// ============================================================================
//
// The Interlock overlay maps every 6-byte (48-bit) chunk of the padded
// plaintext to three disjoint 16-of-48 balanced masks (m0, m1, m2) drawn
// from a per-chunk PRF output, then compresses the chunk's bits into
// three 16-bit lane values by PEXT under each mask. Popcount-16 masks
// spanning 48 disjoint positions guarantee m0|m1|m2 == 2^48-1 and every
// bit of the chunk lands in exactly one lane.
//
// The three lane values are packed as little-endian uint16 into three
// per-lane byte buffers so each lane holds M*2 bytes for M chunks.
// Encoder and decoder derive identical masks from the shared lockSeed
// and chunk index; the decoder's PDEP under the same masks reconstructs
// the chunk exactly.
//
// Mask-space sizing:
//
//   A = C(48, 16) = 2,254,848,913,647    (41.04 bits)
//   B = C(32, 16) = 601,080,390          (29.16 bits)
//   |mask triples| = A * B ≈ 2^70.20
//
// A per-chunk 128-bit PRF output (two 64-bit lanes) reduces to a pair
// (idx0, idx1) via
//
//   q, idx1 = divmod(rank, B)     (one schoolbook 128-by-30 division)
//   idx0    = q mod A             (secondary reduction; q < 2^99)
//
// which is a bijection onto [0, floor(2^128/B)) × [0, B) followed by a
// wrap onto [0, A). The wrap distributes the floor(2^128/(A*B)) ≈ 2^57.8
// preimages per (idx0, idx1) pair with a ±1 granularity: the lowest
// (2^128 mod (A*B)) pairs receive one extra preimage. Per-pair relative
// deviation ≈ 2^-57.8.
//
// The alternative same-rank double-mod (rank mod A, rank mod B) reaches
// only the pairs (a, b) with a ≡ b (mod gcd(A, B)); gcd(A, B) = 66861 =
// 3^2 * 17 * 19 * 23, so that path covers ~1/66861 of the pair space.
// It is not used and its residue-class trap is guarded by test.

// binomialC48 holds C(n, k) for n in [0, 48], k in [0, 16] — the table
// needed for combinatorial unrank in [rankToMaskTriple48]. Computed once
// at package init time via Pascal's recurrence. The largest entry
// C(48, 16) fits in 42 bits, well within uint64.
var binomialC48 [49][17]uint64

func init() {
	for n := 0; n <= 48; n++ {
		binomialC48[n][0] = 1
		for k := 1; k <= 16 && k <= n; k++ {
			binomialC48[n][k] = binomialC48[n-1][k-1] + binomialC48[n-1][k]
		}
	}
}

// Combinatorial constants used by the reduction and unrank steps. All
// three are constants of the construction, computed above at init.
const (
	interlockA48 uint64 = 2254848913647 // C(48, 16)
	interlockB48 uint64 = 601080390     // C(32, 16)
)

// unrankCombination48 converts a rank in [0, C(n, k)) into a 64-bit mask
// of exactly k set bits drawn from positions [0, n). Combinadic
// decomposition: rank = C(c_k, k) + C(c_{k-1}, k-1) + ... + C(c_1, 1)
// with c_k > c_{k-1} > ... > c_1 >= 0; each c_i identifies a set bit
// position.
//
// Caller must supply rank < C(n, k); behaviour is undefined for
// out-of-range rank. n must be <= 48 (binomialC48 table extent) and
// k must be <= 16.
func unrankCombination48(rank uint64, k, n int) uint64 {
	var mask uint64
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && binomialC48[c+1][k] <= rank {
			c++
		}
		mask |= uint64(1) << uint(c)
		rank -= binomialC48[c][k]
		k--
	}
	return mask
}

// rankToMaskTriple48 maps a 128-bit PRF output (lane0 = low 64, lane1 =
// high 64) to a balanced (m0, m1, m2) 48-bit mask triple where
// popcount(m_i) == 16, m0|m1|m2 == 0xFFFF_FFFF_FFFF, and pairwise
// intersections are empty.
//
// Two-step reduction (see the package-level construction note):
//
//	(q, idx1) = divmod128(rank, B)   — 128-by-30 schoolbook divmod
//	idx0      = q mod A              — secondary reduction (q < 2^99)
//
// The schoolbook divmod is performed limb-by-limb via [math/bits.Div64]
// and the secondary reduction accumulates the running quotient's
// residue mod A across the two 64-bit limbs — no big-integer arithmetic
// is used in production; every step operates on native 64-bit values.
func rankToMaskTriple48(lane0, lane1 uint64) (m0, m1, m2 uint64) {
	// Step 1: divide the 128-bit rank by B, MSB-first.
	//
	//   qHi = lane1 / B                            (uint64 quotient)
	//   r1  = lane1 mod B                          (uint64 remainder < B)
	//   qLo = (r1 * 2^64 + lane0) / B              (uint64 quotient)
	//   r   = (r1 * 2^64 + lane0) mod B            (uint64 remainder < B)
	//
	// Full 128-bit quotient q = qHi * 2^64 + qLo; idx1 = r.
	qHi, r1 := bits.Div64(0, lane1, interlockB48)
	qLo, r := bits.Div64(r1, lane0, interlockB48)
	idx1 := r

	// Step 2: reduce q mod A across its two limbs.
	//
	// qHi is at most floor(2^64 / B) ≈ 2^34 < A, so bits.Div64(0, qHi, A)
	// returns quotient 0 and remainder qHi. The second bits.Div64 then
	// combines qHi (as high limb, < A) with qLo (low limb) and reduces
	// the 128-bit value (qHi * 2^64 + qLo) mod A in one step.
	_, hiMod := bits.Div64(0, qHi, interlockA48)
	_, idx0 := bits.Div64(hiMod, qLo, interlockA48)

	// m0: 16-of-48 mask selected by idx0.
	m0 = unrankCombination48(idx0, 16, 48)

	// m1Local: 16-of-32 mask in the local indexing of remaining positions
	// (bits where m0 is zero). unrankCombination48 keeps everything below
	// bit 32, so the local mask fits in a uint32; we treat it as uint64
	// throughout to keep the arithmetic uniform.
	m1Local := unrankCombination48(idx1, 16, 32)

	// Map m1Local positions onto the actual remaining bit positions.
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	remaining := domain & ^m0
	var posIdx uint
	for bit := uint(0); bit < 48; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint64(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

// softPEXT48 compresses bits of x selected by mask into a contiguous
// low-order 16-bit result. Pure-Go portable equivalent of the x86 BMI2
// PEXT instruction restricted to 48-bit inputs and popcount-16 masks
// (the balanced-mask invariant of the overlay).
//
// Branchless: the loop body uses only bitwise AND, OR, and variable
// shift on register values; outBit increments by an integer derived
// from the mask bit (no conditional). On platforms with hardware
// constant-time variable shift (modern x86 / ARM), every iteration
// runs in fixed time regardless of the secret values in x or mask,
// eliminating the Spectre v1 / branch-predictor surface that a
// conditional implementation would expose.
func softPEXT48(x, mask uint64) uint16 {
	var result uint64
	var outBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		xb := (x >> i) & 1
		result |= (bit & xb) << outBit
		outBit += bit
	}
	return uint16(result)
}

// softPDEP48 expands the low-order popcount(mask) bits of v into the
// positions selected by mask, producing a 48-bit value in the low bits
// of the result. Pure-Go portable equivalent of the x86 BMI2 PDEP
// instruction restricted to 48-bit output widths. Inverse of
// [softPEXT48] under matching mask: softPEXT48(softPDEP48(v, mask),
// mask) == v for popcount(mask) == 16 and v < 2^16.
//
// Branchless: same construction as [softPEXT48] — bitwise AND, OR, and
// variable shift on register values, inBit increments by an integer
// derived from the mask bit. No conditional path on secret values.
func softPDEP48(v uint16, mask uint64) uint64 {
	var result uint64
	var inBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		vb := uint64(v>>inBit) & 1
		result |= (bit & vb) << i
		inBit += bit
	}
	return result
}

// chunk48lock is the forward per-chunk kernel. Applies a PRF-keyed
// bit-permutation to a 48-bit input chunk x under mask triple
// (m0, m1, m2) supplied by the caller (typically derived via
// [rankToMaskTriple48] from a per-chunk PRF output). Each lane
// receives exactly 16 bits compressed by its mask.
//
// On amd64 with BMI2 (Haswell+, Excavator+), dispatches to the
// [interlock.Chunk48Lock] hardware path — three PEXTQ instructions
// total, ~10 cycles per chunk. On other platforms or when BMI2 is
// unavailable, falls back to three [softPEXT48] calls. The branch
// predicts perfectly because [interlock.HasBMI2] is a
// process-lifetime constant.
//
// Caller-side packing convention: x = uint64(b0) | uint64(b1)<<8 | ... |
// uint64(b5)<<40, so the low 48 bits carry the six chunk bytes in
// little-endian order. The three lane outputs each fit in a uint16
// (popcount(m_i) == 16 by construction).
func chunk48lock(x, m0, m1, m2 uint64) (l0, l1, l2 uint16) {
	if interlock.HasBMI2 {
		L0, L1, L2 := interlock.Chunk48Lock(x, m0, m1, m2)
		return uint16(L0), uint16(L1), uint16(L2)
	}
	l0 = softPEXT48(x, m0)
	l1 = softPEXT48(x, m1)
	l2 = softPEXT48(x, m2)
	return
}

// unchunk48lock is the inverse of [chunk48lock]. Reassembles three
// 16-bit lane values into the original 48-bit input chunk under the
// same (m0, m1, m2) mask triple. Caller must supply the same masks
// used by chunk48lock — encoder and decoder agree by deriving
// identical masks from the shared lockSeed and chunk index.
//
// On amd64 with BMI2, dispatches to the [interlock.Unchunk48Lock]
// hardware path (three PDEPQ plus two ORs); otherwise falls back to
// three [softPDEP48] calls. The three PDEP-expansions land in
// disjoint bit positions (m0|m1|m2 covers all 48 bits with no
// overlap), so OR-ing them reconstructs x.
func unchunk48lock(l0, l1, l2 uint16, m0, m1, m2 uint64) uint64 {
	if interlock.HasBMI2 {
		return interlock.Unchunk48Lock(uint64(l0), uint64(l1), uint64(l2), m0, m1, m2)
	}
	return softPDEP48(l0, m0) | softPDEP48(l1, m1) | softPDEP48(l2, m2)
}

// ============================================================================
// Chunk packing / lane serialisation conventions
// ============================================================================
//
// Chunk word x is packed little-endian from six padded bytes:
//
//	x = uint64(b0)       | uint64(b1) <<  8 | uint64(b2) << 16 |
//	    uint64(b3) << 24 | uint64(b4) << 32 | uint64(b5) << 40
//
// Lane values (uint16 each) are serialised into the per-lane byte
// buffer as little-endian at offset 2*k for chunk index k:
//
//	p_i[2*k]   = byte(l_i)
//	p_i[2*k+1] = byte(l_i >> 8)
//
// Both conventions are fixed for the wire — the encoder and decoder
// agree bit-exactly on them, and any host-endianness question is
// resolved by these explicit shifts (no unaligned reads from the
// caller's buffer are needed).

// readChunk48 packs the six padded bytes starting at padded[base] into
// the low 48 bits of a uint64, using the little-endian convention above.
func readChunk48(padded []byte, base int) uint64 {
	return uint64(padded[base]) |
		uint64(padded[base+1])<<8 |
		uint64(padded[base+2])<<16 |
		uint64(padded[base+3])<<24 |
		uint64(padded[base+4])<<32 |
		uint64(padded[base+5])<<40
}

// writeChunk48 emits the low 48 bits of x as six little-endian bytes at
// result[base .. base+6].
func writeChunk48(result []byte, base int, x uint64) {
	result[base] = byte(x)
	result[base+1] = byte(x >> 8)
	result[base+2] = byte(x >> 16)
	result[base+3] = byte(x >> 24)
	result[base+4] = byte(x >> 32)
	result[base+5] = byte(x >> 40)
}

// ============================================================================
// PRF closures — per-chunk and batched, per hash width, with Cfg mirrors.
// ============================================================================
//
// The per-chunk closure delivers one mask triple per invocation. The batched
// closure struct delivers factor mask triples per invocation from a single
// underlying Hash call — 1 chunk at 128-bit, 2 at 256-bit, 4 at 512-bit,
// because each chunk consumes two 64-bit lanes for its 128-bit rank.
//
// The buffer layout matches the legacy per-chunk closures for caller-side
// scratch reuse symmetry:
//
//	buf[0]    = 0x03   (Triple lock domain tag)
//	buf[1:9]  = uint64-LE(globalChunkIdx | groupIdx)
//	buf[9:13] = reserved

// lockPRF48 is the per-chunk PRF closure used by the parallel split /
// interleave kernels.
type lockPRF48 func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64)

// lockBatchFactor48_* describe how many chunks a single batched Hash call
// masks at each native hash width. Each chunk consumes two 64-bit lanes,
// so factor = hashWidth / 128.
const (
	lockBatchFactor48_128 = 1
	lockBatchFactor48_256 = 2
	lockBatchFactor48_512 = 4
	lockBatchFactor48Max  = 4
)

// lockBatchPRF48 is the batched counterpart of [lockPRF48]. One call per
// group fills masks[0..factor-1] with the mask triples for that group's
// chunks; factor reports how many the underlying hash width yields.
type lockBatchPRF48 struct {
	factor int
	fill   func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64)
}

// fillLockMasksTriple48 fills masks[0..count-1] from count 128-bit ranks
// packed into prf as pairs (prf[2*j], prf[2*j+1]). count must be <=
// lockBatchFactor48Max.
//
// When the AVX-512F batch kernel is available it derives all 8 lanes in
// one constant-time pass; the 128-bit-rank divmod (Barrett-substitute
// via bits.Div64) is done here in Go, then idx0[]/idx1[] are handed to
// the asm entry. Only the first count triples are copied back into the
// caller's output — the remaining kernel lanes carry garbage that is
// never observed. Without the kernel it falls back to the per-lane
// scalar rankToMaskTriple48, leaving non-AVX-512F hosts unchanged.
func fillLockMasksTriple48(prf *[8]uint64, count int, masks *[lockBatchFactor48Max][3]uint64) {
	if interlock.HasAVX512RankMask {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < count; j++ {
			// Two-step 128-by-30 divmod: q, idx1 = divmod(rank, B); idx0 = q mod A.
			qHi, r1 := bits.Div64(0, prf[2*j+1], interlockB48)
			qLo, r := bits.Div64(r1, prf[2*j], interlockB48)
			_, hiMod := bits.Div64(0, qHi, interlockA48)
			_, m := bits.Div64(hiMod, qLo, interlockA48)
			idx0[j] = m
			idx1[j] = uint32(r)
		}
		var out [3][8]uint64
		interlock.RankToMaskTripleUnrank48(&idx0, &idx1, &out)
		for j := 0; j < count; j++ {
			masks[j][0] = out[0][j]
			masks[j][1] = out[1][j]
			masks[j][2] = out[2][j]
		}
		return
	}
	for j := 0; j < count; j++ {
		masks[j][0], masks[j][1], masks[j][2] = rankToMaskTriple48(prf[2*j], prf[2*j+1])
	}
}

// buildLockPRF48_128 constructs a per-chunk [lockPRF48] closure for the
// 128-bit Triple Ouroboros context. Captures the noiseSeed-derived
// 128-bit lockSeed and the Hash function; per-chunk invocations run one
// Hash call keyed by lockSeed with the chunk index as input, taking the
// full 128-bit output as the mask rank.
//
// When the noiseSeed has a dedicated lockSeed installed via
// [Seed128.AttachLockSeed], that attached seed supplies BOTH the
// per-chunk PRF keying material AND the Hash function — separating
// bit-permutation entropy from the noiseSeed-driven noise-injection
// channel without changing the public Encrypt / Decrypt signatures.
func buildLockPRF48_128(noiseSeed *Seed128, nonce []byte) lockPRF48 {
	src := noiseSeed
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		if !isBitSoupEnabled() && !isLockSoupEnabled() {
			panic(ErrLockSeedOverlayOff)
		}
		src = ls
	}
	lockLo, lockHi := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		lo, hi := h(buf, lockLo, lockHi)
		return rankToMaskTriple48(lo, hi)
	}
}

// buildLockPRF48_256 — 256-bit equivalent of [buildLockPRF48_128]. Uses
// native 256-bit keying material; the 128-bit mask rank is taken from
// (out[0], out[1]) of the Hash output.
func buildLockPRF48_256(noiseSeed *Seed256, nonce []byte) lockPRF48 {
	src := noiseSeed
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		if !isBitSoupEnabled() && !isLockSoupEnabled() {
			panic(ErrLockSeedOverlayOff)
		}
		src = ls
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockSeed)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// buildLockPRF48_512 — 512-bit equivalent of [buildLockPRF48_128]. Uses
// native 512-bit keying material; the 128-bit mask rank is taken from
// (out[0], out[1]) of the Hash output.
func buildLockPRF48_512(noiseSeed *Seed512, nonce []byte) lockPRF48 {
	src := noiseSeed
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		if !isBitSoupEnabled() && !isLockSoupEnabled() {
			panic(ErrLockSeedOverlayOff)
		}
		src = ls
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockSeed)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// buildLockPRF48_128Cfg — Cfg variant of [buildLockPRF48_128] that routes
// inter-lock derivation through [permSeedCfg128](cfg, noiseSeed) so an
// active dedicated lockSeed (cfg.LockSeedHandle) supplies BOTH the
// per-chunk PRF keying material AND the Hash function.
func buildLockPRF48_128Cfg(cfg *Config, noiseSeed *Seed128, nonce []byte) lockPRF48 {
	src := permSeedCfg128(cfg, noiseSeed)
	if noiseSeed.AttachedLockSeed() != nil &&
		!isBitSoupEnabledCfg(cfg) && !isLockSoupEnabledCfg(cfg) {
		panic(ErrLockSeedOverlayOff)
	}
	lockLo, lockHi := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		lo, hi := h(buf, lockLo, lockHi)
		return rankToMaskTriple48(lo, hi)
	}
}

// buildLockPRF48_256Cfg — Cfg variant of [buildLockPRF48_256].
func buildLockPRF48_256Cfg(cfg *Config, noiseSeed *Seed256, nonce []byte) lockPRF48 {
	src := permSeedCfg256(cfg, noiseSeed)
	if noiseSeed.AttachedLockSeed() != nil &&
		!isBitSoupEnabledCfg(cfg) && !isLockSoupEnabledCfg(cfg) {
		panic(ErrLockSeedOverlayOff)
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockSeed)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// buildLockPRF48_512Cfg — Cfg variant of [buildLockPRF48_512].
func buildLockPRF48_512Cfg(cfg *Config, noiseSeed *Seed512, nonce []byte) lockPRF48 {
	src := permSeedCfg512(cfg, noiseSeed)
	if noiseSeed.AttachedLockSeed() != nil &&
		!isBitSoupEnabledCfg(cfg) && !isLockSoupEnabledCfg(cfg) {
		panic(ErrLockSeedOverlayOff)
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockSeed)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// buildLockBatchPRF48_128 is the batched counterpart of [buildLockPRF48_128].
// One Hash call per group yields 1 mask triple from the (lo, hi) output pair
// (each 48-bit chunk consumes two 64-bit lanes for its 128-bit rank, so a
// 128-bit hash width supplies material for exactly one chunk per call).
func buildLockBatchPRF48_128(noiseSeed *Seed128, nonce []byte) lockBatchPRF48 {
	src := noiseSeed
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		if !isBitSoupEnabled() && !isLockSoupEnabled() {
			panic(ErrLockSeedOverlayOff)
		}
		src = ls
	}
	lockLo, lockHi := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return lockBatchPRF48{
		factor: lockBatchFactor48_128,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			lo, hi := h(buf, lockLo, lockHi)
			var prf [8]uint64
			prf[0], prf[1] = lo, hi
			fillLockMasksTriple48(&prf, lockBatchFactor48_128, masks)
		},
	}
}

// buildLockBatchPRF48_256 is the batched counterpart of [buildLockPRF48_256].
// One Hash call per group yields 2 mask triples from out[0..3].
func buildLockBatchPRF48_256(noiseSeed *Seed256, nonce []byte) lockBatchPRF48 {
	src := noiseSeed
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		if !isBitSoupEnabled() && !isLockSoupEnabled() {
			panic(ErrLockSeedOverlayOff)
		}
		src = ls
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return lockBatchPRF48{
		factor: lockBatchFactor48_256,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockSeed)
			var prf [8]uint64
			copy(prf[:4], out[:])
			fillLockMasksTriple48(&prf, lockBatchFactor48_256, masks)
		},
	}
}

// buildLockBatchPRF48_512 is the batched counterpart of [buildLockPRF48_512].
// One Hash call per group yields 4 mask triples from out[0..7].
func buildLockBatchPRF48_512(noiseSeed *Seed512, nonce []byte) lockBatchPRF48 {
	src := noiseSeed
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		if !isBitSoupEnabled() && !isLockSoupEnabled() {
			panic(ErrLockSeedOverlayOff)
		}
		src = ls
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return lockBatchPRF48{
		factor: lockBatchFactor48_512,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockSeed)
			fillLockMasksTriple48(&out, lockBatchFactor48_512, masks)
		},
	}
}

// buildLockBatchPRF48_128Cfg — Cfg variant of [buildLockBatchPRF48_128].
func buildLockBatchPRF48_128Cfg(cfg *Config, noiseSeed *Seed128, nonce []byte) lockBatchPRF48 {
	src := permSeedCfg128(cfg, noiseSeed)
	if noiseSeed.AttachedLockSeed() != nil &&
		!isBitSoupEnabledCfg(cfg) && !isLockSoupEnabledCfg(cfg) {
		panic(ErrLockSeedOverlayOff)
	}
	lockLo, lockHi := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return lockBatchPRF48{
		factor: lockBatchFactor48_128,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			lo, hi := h(buf, lockLo, lockHi)
			var prf [8]uint64
			prf[0], prf[1] = lo, hi
			fillLockMasksTriple48(&prf, lockBatchFactor48_128, masks)
		},
	}
}

// buildLockBatchPRF48_256Cfg — Cfg variant of [buildLockBatchPRF48_256].
func buildLockBatchPRF48_256Cfg(cfg *Config, noiseSeed *Seed256, nonce []byte) lockBatchPRF48 {
	src := permSeedCfg256(cfg, noiseSeed)
	if noiseSeed.AttachedLockSeed() != nil &&
		!isBitSoupEnabledCfg(cfg) && !isLockSoupEnabledCfg(cfg) {
		panic(ErrLockSeedOverlayOff)
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return lockBatchPRF48{
		factor: lockBatchFactor48_256,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockSeed)
			var prf [8]uint64
			copy(prf[:4], out[:])
			fillLockMasksTriple48(&prf, lockBatchFactor48_256, masks)
		},
	}
}

// buildLockBatchPRF48_512Cfg — Cfg variant of [buildLockBatchPRF48_512].
func buildLockBatchPRF48_512Cfg(cfg *Config, noiseSeed *Seed512, nonce []byte) lockBatchPRF48 {
	src := permSeedCfg512(cfg, noiseSeed)
	if noiseSeed.AttachedLockSeed() != nil &&
		!isBitSoupEnabledCfg(cfg) && !isLockSoupEnabledCfg(cfg) {
		panic(ErrLockSeedOverlayOff)
	}
	lockSeed := src.deriveInterLockSeed(nonce)
	h := src.Hash
	return lockBatchPRF48{
		factor: lockBatchFactor48_512,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockSeed)
			fillLockMasksTriple48(&out, lockBatchFactor48_512, masks)
		},
	}
}

// ============================================================================
// Parallel split / interleave — 48-bit chunk kernels
// ============================================================================
//
// The caller prepends a 4-byte big-endian length prefix to the plaintext
// before invoking splitTriple48Locked{,Batch} (see [prependTripleLen] in
// the byte-level bit-soup path). The framed buffer is then padded up to
// a multiple of 6 bytes (zero-fill); every 48-bit chunk is processed
// independently under masks derived from the per-chunk or batched PRF.
// Padding bytes appear as garbage on the decoder side and are stripped
// by the length-prefix slice in the caller's dispatcher.
//
// Chunk count M = LPad / 6; each per-lane output buffer holds 2*M bytes.
// Workers take disjoint chunk-index ranges — no locks are needed because
// output indices per lane are also disjoint. Per-chunk workers use
// runtime.NumCPU() goroutines capped by M; batched workers use the same
// cap on the group count M / factor.

// splitTriple48Locked splits framed into three lane buffers of 2*M bytes
// each, applying the PRF-derived mask triple to every 48-bit chunk. The
// input is padded up to a multiple of 6 bytes; the caller's dispatcher
// strips the framing length prefix on the way back out.
func splitTriple48Locked(data []byte, prf lockPRF48) (p0, p1, p2 []byte) {
	L := len(data)
	LPad := ((L + 5) / 6) * 6
	var padded []byte
	if LPad == L {
		padded = data
	} else {
		padded = make([]byte, LPad)
		copy(padded, data)
	}
	M := LPad / 6

	p0 = make([]byte, 2*M)
	p1 = make([]byte, 2*M)
	p2 = make([]byte, 2*M)

	if M == 0 {
		return
	}

	G := runtime.NumCPU()
	if G > M {
		G = M
	}
	chunksPerWorker := (M + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		start := w * chunksPerWorker
		end := start + chunksPerWorker
		if end > M {
			end = M
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			var buf [13]byte
			for k := s; k < e; k++ {
				m0, m1, m2 := prf(buf[:], uint64(k))
				x := readChunk48(padded, 6*k)
				l0, l1, l2 := chunk48lock(x, m0, m1, m2)
				binary.LittleEndian.PutUint16(p0[2*k:], l0)
				binary.LittleEndian.PutUint16(p1[2*k:], l1)
				binary.LittleEndian.PutUint16(p2[2*k:], l2)
			}
		}(start, end)
	}
	wg.Wait()
	return
}

// interleaveTriple48Locked is the inverse of [splitTriple48Locked]. The
// three lane buffers must be equal length (2*M bytes each). The result
// includes any padding bytes the encoder added; the caller's dispatcher
// strips them via the framing length prefix.
func interleaveTriple48Locked(p0, p1, p2 []byte, prf lockPRF48) []byte {
	M := len(p0) / 2
	result := make([]byte, M*6)

	if M == 0 {
		return result
	}

	G := runtime.NumCPU()
	if G > M {
		G = M
	}
	chunksPerWorker := (M + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		start := w * chunksPerWorker
		end := start + chunksPerWorker
		if end > M {
			end = M
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			var buf [13]byte
			for k := s; k < e; k++ {
				m0, m1, m2 := prf(buf[:], uint64(k))
				l0 := binary.LittleEndian.Uint16(p0[2*k:])
				l1 := binary.LittleEndian.Uint16(p1[2*k:])
				l2 := binary.LittleEndian.Uint16(p2[2*k:])
				x := unchunk48lock(l0, l1, l2, m0, m1, m2)
				writeChunk48(result, 6*k, x)
			}
		}(start, end)
	}
	wg.Wait()
	return result
}

// splitTriple48LockedBatch is the batched counterpart of [splitTriple48Locked].
// Chunks are processed in groups of bp.factor; each group costs one bp.fill
// call producing factor lane mask triples applied to the factor chunks of the
// group. The parallel work split is at GROUP granularity (workers take
// disjoint group ranges, writing disjoint output chunk indices). The final
// group is short when M is not a multiple of factor; only the needed low
// lanes are consumed.
func splitTriple48LockedBatch(data []byte, bp lockBatchPRF48) (p0, p1, p2 []byte) {
	L := len(data)
	LPad := ((L + 5) / 6) * 6
	var padded []byte
	if LPad == L {
		padded = data
	} else {
		padded = make([]byte, LPad)
		copy(padded, data)
	}
	M := LPad / 6

	p0 = make([]byte, 2*M)
	p1 = make([]byte, 2*M)
	p2 = make([]byte, 2*M)

	if M == 0 {
		return
	}

	factor := bp.factor
	numGroups := (M + factor - 1) / factor

	G := runtime.NumCPU()
	if G > numGroups {
		G = numGroups
	}
	groupsPerWorker := (numGroups + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		gStart := w * groupsPerWorker
		gEnd := gStart + groupsPerWorker
		if gEnd > numGroups {
			gEnd = numGroups
		}
		if gStart >= gEnd {
			continue
		}
		wg.Add(1)
		go func(gs, ge int) {
			defer wg.Done()
			var buf [13]byte
			var masks [lockBatchFactor48Max][3]uint64
			for g := gs; g < ge; g++ {
				bp.fill(buf[:], uint64(g), &masks)
				base := g * factor
				for j := 0; j < factor; j++ {
					k := base + j
					if k >= M {
						break
					}
					m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
					x := readChunk48(padded, 6*k)
					l0, l1, l2 := chunk48lock(x, m0, m1, m2)
					binary.LittleEndian.PutUint16(p0[2*k:], l0)
					binary.LittleEndian.PutUint16(p1[2*k:], l1)
					binary.LittleEndian.PutUint16(p2[2*k:], l2)
				}
			}
		}(gStart, gEnd)
	}
	wg.Wait()
	return
}

// interleaveTriple48LockedBatch is the inverse of [splitTriple48LockedBatch],
// mirroring its group-granular work split and short-final-group handling.
func interleaveTriple48LockedBatch(p0, p1, p2 []byte, bp lockBatchPRF48) []byte {
	M := len(p0) / 2
	result := make([]byte, M*6)

	if M == 0 {
		return result
	}

	factor := bp.factor
	numGroups := (M + factor - 1) / factor

	G := runtime.NumCPU()
	if G > numGroups {
		G = numGroups
	}
	groupsPerWorker := (numGroups + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		gStart := w * groupsPerWorker
		gEnd := gStart + groupsPerWorker
		if gEnd > numGroups {
			gEnd = numGroups
		}
		if gStart >= gEnd {
			continue
		}
		wg.Add(1)
		go func(gs, ge int) {
			defer wg.Done()
			var buf [13]byte
			var masks [lockBatchFactor48Max][3]uint64
			for g := gs; g < ge; g++ {
				bp.fill(buf[:], uint64(g), &masks)
				base := g * factor
				for j := 0; j < factor; j++ {
					k := base + j
					if k >= M {
						break
					}
					m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
					l0 := binary.LittleEndian.Uint16(p0[2*k:])
					l1 := binary.LittleEndian.Uint16(p1[2*k:])
					l2 := binary.LittleEndian.Uint16(p2[2*k:])
					x := unchunk48lock(l0, l1, l2, m0, m1, m2)
					writeChunk48(result, 6*k, x)
				}
			}
		}(gStart, gEnd)
	}
	wg.Wait()
	return result
}
