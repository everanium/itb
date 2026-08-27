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

// prependTripleLen returns [uint32_BE(len(data)):4] || data. The 4-byte
// big-endian length prefix is carried inside the plaintext across the
// chunk-level split; after decrypt-side interleave, the first 4 bytes
// of the recovered stream give the exact plaintext length, enabling
// deterministic slicing without a separate header widening.
func prependTripleLen(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out
}

// ============================================================================
// PRF closures — batched, per hash width.
// ============================================================================
//
// The batched closure struct delivers factor mask triples per invocation from
// a single underlying Hash call — 1 chunk at 128-bit, 2 at 256-bit, 4 at
// 512-bit, because each chunk consumes two 64-bit lanes for its 128-bit rank.
//
// The buffer layout is:
//
//	buf[0]    = 0x03   (Triple lock domain tag)
//	buf[1:9]  = uint64-LE(groupIdx)
//	buf[9:13] = reserved

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
//
// fillRanks is the rank-producing variant of fill consumed by the
// superblock worker loops: it performs the same Hash call over the same
// buf layout but writes the raw 128-bit rank pairs into prf[0:2*factor]
// and defers the mask derivation to the caller, which accumulates the
// ranks of [superChunks48] chunks and derives all their mask triples in
// one [fillLockMasksTriple48Super] pass. fill and fillRanks agree on
// every (buf, groupIdx) input by construction — both closures wrap the
// identical Hash invocation.
type lockBatchPRF48 struct {
	factor    int
	fill      func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64)
	fillRanks func(buf []byte, groupIdx uint64, prf []uint64)

	// fillRanksX4 is the optional 4-group batched counterpart of
	// fillRanks, present when the lockSeed exposes a BatchHash arm. One
	// call performs the PRF fill for 4 consecutive groups
	// (groupIdx .. groupIdx+3) through a single 4-lane batched Hash
	// invocation: every lane carries the identical lockKey with a
	// distinct per-lane groupIdx buf, so the call yields 4 distinct
	// rank sources exactly matching 4 sequential fillRanks calls. The
	// call writes 4 * 2 * factor rank words into prf[0 : 8*factor] in
	// chunk order. s provides per-worker scratch for the 4 lane bufs so
	// the batched call performs no per-invocation allocation. fillRanks
	// and fillRanksX4 agree on every group index by the BatchHash
	// parity invariant (BatchHash must agree with Hash on every input;
	// see seed256_batch.go).
	fillRanksX4 func(s *lockFillScratch48, groupIdx uint64, prf []uint64)
}

// lockFillScratch48 is the per-worker scratch consumed by
// lockBatchPRF48.fillRanksX4 — four domain-tagged 13-byte fill bufs
// plus the slice-header array handed to the seed's BatchHash arm.
// Declared once per worker goroutine; the BatchHash indirection makes
// the buffers escape, so worker-scoped reuse keeps the batched fill
// allocation-free per invocation. The bufs' reserved bytes [9:13] stay
// zero for the struct's lifetime, matching the scalar fill buf layout.
type lockFillScratch48 struct {
	bufs [4][13]byte
	data [4][]byte
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
// never observed. On AVX2-only silicon the AVX2 4-lane batch kernel
// serves the same 8-lane contract (two YMM halves per invocation);
// without either kernel the per-lane scalar rankToMaskTriple48 runs.
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
	if interlock.HasAVX2RankMask {
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
		interlock.RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
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

// superChunks48 is the number of chunks whose mask triples are derived
// per batch-kernel invocation by the superblock worker loops — equal to
// the AVX-512 kernel's 8 qword lanes. A superblock spans
// superChunks48 / factor consecutive PRF groups (8 groups at 128-bit
// hash width, 4 at 256, 2 at 512), so every kernel invocation runs with
// all 8 lanes carrying payload regardless of hash width.
const superChunks48 = 8

// fillLockMasksTriple48Super fills masks[0..count-1] from count 128-bit
// ranks packed into prf as pairs (prf[2*j], prf[2*j+1]). count must be
// <= superChunks48. The mask derivation is identical to
// [fillLockMasksTriple48] — same two-step divmod, same unrank — widened
// to the kernel's full 8-lane capacity so one AVX-512 invocation serves
// a whole superblock of chunks. A short superblock (count < 8) leaves
// the upper kernel lanes on zero ranks; their outputs are never read.
// On AVX2-only silicon the AVX2 4-lane batch kernel serves the same
// 8-lane contract; without either kernel the per-rank scalar
// rankToMaskTriple48 runs.
func fillLockMasksTriple48Super(prf *[2 * superChunks48]uint64, count int, masks *[superChunks48][3]uint64) {
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
	if interlock.HasAVX2RankMask {
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
		interlock.RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
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

// buildLockBatchPRF48_128 is the batched 128-bit-width builder.
// One Hash call per group yields 1 mask triple from the (lo, hi) output pair
// (each 48-bit chunk consumes two 64-bit lanes for its 128-bit rank, so a
// 128-bit hash width supplies material for exactly one chunk per call).
//
// The closure captures the lockSeed's ChainHash-derived keying material and
// the lockSeed's Hash function — the overlay's PRF keying is fully isolated
// from the noiseSeed slot's material.
func buildLockBatchPRF48_128(lockSeed *Seed128, nonce []byte) lockBatchPRF48 {
	lockLo, lockHi := lockSeed.deriveInterLockSeed(nonce)
	h := lockSeed.Hash
	bp := lockBatchPRF48{
		factor: lockBatchFactor48_128,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			lo, hi := h(buf, lockLo, lockHi)
			var prf [8]uint64
			prf[0], prf[1] = lo, hi
			fillLockMasksTriple48(&prf, lockBatchFactor48_128, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			prf[0], prf[1] = h(buf, lockLo, lockHi)
		},
	}
	if bh := lockSeed.BatchHash; bh != nil {
		bp.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := bh(&s.data, [4][2]uint64{
				{lockLo, lockHi}, {lockLo, lockHi},
				{lockLo, lockHi}, {lockLo, lockHi},
			})
			for i := 0; i < 4; i++ {
				prf[2*i] = out[i][0]
				prf[2*i+1] = out[i][1]
			}
		}
	}
	return bp
}

// buildLockBatchPRF48_256 is the 256-bit counterpart of [buildLockBatchPRF48_128].
// One Hash call per group yields 2 mask triples from out[0..3].
func buildLockBatchPRF48_256(lockSeed *Seed256, nonce []byte) lockBatchPRF48 {
	lockKey := lockSeed.deriveInterLockSeed(nonce)
	h := lockSeed.Hash
	bp := lockBatchPRF48{
		factor: lockBatchFactor48_256,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockKey)
			var prf [8]uint64
			copy(prf[:4], out[:])
			fillLockMasksTriple48(&prf, lockBatchFactor48_256, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockKey)
			copy(prf[:4], out[:])
		},
	}
	if bh := lockSeed.BatchHash; bh != nil {
		bp.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := bh(&s.data, [4][4]uint64{lockKey, lockKey, lockKey, lockKey})
			for i := 0; i < 4; i++ {
				copy(prf[4*i:4*i+4], out[i][:])
			}
		}
	}
	return bp
}

// buildLockBatchPRF48_512 is the 512-bit counterpart of [buildLockBatchPRF48_128].
// One Hash call per group yields 4 mask triples from out[0..7].
func buildLockBatchPRF48_512(lockSeed *Seed512, nonce []byte) lockBatchPRF48 {
	lockKey := lockSeed.deriveInterLockSeed(nonce)
	h := lockSeed.Hash
	bp := lockBatchPRF48{
		factor: lockBatchFactor48_512,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockKey)
			fillLockMasksTriple48(&out, lockBatchFactor48_512, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := h(buf, lockKey)
			copy(prf[:8], out[:])
		},
	}
	if bh := lockSeed.BatchHash; bh != nil {
		bp.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := bh(&s.data, [4][8]uint64{lockKey, lockKey, lockKey, lockKey})
			for i := 0; i < 4; i++ {
				copy(prf[8*i:8*i+8], out[i][:])
			}
		}
	}
	return bp
}

// buildLockBatchPRF48_128Cfg — Cfg variant of [buildLockBatchPRF48_128]. The cfg
// pointer is accepted only for symmetry with the surrounding Cfg-suffixed
// helpers; no cfg field feeds into the derivation any more.
func buildLockBatchPRF48_128Cfg(_ *Config, lockSeed *Seed128, nonce []byte) lockBatchPRF48 {
	return buildLockBatchPRF48_128(lockSeed, nonce)
}

// buildLockBatchPRF48_256Cfg — Cfg variant of [buildLockBatchPRF48_256].
func buildLockBatchPRF48_256Cfg(_ *Config, lockSeed *Seed256, nonce []byte) lockBatchPRF48 {
	return buildLockBatchPRF48_256(lockSeed, nonce)
}

// buildLockBatchPRF48_512Cfg — Cfg variant of [buildLockBatchPRF48_512].
func buildLockBatchPRF48_512Cfg(_ *Config, lockSeed *Seed512, nonce []byte) lockBatchPRF48 {
	return buildLockBatchPRF48_512(lockSeed, nonce)
}

// ============================================================================
// Parallel split / interleave — 48-bit chunk kernels
// ============================================================================
//
// The caller prepends a 4-byte big-endian length prefix to the plaintext
// before invoking splitTriple48Locked{,Batch} (see [prependTripleLen]).
// The framed buffer is then padded up to a multiple of 6 bytes
// (zero-fill); every 48-bit chunk is processed
// independently under masks derived from the per-chunk or batched PRF.
// Padding bytes appear as garbage on the decoder side and are stripped
// by the length-prefix slice in the caller's dispatcher.
//
// Chunk count M = LPad / 6; each per-lane output buffer holds 2*M bytes.
// Workers take disjoint chunk-index ranges — no locks are needed because
// output indices per lane are also disjoint. Per-chunk workers use
// runtime.NumCPU() goroutines capped by M; batched workers use the same
// cap on the group count M / factor.

// splitTriple48LockedBatch is the parallel batched 48-bit encode kernel.
// Chunks are processed in groups of bp.factor; each group costs one
// bp.fillRanks call producing factor 128-bit rank pairs for the factor
// chunks of the group. Workers accumulate the ranks of up to
// [superChunks48] consecutive chunks (superChunks48 / factor groups)
// and derive all their mask triples in a single
// [fillLockMasksTriple48Super] pass, so the AVX-512 batch kernel runs
// with every lane carrying payload. The parallel work split is at GROUP
// granularity (workers take disjoint group ranges, writing disjoint
// output chunk indices); a worker range whose length is not a multiple
// of the superblock span simply ends on a short superblock. The final
// group is short when M is not a multiple of factor; only the needed
// low chunks are consumed.
//
// Mask derivation is a pure function of each chunk's rank pair, so the
// superblock accumulation changes only the point at which the unrank
// executes — the produced lane bytes are bit-identical to a per-group
// derivation via bp.fill (asserted by test against the bp.fill
// reference and by golden lane digests).
//
// When bp.fillRanksX4 is present, full blocks of max(groupsPerSuper, 4)
// groups route their PRF fills through the 4-lane batched arm — one
// batched Hash call per 4 consecutive groups instead of 4 sequential
// fillRanks calls. The batched arm agrees with fillRanks on every group
// index (BatchHash parity invariant), so the produced lane bytes stay
// bit-identical; worker tails shorter than a block fall back to the
// scalar fillRanks path.
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
			var scratch lockFillScratch48
			var prf [8 * lockBatchFactor48Max]uint64
			var masks [superChunks48][3]uint64
			groupsPerSuper := superChunks48 / factor
			// x4 block sizing: fillRanksX4 covers 4 consecutive groups
			// per call; a block of max(groupsPerSuper, 4) groups keeps
			// the chunk count a multiple of superChunks48 so every
			// unrank pass runs with all lanes carrying payload.
			x4Groups := 0
			if bp.fillRanksX4 != nil {
				x4Groups = groupsPerSuper
				if x4Groups < 4 {
					x4Groups = 4
				}
			}
			for g := gs; g < ge; {
				if x4Groups != 0 && ge-g >= x4Groups {
					base := g * factor
					for c := 0; c < x4Groups; c += 4 {
						bp.fillRanksX4(&scratch, uint64(g+c), prf[2*c*factor:])
					}
					nChunks := x4Groups * factor
					for off := 0; off < nChunks; off += superChunks48 {
						p := (*[2 * superChunks48]uint64)(prf[2*off : 2*off+2*superChunks48])
						fillLockMasksTriple48Super(p, superChunks48, &masks)
						for j := 0; j < superChunks48; j++ {
							k := base + off + j
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
					g += x4Groups
					continue
				}
				gFlush := g + groupsPerSuper
				if gFlush > ge {
					gFlush = ge
				}
				base := g * factor
				n := 0
				for ; g < gFlush; g++ {
					bp.fillRanks(buf[:], uint64(g), prf[2*n:])
					n += factor
				}
				fillLockMasksTriple48Super((*[2 * superChunks48]uint64)(prf[0:2*superChunks48]), n, &masks)
				for j := 0; j < n; j++ {
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
			var scratch lockFillScratch48
			var prf [8 * lockBatchFactor48Max]uint64
			var masks [superChunks48][3]uint64
			groupsPerSuper := superChunks48 / factor
			// x4 block sizing: mirrors splitTriple48LockedBatch.
			x4Groups := 0
			if bp.fillRanksX4 != nil {
				x4Groups = groupsPerSuper
				if x4Groups < 4 {
					x4Groups = 4
				}
			}
			for g := gs; g < ge; {
				if x4Groups != 0 && ge-g >= x4Groups {
					base := g * factor
					for c := 0; c < x4Groups; c += 4 {
						bp.fillRanksX4(&scratch, uint64(g+c), prf[2*c*factor:])
					}
					nChunks := x4Groups * factor
					for off := 0; off < nChunks; off += superChunks48 {
						p := (*[2 * superChunks48]uint64)(prf[2*off : 2*off+2*superChunks48])
						fillLockMasksTriple48Super(p, superChunks48, &masks)
						for j := 0; j < superChunks48; j++ {
							k := base + off + j
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
					g += x4Groups
					continue
				}
				gFlush := g + groupsPerSuper
				if gFlush > ge {
					gFlush = ge
				}
				base := g * factor
				n := 0
				for ; g < gFlush; g++ {
					bp.fillRanks(buf[:], uint64(g), prf[2*n:])
					n += factor
				}
				fillLockMasksTriple48Super((*[2 * superChunks48]uint64)(prf[0:2*superChunks48]), n, &masks)
				for j := 0; j < n; j++ {
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

// ============================================================================
// Top-level dispatcher — Cfg-aware routing through the 48-bit interlock overlay.
// ============================================================================
//
// splitForTriple48LockedCfg drives every Triple plaintext through the
// 48-bit keyed overlay path. The caller-supplied batched
// (lockBatchPRF48) closure carries the shared lockSeed and Hash
// function derived once at Encrypt* entry. Only the batched dispatch
// is shipped in production — the per-chunk lockPRF48 counterpart
// survives in the test suite as the parity oracle against which the
// batched kernel is validated.
//
// Plausible-decryption invariant: never errors. Wrong-seed brute-force
// feeds garbage p0/p1/p2 into the inverse; interleaveForTriple48LockedCfg
// returns garbage bytes clamped to the recovered payload extent, no
// error oracle.

// splitForTriple48LockedCfg dispatches plaintext splitting through the
// 48-bit interlock overlay path. The caller-supplied bp closure
// carries the shared lockSeed and Hash function derived once at
// Encrypt* entry. The 4-byte big-endian length prefix is prepended
// inside this function so recoverers can slice back exactly to the
// original payload extent.
func splitForTriple48LockedCfg(_ *Config, data []byte, bp lockBatchPRF48) (p0, p1, p2 []byte) {
	return splitTriple48LockedBatch(prependTripleLen(data), bp)
}

// interleaveForTriple48LockedCfg is the inverse of
// [splitForTriple48LockedCfg]. The raw padded framed bytes returned by
// the underlying interleave are stripped down to the original payload
// via the 4-byte length prefix that splitForTriple48LockedCfg
// prepended on the corresponding encode.
//
// Plausible-decryption invariant: never errors. Wrong-seed brute-force
// or mismatched-mode decrypt feeds garbage into the inverse; this
// function returns garbage bytes clamped to the recovered payload
// extent instead of distinguishing wrong-seed attempts from valid ones
// via an error oracle.
func interleaveForTriple48LockedCfg(_ *Config, p0, p1, p2 []byte, bp lockBatchPRF48) []byte {
	// Wrong-seed decrypt paths pass unequal-length lanes (each COBS-
	// decoded stream truncates at whatever spurious 0x00 the garbage
	// bytes contained). Pad every lane to the longest even length so
	// the underlying interleave never indexes past a lane end — the
	// plausible-decryption invariant is preserved (garbage bytes, no
	// panic). Correct-seed decrypt has bit-exact matching lengths and
	// the padding is a no-op.
	p0, p1, p2 = padLanesToEqualEven(p0, p1, p2)
	framed := interleaveTriple48LockedBatch(p0, p1, p2, bp)
	if len(framed) < 4 {
		return framed
	}
	length := binary.BigEndian.Uint32(framed[:4])
	end := uint64(length) + 4
	if end > uint64(len(framed)) {
		end = uint64(len(framed))
	}
	return framed[4:int(end)]
}

// padLanesToEqualEven returns copies of p0/p1/p2 padded with trailing
// zero bytes to the largest even length across the three. Called from
// [interleaveForTriple48LockedCfg] to keep the batched interleave
// safe under wrong-seed inputs whose COBS-decoded lane lengths would
// otherwise disagree.
func padLanesToEqualEven(p0, p1, p2 []byte) ([]byte, []byte, []byte) {
	target := len(p0)
	if len(p1) > target {
		target = len(p1)
	}
	if len(p2) > target {
		target = len(p2)
	}
	if target%2 != 0 {
		target++
	}
	pad := func(p []byte) []byte {
		if len(p) == target {
			return p
		}
		out := make([]byte, target)
		copy(out, p)
		return out
	}
	return pad(p0), pad(p1), pad(p2)
}
