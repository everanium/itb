package itb

import (
	"math/bits"
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
// The pure-Go fallback path uses three [softPEXT48] calls. The BMI2
// hardware path lives under [internal/interlock] and is wired at
// commit time by the dispatcher; this file supplies only the reference
// implementation.
//
// Caller-side packing convention: x = uint64(b0) | uint64(b1)<<8 | ... |
// uint64(b5)<<40, so the low 48 bits carry the six chunk bytes in
// little-endian order. The three lane outputs each fit in a uint16
// (popcount(m_i) == 16 by construction).
func chunk48lock(x, m0, m1, m2 uint64) (l0, l1, l2 uint16) {
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
// The three PDEP-expansions land in disjoint bit positions
// (m0|m1|m2 covers all 48 bits with no overlap), so OR-ing them
// reconstructs x. The pure-Go fallback path uses three [softPDEP48]
// calls; the BMI2 hardware path lives under [internal/interlock].
func unchunk48lock(l0, l1, l2 uint16, m0, m1, m2 uint64) uint64 {
	return softPDEP48(l0, m0) | softPDEP48(l1, m1) | softPDEP48(l2, m2)
}
