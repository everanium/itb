package itb

import "math/bits"

// The two-step reduction of a 128-bit interlock rank (lane0 = low 64
// bits, lane1 = high 64 bits) into the combinadic index pair consumed
// by the mask-triple unrank:
//
//	(q, idx1) = divmod(rank, B)   B = C(32, 16), a 30-bit divisor
//	idx0      = q mod A           A = C(48, 16), a 42-bit divisor
//
// Two formulations are kept, both bit-exact and pinned against each
// other by the package tests: [splitRank48Div] runs the limb-by-limb
// [math/bits.Div64] schoolbook and is the arm taken where Div64 is a
// hardware 128-by-64 divide (amd64: DIVQ); [splitRank48Recip] replaces
// every division by a constant-divisor reciprocal multiply and is the
// arm taken where Div64 is a software routine (arm64 and every other
// architecture). The per-architecture [splitRank48] selects between
// them at build time (interlock48_rank_split_amd64.go /
// interlock48_rank_split_other.go).

// splitRank48Recip is the reciprocal-multiply formulation.
//
// Constant-time: every step is a fixed sequence of multiplies, shifts,
// subtractions and arithmetic selects — no data-dependent branch and
// no data-dependent memory access.
func splitRank48Recip(lane0, lane1 uint64) (idx0 uint64, idx1 uint32) {
	// Step 1: (lane1:lane0) / B, limb by limb. The high limb reduces on
	// its own; the low limb is fed in two 32-bit halves so every partial
	// dividend stays below 2^62 (remainder < B < 2^30, shifted by 32).
	qHi, r1 := divB(lane1)
	qa, ra := divB(r1<<32 | lane0>>32)
	qb, r := divB(ra<<32 | lane0&0xFFFF_FFFF)
	qLo := qa<<32 | qb
	idx1 = uint32(r)

	// Step 2: (qHi:qLo) mod A. qHi < 2^35 (lane1 < 2^64, B > 2^29), so
	// the high limb is already below A; the low limb is folded in three
	// digits of 22 + 21 + 21 bits so every partial value stays below
	// 2^63 (residue < A < 2^42, shifted by at most 22).
	u := modA(qHi<<22 | qLo>>42)
	u = modA(u<<21 | (qLo>>21)&(1<<21-1))
	idx0 = modA(u<<21 | qLo&(1<<21-1))
	return
}

// Reciprocal constants for the two constant divisors. For a divisor d
// with 2^s < d, m = floor(2^(64+s) / d) fits in 64 bits and the
// estimate q' = mulhi(n, m) >> s satisfies q - 1 <= q' <= q for every
// 64-bit n (the truncation error n * (2^(64+s)/d - m) / 2^(64+s) is
// below 2^-s <= 1), so one arithmetic correction step makes the
// quotient exact.
const (
	interlockB48Shift = 29 // 2^29 < B < 2^30
	interlockA48Shift = 41 // 2^41 < A < 2^42
)

var (
	interlockB48Recip uint64 // floor(2^93 / B)
	interlockA48Recip uint64 // floor(2^105 / A)
)

func init() {
	interlockB48Recip, _ = bits.Div64(1<<interlockB48Shift, 0, interlockB48)
	interlockA48Recip, _ = bits.Div64(1<<interlockA48Shift, 0, interlockA48)
}

// divB returns (n / B, n mod B) for any 64-bit n.
func divB(n uint64) (q, r uint64) {
	hi, _ := bits.Mul64(n, interlockB48Recip)
	q = hi >> interlockB48Shift
	r = n - q*interlockB48
	// r is in [0, 2B): correct once when r >= B, without a branch.
	c := ((r - interlockB48) >> 63) ^ 1
	q += c
	r -= interlockB48 & -c
	return
}

// modA returns n mod A for any 64-bit n.
func modA(n uint64) uint64 {
	hi, _ := bits.Mul64(n, interlockA48Recip)
	r := n - (hi>>interlockA48Shift)*interlockA48
	c := ((r - interlockA48) >> 63) ^ 1
	return r - interlockA48&-c
}

// splitRank48Div is the limb-by-limb [math/bits.Div64] formulation of
// the same reduction: the production arm where Div64 is a hardware
// divide, and the reference the reciprocal arm is pinned against.
func splitRank48Div(lane0, lane1 uint64) (idx0 uint64, idx1 uint32) {
	qHi, r1 := bits.Div64(0, lane1, interlockB48)
	qLo, r := bits.Div64(r1, lane0, interlockB48)
	_, hiMod := bits.Div64(0, qHi, interlockA48)
	_, idx0 = bits.Div64(hiMod, qLo, interlockA48)
	return idx0, uint32(r)
}
