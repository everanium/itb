package itb

import (
	"math/bits"
	"runtime"
)

// Compile-time divisor and Barrett-like reciprocal constants for the
// 168-bit Interlock two-step rank reduction:
//
//	(Q, idx1) = divmod(R_512, B168)   B168 = C(112, 56), a 109-bit divisor (2 limbs)
//	idx0      = Q mod A168            A168 = C(168, 56), a 151-bit divisor (3 limbs)
const (
	interlockA168_0 uint64 = 0xb93f03fb9f9a2ad8
	interlockA168_1 uint64 = 0x053d5b033cbb2e27
	interlockA168_2 uint64 = 0x000000000050afaf

	interlockB168_0 uint64 = 0x5bc2bbe1b5e02c78
	interlockB168_1 uint64 = 0x00001341f080963d

	// muB168 = floor(2^236 / B168) (128 bits, 2 limbs LE)
	interlockMuB168_0 uint64 = 0x4508f9134af46c6b
	interlockMuB168_1 uint64 = 0xd4b20d19ce585c96

	// muA168 = floor(2^342 / A168) (192 bits, 3 limbs LE)
	interlockMuA168_0 uint64 = 0xe2ea7578684213e8
	interlockMuA168_1 uint64 = 0x660063d3f1f72561
	interlockMuA168_2 uint64 = 0xcb0ee004eb554b2b
)

// divmodStepB168 performs a single 64-bit limb reduction step for divisor B168.
// Given running remainder (r0, r1) < B168 (2 limbs LE) and next limb w, it forms
// the 173-bit dividend X = (r << 64) | w and returns q = floor(X / B168) (< 2^64)
// and (remOut0, remOut1) = X mod B168 (< B168) using only 64x64->128 multiplies,
// shifts, and branchless subtraction. Scalar arguments and results stay in GPRs
// under Go ABIInternal.
func divmodStepB168(r0, r1, w uint64) (q, remOut0, remOut1 uint64) {
	x0, x1, x2 := w, r0, r1

	hi01, lo01 := bits.Mul64(x0, interlockMuB168_1)
	hi10, lo10 := bits.Mul64(x1, interlockMuB168_0)
	hi11, lo11 := bits.Mul64(x1, interlockMuB168_1)
	hi20, lo20 := bits.Mul64(x2, interlockMuB168_0)
	hi21, lo21 := bits.Mul64(x2, interlockMuB168_1)

	_, c0 := bits.Add64(lo01, lo10, 0)

	s1a, c1a := bits.Add64(hi01, hi10, c0)
	s1b, c1b := bits.Add64(lo11, lo20, 0)
	_, c1c := bits.Add64(s1a, s1b, 0)
	carry1 := c1a + c1b + c1c

	s2a, c2a := bits.Add64(hi11, hi20, 0)
	s2b, c2b := bits.Add64(lo21, carry1, 0)
	m2, c2c := bits.Add64(s2a, s2b, 0)
	carry2 := c2a + c2b + c2c

	m3 := hi21 + carry2
	qHat := (m2 >> 44) | (m3 << 20)

	p0Hi, p0Lo := bits.Mul64(qHat, interlockB168_0)
	_, p1Lo := bits.Mul64(qHat, interlockB168_1)

	rem0, br0 := bits.Sub64(x0, p0Lo, 0)
	rem1 := x1 - (p0Hi + p1Lo) - br0

	d0, b0 := bits.Sub64(rem0, interlockB168_0, 0)
	d1, b1 := bits.Sub64(rem1, interlockB168_1, b0)
	c := b1 ^ 1
	mask := -c

	q = qHat + c
	remOut0 = (rem0 & ^mask) | (d0 & mask)
	remOut1 = (rem1 & ^mask) | (d1 & mask)
	return
}

// modStepA168 performs a single 64-bit limb reduction step for divisor A168.
// Given running remainder (r0, r1, r2) < A168 (3 limbs LE) and next limb w, it
// forms the 215-bit dividend X = (r << 64) | w and returns (remOut0, remOut1, remOut2)
// = X mod A168 (< A168) using only 64x64->128 multiplies, shifts, and branchless
// subtraction. Scalar arguments and results stay in GPRs under Go ABIInternal.
func modStepA168(r0, r1, r2, w uint64) (remOut0, remOut1, remOut2 uint64) {
	x0, x1, x2, x3 := w, r0, r1, r2

	// t2 = x0*mu2 + x1*mu1 + x2*mu0 (weight 2^128)
	hi02, lo02 := bits.Mul64(x0, interlockMuA168_2)
	hi11, lo11 := bits.Mul64(x1, interlockMuA168_1)
	hi20, lo20 := bits.Mul64(x2, interlockMuA168_0)
	s0, c0a := bits.Add64(lo02, lo11, 0)
	_, c0b := bits.Add64(s0, lo20, 0)
	s1, c1a := bits.Add64(hi02, hi11, c0a)
	t2_1, c1b := bits.Add64(s1, hi20, c0b)
	t2_2 := c1a + c1b

	// t3 = x1*mu2 + x2*mu1 + x3*mu0 (weight 2^192)
	hi12, lo12 := bits.Mul64(x1, interlockMuA168_2)
	hi21, lo21 := bits.Mul64(x2, interlockMuA168_1)
	hi30, lo30 := bits.Mul64(x3, interlockMuA168_0)
	u0, d0a := bits.Add64(lo12, lo21, 0)
	t3_0, d0b := bits.Add64(u0, lo30, 0)
	u1, d1a := bits.Add64(hi12, hi21, d0a)
	t3_1, d1b := bits.Add64(u1, hi30, d0b)
	t3_2 := d1a + d1b

	// t4 = x2*mu2 + x3*mu1 (weight 2^256)
	hi22, lo22 := bits.Mul64(x2, interlockMuA168_2)
	hi31, lo31 := bits.Mul64(x3, interlockMuA168_1)
	t4_0, e0 := bits.Add64(lo22, lo31, 0)
	t4_1, e1 := bits.Add64(hi22, hi31, e0)
	t4_2 := e1

	// t5 = x3*mu2 (weight 2^320)
	t5_1, t5_0 := bits.Mul64(x3, interlockMuA168_2)

	// high_prod = t2 + (t3 << 64) + (t4 << 128) + (t5 << 192)
	_, ch1 := bits.Add64(t2_1, t3_0, 0)
	v2, ch2a := bits.Add64(t3_1, t4_0, ch1)
	_, ch2b := bits.Add64(v2, t2_2, 0)
	ch2 := ch2a + ch2b

	v3, ch3a := bits.Add64(t4_1, t5_0, 0)
	h3, ch3b := bits.Add64(v3, t3_2+ch2, 0)
	ch3 := ch3a + ch3b

	h4 := t4_2 + t5_1 + ch3
	qHat := (h3 >> 22) | (h4 << 42)

	pa0Hi, pa0Lo := bits.Mul64(qHat, interlockA168_0)
	pa1Hi, pa1Lo := bits.Mul64(qHat, interlockA168_1)
	_, pa2Lo := bits.Mul64(qHat, interlockA168_2)

	prod0 := pa0Lo
	prod1, cprod1 := bits.Add64(pa0Hi, pa1Lo, 0)
	prod2 := pa1Hi + pa2Lo + cprod1

	rem0, br0 := bits.Sub64(x0, prod0, 0)
	rem1, br1 := bits.Sub64(x1, prod1, br0)
	rem2, _ := bits.Sub64(x2, prod2, br1)

	d0, b0 := bits.Sub64(rem0, interlockA168_0, 0)
	d1, b1 := bits.Sub64(rem1, interlockA168_1, b0)
	d2, b2 := bits.Sub64(rem2, interlockA168_2, b1)
	mask := -(b2 ^ 1)

	remOut0 = (rem0 & ^mask) | (d0 & mask)
	remOut1 = (rem1 & ^mask) | (d1 & mask)
	remOut2 = (rem2 & ^mask) | (d2 & mask)
	return
}

// splitRank168 reduces a 512-bit rank digest (8 little-endian uint64 limbs)
// into the combinadic index pair (idx0, idx1) via the Two-Step Exact-B
// Reciprocal Reduction:
//
//	Step 1: (Q, idx1) = divmod(R_512, B168)   (7 steps, i = 6..0)
//	Step 2: idx0      = Q mod A168            (5 steps, i = 4..0)
func splitRank168(r [8]uint64) (idx0 [3]uint64, idx1 [2]uint64) {
	remB0, remB1 := r[7], uint64(0)
	var q [7]uint64
	for i := 6; i >= 0; i-- {
		q[i], remB0, remB1 = divmodStepB168(remB0, remB1, r[i])
	}
	idx1 = [2]uint64{remB0, remB1}

	remA0, remA1, remA2 := q[5], q[6], uint64(0)
	for i := 4; i >= 0; i-- {
		remA0, remA1, remA2 = modStepA168(remA0, remA1, remA2, q[i])
	}
	idx0 = [3]uint64{remA0, remA1, remA2}
	r = [8]uint64{}
	q = [7]uint64{}
	runtime.KeepAlive(&r)
	runtime.KeepAlive(&q)
	return
}
