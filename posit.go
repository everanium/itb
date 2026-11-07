package itb

import (
	"math"
	"math/bits"
	"runtime"
)

// posit64 represents a 64-bit Gustafson Posit number parameterized at runtime
// by the exponent field width es in {1, 2, 3} (with useed = 2^(2^es) in
// {4, 16, 256}). All operations are implemented in pure 64-bit integer and
// 512-bit fixed-point quire arithmetic without IEEE-754 floating-point
// instructions, ensuring bit-for-bit determinism across all CPU architectures.
type posit64 uint64

const (
	positZero posit64 = 0x0000000000000000
	positNaR  posit64 = 0x8000000000000000
	positMax  posit64 = 0x7fffffffffffffff
	positMin  posit64 = 0x0000000000000001
	positOne  posit64 = 0x4000000000000000
)

// quire512 is a 512-bit two's-complement fixed-point accumulator ([8]uint64 in
// little-endian word order) with its binary point at bit 256 (bit 0 of q[4]
// has weight 2^0 = 1). Products and sums of posit64 values accumulate into
// quire512 without intermediate rounding before a single final RNE rounding
// back to posit64(es).
type quire512 [8]uint64

const quireFracBits = 256

// quirePi holds the exact 256-bit fractional expansion of pi in quire512
// fixed-point representation:
//
//	pi = 3 + 0x243f6a8885a308d3_13198a2e03707344_a4093822299f31d0_082efa98ec4e6c89 * 2^-256
var quirePi = quire512{
	0x082efa98ec4e6c89, // bits   0..63  (2^-256 .. 2^-193)
	0xa4093822299f31d0, // bits  64..127 (2^-192 .. 2^-129)
	0x13198a2e03707344, // bits 128..191 (2^-128 .. 2^-65)
	0x243f6a8885a308d3, // bits 192..255 (2^-64  .. 2^-1)
	0x0000000000000003, // bits 256..319 (integer part = 3)
	0x0000000000000000,
	0x0000000000000000,
	0x0000000000000000,
}

// positPiDeepFrac holds bits -512..-257 of pi - 3 for mixing key-derived
// perturbations into the quire512 fractional accumulator under Mode 3.
var positPiDeepFrac = [4]uint64{
	0x3f84d5b5b5470917, // bits -512..-449
	0xc0ac29b7c97c50dd, // bits -448..-385
	0xbe5466cf34e90c6c, // bits -384..-321
	0x452821e638d01377, // bits -320..-257
}

// positDecode64 decodes a non-zero, non-NaR posit64(es) into:
//   - sign: true when negative
//   - k: regime value in [-62, 62]
//   - e: exponent value in [0, (1<<es)-1]
//   - scale: total power-of-two scale (k << es) + int(e)
//   - normM: normalized 64-bit significand with bit 63 set, representing
//     normM * 2^-63 in [1, 2).
func positDecode64(u posit64, es uint) (sign bool, k int, e uint, scale int, normM uint64) {
	if u == positZero || u == positNaR {
		return u == positNaR, 0, 0, 0, 0
	}
	sign = (uint64(u) >> 63) != 0
	p := uint64(u)
	if sign {
		p = uint64(-int64(p))
	}
	r0 := (p >> 62) & 1
	var m int
	if r0 == 1 {
		m = bits.LeadingZeros64(^(p << 1)) // 1..63
		k = m - 1                          // 0..62
	} else {
		m = bits.LeadingZeros64(p << 1) // 1..62
		k = -m                          // -62..-1
	}
	var rem uint64
	if m <= 62 {
		rem = p << uint(m+2)
	}
	e = uint(rem >> (64 - es))
	fracAligned := rem << es
	normM = (uint64(1) << 63) | (fracAligned >> 1)
	scale = (k << es) + int(e)
	return
}

// positEncode64 encodes (-1)^sign * (normM * 2^-63) * 2^scale with additional
// sticky bits into posit64(es) using Round-to-Nearest-Even (RNE). Requires
// normM == 0 (for positZero) or bit 63 of normM == 1.
func positEncode64(sign bool, scale int, normM uint64, sticky uint64, es uint) posit64 {
	if normM == 0 {
		return positZero
	}
	maxScale := 62 << es
	if scale >= maxScale {
		if sign {
			return positNeg(positMax)
		}
		return positMax
	}
	if scale < -maxScale {
		if sign {
			return positNeg(positMin)
		}
		return positMin
	}

	k := scale >> es
	e := uint64(scale) & ((uint64(1) << es) - 1)

	var m uint
	var regPattern uint64
	if k >= 0 {
		m = uint(k + 1) // 1..62
		regPattern = ((uint64(1) << m) - 1) << (63 - m)
	} else {
		m = uint(-k) // 1..62
		regPattern = uint64(1) << (62 - m)
	}

	frac63 := normM << 1
	var expFracHi, expFracLo uint64
	if es == 0 {
		expFracHi = frac63
		expFracLo = sticky
	} else {
		expFracHi = (e << (64 - es)) | (frac63 >> es)
		expFracLo = (frac63 << (64 - es)) | sticky
	}

	shift := m + 2 // 3..64
	var p uint64
	var guard uint64
	var remSticky uint64
	if shift == 64 {
		p = regPattern
		guard = expFracHi >> 63
		remSticky = (expFracHi & 0x7fffffffffffffff) | expFracLo
	} else {
		p = regPattern | (expFracHi >> shift)
		guard = (expFracHi >> (shift - 1)) & 1
		remSticky = (expFracHi & ((uint64(1) << (shift - 1)) - 1)) | expFracLo
	}

	if guard == 1 && (remSticky != 0 || (p&1) == 1) {
		p++
	}
	if sign {
		p = uint64(-int64(p))
	}
	return posit64(p)
}

func positNeg(a posit64) posit64 {
	return posit64(uint64(-int64(a)))
}

func positFromUint64(v uint64, es uint) posit64 {
	if v == 0 {
		return positZero
	}
	lz := bits.LeadingZeros64(v)
	scale := 63 - lz
	normM := v << uint(lz)
	return positEncode64(false, scale, normM, 0, es)
}

func positFromInt64(v int64, es uint) posit64 {
	if v == 0 {
		return positZero
	}
	sign := v < 0
	uv := uint64(v)
	if sign {
		uv = uint64(-v)
	}
	lz := bits.LeadingZeros64(uv)
	scale := 63 - lz
	normM := uv << uint(lz)
	return positEncode64(sign, scale, normM, 0, es)
}

func positFloorUint64(u posit64, es uint) uint64 {
	if u == positZero || u == positNaR || (uint64(u)>>63) != 0 {
		return 0
	}
	_, _, _, scale, normM := positDecode64(u, es)
	if scale < 0 {
		return 0
	}
	if scale >= 64 {
		return math.MaxUint64
	}
	return normM >> uint(63-scale)
}

func positAdd(a, b posit64, es uint) posit64 {
	if a == positNaR || b == positNaR {
		return positNaR
	}
	if a == positZero {
		return b
	}
	if b == positZero {
		return a
	}
	if a == positNeg(b) {
		return positZero
	}

	sa, _, _, scaleA, ma := positDecode64(a, es)
	sb, _, _, scaleB, mb := positDecode64(b, es)

	if scaleA < scaleB || (scaleA == scaleB && ma < mb) {
		sa, sb = sb, sa
		scaleA, scaleB = scaleB, scaleA
		ma, mb = mb, ma
	}

	diff := scaleA - scaleB
	var bHi, bLo, sticky uint64
	if diff == 0 {
		bHi = mb
	} else if diff < 64 {
		bHi = mb >> uint(diff)
		bLo = mb << uint(64-diff)
	} else if diff == 64 {
		bLo = mb
	} else if diff < 128 {
		s := uint(diff - 64)
		bLo = mb >> s
		sticky = mb << (64 - s)
	} else {
		sticky = mb
	}

	if sa == sb {
		lo := bLo
		hi, carry := bits.Add64(ma, bHi, 0)
		scale := scaleA
		if carry != 0 {
			sticky |= lo & 1
			lo = (lo >> 1) | (hi << 63)
			hi = (uint64(1) << 63) | (hi >> 1)
			scale++
		}
		return positEncode64(sa, scale, hi, lo|sticky, es)
	}

	var borrow uint64
	var subSticky uint64
	if sticky != 0 {
		subSticky = 1
		borrow = 1
	}
	lo, borrow := bits.Sub64(0, bLo, borrow)
	hi, _ := bits.Sub64(ma, bHi, borrow)

	if hi == 0 && lo == 0 && subSticky == 0 {
		return positZero
	}
	scale := scaleA
	if hi != 0 {
		lz := bits.LeadingZeros64(hi)
		if lz > 0 {
			scale -= lz
			hi = (hi << uint(lz)) | (lo >> uint(64-lz))
			lo = (lo << uint(lz)) | (subSticky << uint(lz-1))
			subSticky = 0
		}
	} else {
		lz := bits.LeadingZeros64(lo)
		scale -= 64 + lz
		hi = lo << uint(lz)
		lo = 0
	}
	return positEncode64(sa, scale, hi, lo|subSticky, es)
}

func positSub(a, b posit64, es uint) posit64 {
	return positAdd(a, positNeg(b), es)
}

func positMul(a, b posit64, es uint) posit64 {
	if a == positNaR || b == positNaR {
		return positNaR
	}
	if a == positZero || b == positZero {
		return positZero
	}
	sa, _, _, scaleA, ma := positDecode64(a, es)
	sb, _, _, scaleB, mb := positDecode64(b, es)
	sign := sa != sb
	hi, lo := bits.Mul64(ma, mb)
	scale := scaleA + scaleB
	if (hi >> 63) != 0 {
		scale++
		return positEncode64(sign, scale, hi, lo, es)
	}
	normM := (hi << 1) | (lo >> 63)
	sticky := lo << 1
	return positEncode64(sign, scale, normM, sticky, es)
}

func positDiv(a, b posit64, es uint) posit64 {
	if a == positNaR || b == positNaR || b == positZero {
		return positNaR
	}
	if a == positZero {
		return positZero
	}
	sa, _, _, scaleA, ma := positDecode64(a, es)
	sb, _, _, scaleB, mb := positDecode64(b, es)
	sign := sa != sb
	scale := scaleA - scaleB
	var q, rem uint64
	if ma >= mb {
		q, rem = bits.Div64(ma>>1, ma<<63, mb)
	} else {
		scale--
		q, rem = bits.Div64(ma, 0, mb)
	}
	return positEncode64(sign, scale, q, rem, es)
}

func positSqrt(a posit64, es uint) posit64 {
	if a == positNaR || (uint64(a)>>63) != 0 {
		return positNaR
	}
	if a == positZero {
		return positZero
	}
	_, _, _, scaleA, ma := positDecode64(a, es)
	odd := uint(scaleA & 1)
	scaleOut := scaleA >> 1

	var xHi, xLo uint64
	if odd == 0 {
		xHi = ma >> 1
		xLo = ma << 63
	} else {
		xHi = ma
		xLo = 0
	}
	root, rem := positIsqrt128(xHi, xLo)
	return positEncode64(false, scaleOut, root, rem, es)
}

// positIsqrt128 computes floor(sqrt(xHi*2^64 + xLo)) for xHi in [2^62, 2^64)
// and a non-zero sticky flag when the remainder is non-zero, using strictly
// integer uint64 / math/bits arithmetic.
func positIsqrt128(xHi, xLo uint64) (uint64, uint64) {
	r := uint64(1) << 32
	for i := 0; i < 6; i++ {
		r = (r + xHi/r) >> 1
	}
	if r >= (uint64(1) << 32) {
		r = math.MaxUint64
	} else {
		r = (r << 32) | 0x80000000
	}

	for i := 0; i < 2; i++ {
		var q uint64
		if xHi >= r {
			q = math.MaxUint64
		} else {
			q, _ = bits.Div64(xHi, xLo, r)
		}
		r = (r >> 1) + (q >> 1) + (r & q & 1)
	}

	sqHi, sqLo := bits.Mul64(r, r)
	for sqHi > xHi || (sqHi == xHi && sqLo > xLo) {
		r--
		sqHi, sqLo = bits.Mul64(r, r)
	}
	for r < math.MaxUint64 {
		nHi, nLo := bits.Mul64(r+1, r+1)
		if nHi < xHi || (nHi == xHi && nLo <= xLo) {
			r++
			sqHi, sqLo = nHi, nLo
		} else {
			break
		}
	}
	var sticky uint64
	if sqHi != xHi || sqLo != xLo {
		sticky = 1
	}
	return r, sticky
}

func positPi(es uint) posit64 {
	return quirePi.toPosit(es)
}

func (q *quire512) neg() {
	var carry uint64 = 1
	for i := 0; i < 8; i++ {
		q[i], carry = bits.Add64(^q[i], 0, carry)
	}
}

func (q *quire512) addSignedShifted128(sign bool, hi, lo uint64, bitPos int) {
	if hi == 0 && lo == 0 {
		return
	}
	var mag [8]uint64
	words := [2]uint64{lo, hi}
	for wIdx, val := range words {
		if val == 0 {
			continue
		}
		bp := bitPos + wIdx*64
		wordPos := bp >> 6
		bitShift := uint(bp & 63)
		if wordPos >= 0 && wordPos < 8 {
			var c uint64
			mag[wordPos], c = bits.Add64(mag[wordPos], val<<bitShift, 0)
			for k := wordPos + 1; k < 8 && c != 0; k++ {
				mag[k], c = bits.Add64(mag[k], 0, c)
			}
		}
		if bitShift > 0 && wordPos+1 >= 0 && wordPos+1 < 8 {
			var c uint64
			mag[wordPos+1], c = bits.Add64(mag[wordPos+1], val>>(64-bitShift), 0)
			for k := wordPos + 2; k < 8 && c != 0; k++ {
				mag[k], c = bits.Add64(mag[k], 0, c)
			}
		}
	}
	if sign {
		var borrow uint64
		for i := 0; i < 8; i++ {
			q[i], borrow = bits.Sub64(q[i], mag[i], borrow)
		}
	} else {
		var carry uint64
		for i := 0; i < 8; i++ {
			q[i], carry = bits.Add64(q[i], mag[i], carry)
		}
	}
	clear(mag[:])
	clear(words[:])
	runtime.KeepAlive(&mag)
	runtime.KeepAlive(&words)
}

func (q *quire512) addPosit(a posit64, es uint) {
	if a == positZero || a == positNaR {
		return
	}
	sa, _, _, scaleA, ma := positDecode64(a, es)
	q.addSignedShifted128(sa, 0, ma, quireFracBits+scaleA-63)
}

func (q *quire512) addProduct(a, b posit64, es uint) {
	if a == positZero || b == positZero || a == positNaR || b == positNaR {
		return
	}
	sa, _, _, scaleA, ma := positDecode64(a, es)
	sb, _, _, scaleB, mb := positDecode64(b, es)
	hi, lo := bits.Mul64(ma, mb)
	q.addSignedShifted128(sa != sb, hi, lo, quireFracBits+scaleA+scaleB-126)
}

func (q *quire512) subProduct(a, b posit64, es uint) {
	q.addProduct(a, positNeg(b), es)
}

func (q quire512) toPosit(es uint) posit64 {
	if q == (quire512{}) {
		return positZero
	}
	sign := (q[7] >> 63) != 0
	mag := q
	defer func() {
		clear(mag[:])
		runtime.KeepAlive(&mag)
	}()
	if sign {
		mag.neg()
	}
	topIdx := -1
	for i := 7; i >= 0; i-- {
		if mag[i] != 0 {
			topIdx = i
			break
		}
	}
	if topIdx < 0 {
		return positZero
	}
	lz := bits.LeadingZeros64(mag[topIdx])
	msbPos := topIdx*64 + (63 - lz)
	scale := msbPos - quireFracBits

	var normM uint64
	var sticky uint64
	if lz == 0 {
		normM = mag[topIdx]
		for i := 0; i < topIdx; i++ {
			sticky |= mag[i]
		}
	} else {
		normM = mag[topIdx] << uint(lz)
		if topIdx > 0 {
			normM |= mag[topIdx-1] >> uint(64-lz)
			sticky |= mag[topIdx-1] << uint(lz)
			for i := 0; i < topIdx-1; i++ {
				sticky |= mag[i]
			}
		}
	}
	return positEncode64(sign, scale, normM, sticky, es)
}

// positGaussCircleFloor computes the Mode 3 inscribed Gauss circle container
// floor for 3*minPxJoint pixels in canonical posit64(2):
//
//	floor((2 * threeMinPx) / pi_posit(es=2)) + 1
func positGaussCircleFloor(threeMinPx int) int {
	if threeMinPx <= 0 {
		return 1
	}
	const es = 2
	num := positFromUint64(uint64(2*threeMinPx), es)
	pi := positPi(es)
	q := positDiv(num, pi, es)
	return int(positFloorUint64(q, es)) + 1
}

// positDeriveSecretPi derives a region's secret Posit configuration es_r in
// {1, 2, 3} and secret Posit circle constant pi_{K,r} from the 8 folded
// domain-0x05 words w[0..7] by accumulating a key-dependent perturbation into
// the 512-bit quirePi accumulator before RNE rounding to posit64(es_r).
func positDeriveSecretPi(w [8]uint64) (piK posit64, es uint) {
	es = 1 + uint((w[0]>>40)%3) // {1, 2, 3}

	q := quirePi
	var delta [4]uint64
	delta[0] = (w[4] >> 16) ^ bits.RotateLeft64(w[5], 19) ^ positPiDeepFrac[0]
	delta[1] = (w[5] >> 16) ^ bits.RotateLeft64(w[6], 29) ^ positPiDeepFrac[1]
	delta[2] = (w[6] >> 16) ^ bits.RotateLeft64(w[7], 37) ^ positPiDeepFrac[2]
	// Place all 48 upper bits [16..63] of each word w[2..7] inside bits [8..59]
	// of delta[3] (weights 2^-56 .. 2^-5), strictly inside the 58..60-bit
	// mantissa window of posit64(es_r) at scale 1 while keeping pi_{K,r} in
	// [pi, pi + 0.0625).
	topMix := ((w[2] >> 16) << 8) ^
		((w[3] >> 16) << 9) ^
		((w[4] >> 16) << 10) ^
		((w[5] >> 16) << 11) ^
		((w[6] >> 16) << 12) ^
		((w[7] >> 16) << 12) ^
		(positPiDeepFrac[3] >> 4)
	delta[3] = topMix & 0x0fffffffffffffff

	var carry uint64
	for i := 0; i < 4; i++ {
		q[i], carry = bits.Add64(q[i], delta[i], carry)
	}
	for i := 4; i < 8 && carry != 0; i++ {
		q[i], carry = bits.Add64(q[i], 0, carry)
	}

	piK = q.toPosit(es)
	topMix = 0
	clear(w[:])
	clear(delta[:])
	clear(q[:])
	runtime.KeepAlive(&topMix)
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&delta)
	runtime.KeepAlive(&q)
	return piK, es
}

// buildSubregionSchedulePosit constructs the Mode 3 Layer I (0x05) sub-region
// schedule by slicing the region of totalPixels into Gauss circle chords
// floor(sqrt(R_posit^2 - y_j^2))_posit evaluated in posit64(es_r) and the
// 512-bit quire512 accumulator under the region's secret (pi_{K,r}, es_r).
func buildSubregionSchedulePosit(startPixel, totalPixels int, w [8]uint64) subregionSchedule {
	var k, deltaMax int
	if totalPixels < mode1DesyncRegionPixels {
		k = 6 + int(w[0]%5) // [6, 10]
		deltaMax = 1        // delta in {-1, 0}
	} else {
		k = 8 + int(w[0]%9) // [8, 16]
		deltaMax = 2        // delta in {-2, -1, 0, +1}
	}

	piK, es := positDeriveSecretPi(w)
	pTotal := positFromUint64(uint64(totalPixels), es)
	radius := positMul(pTotal, piK, es)

	phase := uint64((w[0] >> 44) & 63) // [0, 63]
	flip := ((w[0] >> 52) & 1) != 0
	denPosit := positFromUint64(uint64(64*k+32), es)

	var chords [maxDesyncSubregions]uint64
	var chordSum uint64
	var chordDigest uint64
	for j := 0; j < k; j++ {
		idx := j
		if flip {
			idx = k - 1 - j
		}
		num := uint64(64*idx+16) + phase
		y := positDiv(positMul(radius, positFromUint64(num, es), es), denPosit, es)

		var q quire512
		q.addProduct(radius, radius, es)
		q.subProduct(y, y, es)
		r2MinusY2 := q.toPosit(es)
		clear(q[:])
		runtime.KeepAlive(&q)

		cPosit := positSqrt(r2MinusY2, es)
		cBits := uint64(cPosit)
		cFold := cBits ^ (cBits >> 13) ^ (cBits >> 27) ^ (cBits >> 41) ^ (cBits >> 53)
		chord := positFloorUint64(cPosit, es) + 1 + (cFold & 7)
		chords[j] = chord
		chordSum += chord
		chordDigest = bits.RotateLeft64(chordDigest, 19) ^ (cBits * desyncGoldenGamma) ^ uint64(r2MinusY2)
	}

	// Reserve minSub = 5 pixels per sub-region so even after boundary jitter
	// delta in [-2, +1], adjacent offsets satisfy physSize[j] >= 5 - 3 = 2.
	const minSub = 5
	remPixels := totalPixels - k*minSub

	var physOff [maxDesyncSubregions + 1]int
	var physSize [maxDesyncSubregions]int
	var cum uint64
	for j := 1; j < k; j++ {
		cum += chords[j-1]
		prop := int((uint64(remPixels) * cum) / chordSum)
		var delta int
		if deltaMax == 1 {
			raw := int(((w[0] >> uint(8+j)) ^ (chordDigest >> uint(j))) & 1)
			delta = raw - 1
		} else {
			raw := int(((w[0] >> uint(8+2*j)) ^ (chordDigest >> uint(2*j))) & 3)
			delta = raw - 2
		}
		physOff[j] = j*minSub + prop + delta
	}
	physOff[k] = totalPixels
	for j := 0; j < k; j++ {
		physSize[j] = physOff[j+1] - physOff[j]
	}

	var tau [maxDesyncSubregions]int
	for i := 0; i < k; i++ {
		tau[i] = i
	}
	u := w[1] ^ bits.RotateLeft64(chordDigest, 29)
	for i := k - 1; i > 0; i-- {
		mod := uint64(i + 1)
		swapIdx := int(u % mod)
		u /= mod
		tau[i], tau[swapIdx] = tau[swapIdx], tau[i]
	}

	var sched subregionSchedule
	sched.k = k
	for step := 0; step < k; step++ {
		physIdx := tau[step]
		m := physSize[physIdx]
		sched.offset[step] = physOff[physIdx]
		sched.size[step] = m
		sched.logOff[step+1] = sched.logOff[step] + m
		positMix := uint64(piK) ^ bits.RotateLeft64(uint64(radius), 19*(step+1)) ^ bits.RotateLeft64(chordDigest, 7*(step+1))
		mix := bits.RotateLeft64(w[2+(step%6)], 11*step) ^ (uint64(step+1) * desyncGoldenGamma) ^ positMix
		sched.start[step] = int((uint64(startPixel) + mix) % uint64(m))
	}

	piK = 0
	radius = 0
	chordDigest = 0
	u = 0
	clear(w[:])
	clear(chords[:])
	clear(physOff[:])
	clear(physSize[:])
	clear(tau[:])
	runtime.KeepAlive(&piK)
	runtime.KeepAlive(&radius)
	runtime.KeepAlive(&chordDigest)
	runtime.KeepAlive(&u)
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&chords)
	runtime.KeepAlive(&physOff)
	runtime.KeepAlive(&physSize)
	runtime.KeepAlive(&tau)
	return sched
}
