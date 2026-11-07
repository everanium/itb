// Known Answer Tests (KATs) and differential verification of posit64(es) and
// the 512-bit quire512 accumulator against an exact arbitrary-precision
// math/big.Rat and math/big.Float rational/dyadic oracle across es in {1, 2, 3}.

package itb

import (
	"math"
	"math/big"
	"math/rand"
	"testing"
)

// positToBigRat converts a non-NaR posit64(es) into its exact rational value.
func positToBigRat(u posit64, es uint) *big.Rat {
	if u == positZero {
		return new(big.Rat)
	}
	sign, _, _, scale, normM := positDecode64(u, es)
	num := new(big.Int).SetUint64(normM)
	r := new(big.Rat).SetInt(num)
	shift := scale - 63
	if shift >= 0 {
		p2 := new(big.Int).Lsh(big.NewInt(1), uint(shift))
		r.Mul(r, new(big.Rat).SetInt(p2))
	} else {
		p2 := new(big.Int).Lsh(big.NewInt(1), uint(-shift))
		r.Quo(r, new(big.Rat).SetInt(p2))
	}
	if sign {
		r.Neg(r)
	}
	return r
}

// bigRatToPosit rounds an exact rational r into posit64(es) under RNE.
func bigRatToPosit(r *big.Rat, es uint) posit64 {
	if r.Sign() == 0 {
		return positZero
	}
	sign := r.Sign() < 0
	absR := new(big.Rat).Abs(r)
	num := new(big.Int).Set(absR.Num())
	den := new(big.Int).Set(absR.Denom())

	scale := num.BitLen() - den.BitLen()
	if scale >= 0 {
		dShift := new(big.Int).Lsh(den, uint(scale))
		if num.Cmp(dShift) < 0 {
			scale--
		} else {
			dShift2 := new(big.Int).Lsh(den, uint(scale+1))
			if num.Cmp(dShift2) >= 0 {
				scale++
			}
		}
	} else {
		nShift := new(big.Int).Lsh(num, uint(-scale))
		if nShift.Cmp(den) < 0 {
			scale--
		} else if -scale-1 >= 0 {
			nShift2 := new(big.Int).Lsh(num, uint(-scale-1))
			if nShift2.Cmp(den) >= 0 {
				scale++
			}
		} else {
			dShift := new(big.Int).Lsh(den, 1)
			if num.Cmp(dShift) >= 0 {
				scale++
			}
		}
	}

	s := 63 - scale
	var q, rem *big.Int
	if s >= 0 {
		nScaled := new(big.Int).Lsh(num, uint(s))
		q, rem = new(big.Int).QuoRem(nScaled, den, new(big.Int))
	} else {
		dScaled := new(big.Int).Lsh(den, uint(-s))
		q, rem = new(big.Int).QuoRem(num, dScaled, new(big.Int))
	}
	normM := q.Uint64()
	var sticky uint64
	if rem.Sign() != 0 {
		sticky = 1
	}
	return positEncode64(sign, scale, normM, sticky, es)
}

func TestPositKATIntegersAndFloor(t *testing.T) {
	type intKAT struct {
		es        uint
		v         uint64
		wantPosit posit64
		wantNeg   posit64
		wantFloor uint64
	}
	kats := []intKAT{
		// es = 1
		{1, 0, 0x0000000000000000, 0x0000000000000000, 0},
		{1, 1, 0x4000000000000000, 0xc000000000000000, 1},
		{1, 2, 0x5000000000000000, 0xb000000000000000, 2},
		{1, 3, 0x5800000000000000, 0xa800000000000000, 3},
		{1, 4, 0x6000000000000000, 0xa000000000000000, 4},
		{1, 7, 0x6600000000000000, 0x9a00000000000000, 7},
		{1, 42, 0x7540000000000000, 0x8ac0000000000000, 42},
		{1, 255, 0x7bfc000000000000, 0x8404000000000000, 255},
		{1, 65536, 0x7fc0000000000000, 0x8040000000000000, 65536},
		{1, 1_000_000, 0x7fef424000000000, 0x8010bdc000000000, 1_000_000},
		{1, (1 << 40) + 1, 0x7ffffc0000000001, 0x800003ffffffffff, (1 << 40) + 1},
		{1, (1 << 53) + 1, 0x7ffffff400000000, 0x8000000c00000000, 1 << 53},
		{1, math.MaxUint64, 0x7fffffffc0000000, 0x8000000040000000, math.MaxUint64},

		// es = 2
		{2, 0, 0x0000000000000000, 0x0000000000000000, 0},
		{2, 1, 0x4000000000000000, 0xc000000000000000, 1},
		{2, 2, 0x4800000000000000, 0xb800000000000000, 2},
		{2, 3, 0x4c00000000000000, 0xb400000000000000, 3},
		{2, 4, 0x5000000000000000, 0xb000000000000000, 4},
		{2, 7, 0x5600000000000000, 0xaa00000000000000, 7},
		{2, 42, 0x6540000000000000, 0x9ac0000000000000, 42},
		{2, 255, 0x6ff8000000000000, 0x9008000000000000, 255},
		{2, 65536, 0x7c00000000000000, 0x8400000000000000, 65536},
		{2, 1_000_000, 0x7df4240000000000, 0x820bdc0000000000, 1_000_000},
		{2, (1 << 40) + 1, 0x7ff0000000000200, 0x800ffffffffffe00, (1 << 40) + 1},
		{2, (1 << 47) + 1, 0x7ffb000000000002, 0x8004fffffffffffe, (1 << 47) + 1},
		{2, (1 << 53) + 1, 0x7ffe400000000000, 0x8001c00000000000, 1 << 53},
		{2, math.MaxUint64, 0x7fffc00000000000, 0x8000400000000000, math.MaxUint64},

		// es = 3
		{3, 0, 0x0000000000000000, 0x0000000000000000, 0},
		{3, 1, 0x4000000000000000, 0xc000000000000000, 1},
		{3, 2, 0x4400000000000000, 0xbc00000000000000, 2},
		{3, 3, 0x4600000000000000, 0xba00000000000000, 3},
		{3, 4, 0x4800000000000000, 0xb800000000000000, 4},
		{3, 7, 0x4b00000000000000, 0xb500000000000000, 7},
		{3, 42, 0x5540000000000000, 0xaac0000000000000, 42},
		{3, 255, 0x5ff8000000000000, 0xa008000000000000, 255},
		{3, 65536, 0x7000000000000000, 0x9000000000000000, 65536},
		{3, 1_000_000, 0x73e8480000000000, 0x8c17b80000000000, 1_000_000},
		{3, (1 << 40) + 1, 0x7e00000000002000, 0x81ffffffffffe000, (1 << 40) + 1},
		{3, (1 << 52) + 1, 0x7f40000000000001, 0x80bfffffffffffff, (1 << 52) + 1},
		{3, (1 << 53) + 1, 0x7f50000000000000, 0x80b0000000000000, 1 << 53},
		{3, math.MaxUint64, 0x7fc0000000000000, 0x8040000000000000, math.MaxUint64},
	}

	for _, tc := range kats {
		got := positFromUint64(tc.v, tc.es)
		if got != tc.wantPosit {
			t.Fatalf("es=%d positFromUint64(%d): got 0x%016x, want 0x%016x", tc.es, tc.v, got, tc.wantPosit)
		}
		if neg := positNeg(got); neg != tc.wantNeg {
			t.Fatalf("es=%d positNeg(0x%016x): got 0x%016x, want 0x%016x", tc.es, got, neg, tc.wantNeg)
		}
		if fl := positFloorUint64(got, tc.es); fl != tc.wantFloor {
			t.Fatalf("es=%d positFloorUint64(0x%016x): got %d, want %d", tc.es, got, fl, tc.wantFloor)
		}
		ratU := new(big.Rat).SetInt(new(big.Int).SetUint64(tc.v))
		if ratGot := bigRatToPosit(ratU, tc.es); ratGot != got {
			t.Fatalf("es=%d bigRatToPosit(%d) = 0x%016x, positFromUint64 = 0x%016x", tc.es, tc.v, ratGot, got)
		}
	}
}

func TestPositKATRationalsAndRegimes(t *testing.T) {
	type ratKAT struct {
		es       uint
		num, den int64
		want     posit64
	}
	ratKATs := []ratKAT{
		// es = 1
		{1, 1, 2, 0x3000000000000000},
		{1, 1, 3, 0x2555555555555555},
		{1, 1, 5, 0x1ccccccccccccccd},
		{1, 1, 7, 0x1924924924924925},
		{1, 1, 10, 0x14cccccccccccccd},
		{1, 22, 7, 0x5924924924924925},
		{1, 355, 113, 0x5921fb78121fb781},

		// es = 2
		{2, 1, 2, 0x3800000000000000},
		{2, 1, 3, 0x32aaaaaaaaaaaaab},
		{2, 1, 5, 0x2ccccccccccccccd},
		{2, 1, 7, 0x2924924924924925},
		{2, 1, 10, 0x24cccccccccccccd},
		{2, 22, 7, 0x4c92492492492492},
		{2, 355, 113, 0x4c90fdbc090fdbc1},

		// es = 3
		{3, 1, 2, 0x3c00000000000000},
		{3, 1, 3, 0x3955555555555555},
		{3, 1, 5, 0x3666666666666666},
		{3, 1, 7, 0x3492492492492492},
		{3, 1, 10, 0x3266666666666666},
		{3, 22, 7, 0x4649249249249249},
		{3, 355, 113, 0x46487ede0487ede0},
	}

	for _, tc := range ratKATs {
		got := positDiv(positFromInt64(tc.num, tc.es), positFromInt64(tc.den, tc.es), tc.es)
		if got != tc.want {
			t.Fatalf("es=%d %d/%d: got 0x%016x, want 0x%016x", tc.es, tc.num, tc.den, got, tc.want)
		}
		if oracle := bigRatToPosit(big.NewRat(tc.num, tc.den), tc.es); oracle != tc.want {
			t.Fatalf("es=%d bigRatToPosit(%d/%d) = 0x%016x, want 0x%016x", tc.es, tc.num, tc.den, oracle, tc.want)
		}
	}

	// Verify regime boundaries and exact tie at minpos across es in {1, 2, 3}.
	for _, es := range []uint{1, 2, 3} {
		maxScale := 62 << es
		if got := positEncode64(false, maxScale, 1<<63, 0, es); got != positMax {
			t.Fatalf("es=%d scale=%d: got 0x%016x, want positMax", es, maxScale, got)
		}
		if got := positEncode64(false, -maxScale, 1<<63, 0, es); got != positMin {
			t.Fatalf("es=%d scale=%d: got 0x%016x, want positMin", es, -maxScale, got)
		}
		// Exact halfway tie in exponent field at k=-62 has p=1 (odd), so RNE rounds up to even (p=2).
		halfExpScale := -maxScale + (1 << (es - 1))
		if got := positEncode64(false, halfExpScale, 1<<63, 0, es); got != 2 {
			t.Fatalf("es=%d exact tie scale=%d: got 0x%016x, want 0x0000000000000002", es, halfExpScale, got)
		}
		if got := positEncode64(false, halfExpScale, 1<<63, 1, es); got != 2 {
			t.Fatalf("es=%d tie+sticky scale=%d: got 0x%016x, want 0x0000000000000002", es, halfExpScale, got)
		}
	}
}

func TestPositKATPiAndSqrt(t *testing.T) {
	type opKAT struct {
		es           uint
		wantPi       posit64
		wantPiF64    posit64
		wantSqrt2    posit64
		wantSqrt3    posit64
		wantSqrt5    posit64
		wantSqrtPi   posit64
		wantPiPlus37 posit64
		wantPi365    posit64
		wantPi1225   posit64
	}
	kats := []opKAT{
		{
			es:           1,
			wantPi:       0x5921fb54442d1847,
			wantPiF64:    0x5921fb54442d1800,
			wantSqrt2:    0x46a09e667f3bcc91,
			wantSqrt3:    0x4bb67ae8584caa74,
			wantSqrt5:    0x51e3779b97f4a7c1,
			wantSqrtPi:   0x4c5bf891b4ef6aa8,
			wantPiPlus37: 0x5c8fb22fb1e3f3b5,
			wantPi365:    0x7e0f55cd5c94d12e,
			wantPi1225:   0x7ef087374c747792,
		},
		{
			es:           2,
			wantPi:       0x4c90fdaa22168c23,
			wantPiF64:    0x4c90fdaa22168c00,
			wantSqrt2:    0x43504f333f9de648,
			wantSqrt3:    0x45db3d742c26553a,
			wantSqrt5:    0x48f1bbcdcbfa53e1,
			wantSqrtPi:   0x462dfc48da77b554,
			wantPiPlus37: 0x4e47d917d8f1f9da,
			wantPi365:    0x743d5735725344ba,
			wantPi1225:   0x77c21cdd31d1de49,
		},
		{
			es:           3,
			wantPi:       0x46487ed5110b4612,
			wantPiF64:    0x46487ed5110b4600,
			wantSqrt2:    0x41a827999fcef324,
			wantSqrt3:    0x42ed9eba16132a9d,
			wantSqrt5:    0x4478dde6e5fd29f0,
			wantSqrtPi:   0x4316fe246d3bdaaa,
			wantPiPlus37: 0x4723ec8bec78fced,
			wantPi365:    0x643d5735725344ba,
			wantPi1225:   0x67c21cdd31d1de4a,
		},
	}

	bfPi, _, err := big.ParseFloat(
		"3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679",
		10, 512, big.ToNearestEven,
	)
	if err != nil {
		t.Fatalf("ParseFloat(pi): %v", err)
	}
	ratPi, _ := bfPi.Rat(nil)
	ratPi64 := new(big.Rat).SetFloat64(math.Pi)

	for _, tc := range kats {
		piP := positPi(tc.es)
		if piP != tc.wantPi {
			t.Fatalf("es=%d positPi: got 0x%016x, want 0x%016x", tc.es, piP, tc.wantPi)
		}
		if oraclePi := bigRatToPosit(ratPi, tc.es); oraclePi != piP {
			t.Fatalf("es=%d 512-bit bigRatToPosit(pi) = 0x%016x, positPi = 0x%016x", tc.es, oraclePi, piP)
		}
		if oraclePi64 := bigRatToPosit(ratPi64, tc.es); oraclePi64 != tc.wantPiF64 {
			t.Fatalf("es=%d float64(math.Pi) posit = 0x%016x, want 0x%016x", tc.es, oraclePi64, tc.wantPiF64)
		}
		if piP == tc.wantPiF64 {
			t.Fatalf("es=%d positPi unexpectedly equals IEEE-754 float64(math.Pi) truncation", tc.es)
		}

		p2 := positFromUint64(2, tc.es)
		p3 := positFromUint64(3, tc.es)
		p5 := positFromUint64(5, tc.es)
		p7 := positFromUint64(7, tc.es)
		p365 := positFromUint64(365, tc.es)
		p1225 := positFromUint64(1225, tc.es)

		if got := positSqrt(p2, tc.es); got != tc.wantSqrt2 {
			t.Fatalf("es=%d positSqrt(2) = 0x%016x, want 0x%016x", tc.es, got, tc.wantSqrt2)
		}
		if got := positSqrt(p3, tc.es); got != tc.wantSqrt3 {
			t.Fatalf("es=%d positSqrt(3) = 0x%016x, want 0x%016x", tc.es, got, tc.wantSqrt3)
		}
		if got := positSqrt(p5, tc.es); got != tc.wantSqrt5 {
			t.Fatalf("es=%d positSqrt(5) = 0x%016x, want 0x%016x", tc.es, got, tc.wantSqrt5)
		}
		if got := positSqrt(piP, tc.es); got != tc.wantSqrtPi {
			t.Fatalf("es=%d positSqrt(pi) = 0x%016x, want 0x%016x", tc.es, got, tc.wantSqrtPi)
		}
		if got := positAdd(piP, positDiv(p3, p7, tc.es), tc.es); got != tc.wantPiPlus37 {
			t.Fatalf("es=%d pi+3/7 = 0x%016x, want 0x%016x", tc.es, got, tc.wantPiPlus37)
		}
		if got := positMul(piP, p365, tc.es); got != tc.wantPi365 {
			t.Fatalf("es=%d pi*365 = 0x%016x, want 0x%016x", tc.es, got, tc.wantPi365)
		}
		if got := positMul(piP, p1225, tc.es); got != tc.wantPi1225 {
			t.Fatalf("es=%d pi*1225 = 0x%016x, want 0x%016x", tc.es, got, tc.wantPi1225)
		}
	}
}

func TestPositKATQuireGaussChordsAndCancellation(t *testing.T) {
	type quireKAT struct {
		es           uint
		wantR2MinusY posit64
		wantChord    posit64
		wantFloor    uint64
	}
	kats := []quireKAT{
		{1, 0x7fee0a1ddecb6d69, 0x7ddf9b8ce030ba54, 959},
		{2, 0x7de0a1ddecb6d68b, 0x73bf3719c061749c, 959},
		{3, 0x73c143bbd96dad16, 0x63bf3719c061749c, 959},
	}

	for _, tc := range kats {
		piP := positPi(tc.es)
		r := positMul(piP, positFromUint64(365, tc.es), tc.es)
		y := positMul(piP, positFromUint64(200, tc.es), tc.es)
		var q quire512
		q.addProduct(r, r, tc.es)
		q.subProduct(y, y, tc.es)
		r2MinusY2 := q.toPosit(tc.es)
		if r2MinusY2 != tc.wantR2MinusY {
			t.Fatalf("es=%d quire(R^2-Y^2) = 0x%016x, want 0x%016x", tc.es, r2MinusY2, tc.wantR2MinusY)
		}
		chord := positSqrt(r2MinusY2, tc.es)
		if chord != tc.wantChord {
			t.Fatalf("es=%d positSqrt(quire(R^2-Y^2)) = 0x%016x, want 0x%016x", tc.es, chord, tc.wantChord)
		}
		if fl := positFloorUint64(chord, tc.es); fl != tc.wantFloor {
			t.Fatalf("es=%d floor(chord) = %d, want %d", tc.es, fl, tc.wantFloor)
		}

		// Catastrophic cancellation: (2^40 + 1)^2 - (2^40)^2 - 2^41 == 1.0 in quire512,
		// whereas intermediate rounding without quire collapses to 0.
		pPow40 := positEncode64(false, 40, 1<<63, 0, tc.es)
		pPow41 := positEncode64(false, 41, 1<<63, 0, tc.es)
		pBig := positAdd(pPow40, positOne, tc.es)
		var qCancel quire512
		qCancel.addProduct(pBig, pBig, tc.es)
		qCancel.subProduct(pPow40, pPow40, tc.es)
		qCancel.subProduct(pPow41, positOne, tc.es)
		if got := qCancel.toPosit(tc.es); got != positOne {
			t.Fatalf("es=%d quire cancellation = 0x%016x, want positOne (0x%016x)", tc.es, got, positOne)
		}
		nonQuire := positSub(positSub(positMul(pBig, pBig, tc.es), positMul(pPow40, pPow40, tc.es), tc.es), pPow41, tc.es)
		if nonQuire == positOne {
			t.Fatalf("es=%d non-quire cancellation unexpectedly preserved 1.0", tc.es)
		}
	}
}

// bigRatSqrtToPosit computes the exact RNE posit64(es) square root of a
// positive rational r = num/den using math/big.Int.Sqrt on a 256-bit scaled
// integer radicand with exact remainder sticky-bit tracking.
func bigRatSqrtToPosit(u posit64, es uint) posit64 {
	if u == positZero {
		return positZero
	}
	sign, _, _, scale, normM := positDecode64(u, es)
	if sign {
		return positNaR
	}
	halfScale := scale >> 1
	radShift := uint(63)
	if (scale & 1) != 0 {
		radShift = 64
	}
	rad := new(big.Int).SetUint64(normM)
	rad.Lsh(rad, radShift)
	root := new(big.Int).Sqrt(rad)
	rem := new(big.Int).Sub(rad, new(big.Int).Mul(root, root))
	root64 := root.Uint64()
	var lo uint64
	if rem.Sign() != 0 {
		lo = 1
	}
	return positEncode64(false, halfScale, root64, lo, es)
}

func TestPositDifferentialOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(0x17B3_2026))
	for _, es := range []uint{1, 2, 3} {
		for i := 0; i < 1500; i++ {
			u1 := posit64(rng.Uint64())
			u2 := posit64(rng.Uint64())
			if u1 == positNaR || u2 == positNaR {
				continue
			}

			r1 := positToBigRat(u1, es)
			r2 := positToBigRat(u2, es)

			if rt := bigRatToPosit(r1, es); rt != u1 {
				t.Fatalf("es=%d round-trip 0x%016x -> 0x%016x", es, u1, rt)
			}

			// Exact big.Rat oracle checks across the full posit64(es) range.
			if got, want := positAdd(u1, u2, es), bigRatToPosit(new(big.Rat).Add(r1, r2), es); got != want {
				t.Fatalf("es=%d positAdd(0x%016x, 0x%016x) = 0x%016x, want 0x%016x", es, u1, u2, got, want)
			}
			if got, want := positSub(u1, u2, es), bigRatToPosit(new(big.Rat).Sub(r1, r2), es); got != want {
				t.Fatalf("es=%d positSub(0x%016x, 0x%016x) = 0x%016x, want 0x%016x", es, u1, u2, got, want)
			}
			if got, want := positMul(u1, u2, es), bigRatToPosit(new(big.Rat).Mul(r1, r2), es); got != want {
				t.Fatalf("es=%d positMul(0x%016x, 0x%016x) = 0x%016x, want 0x%016x", es, u1, u2, got, want)
			}
			if u2 != positZero {
				if got, want := positDiv(u1, u2, es), bigRatToPosit(new(big.Rat).Quo(r1, r2), es); got != want {
					t.Fatalf("es=%d positDiv(0x%016x, 0x%016x) = 0x%016x, want 0x%016x", es, u1, u2, got, want)
				}
			}
			if (u1>>63) == 0 && u1 != positZero {
				if got, want := positSqrt(u1, es), bigRatSqrtToPosit(u1, es); got != want {
					t.Fatalf("es=%d positSqrt(0x%016x) = 0x%016x, want 0x%016x", es, u1, got, want)
				}
			}

			// Quire512 exact FMA check against big.Rat for scales within [-100, 100].
			_, _, _, sc1, _ := positDecode64(u1, es)
			_, _, _, sc2, _ := positDecode64(u2, es)
			if sc1 >= -100 && sc1 <= 100 && sc2 >= -100 && sc2 <= 100 {
				var q quire512
				q.addProduct(u1, u1, es)
				q.subProduct(u2, u2, es)
				gotQ := q.toPosit(es)
				rSqDiff := new(big.Rat).Sub(new(big.Rat).Mul(r1, r1), new(big.Rat).Mul(r2, r2))
				wantQ := bigRatToPosit(rSqDiff, es)
				if gotQ != wantQ {
					t.Fatalf("es=%d quire(u1^2 - u2^2) for (0x%016x, 0x%016x): got 0x%016x, want 0x%016x", es, u1, u2, gotQ, wantQ)
				}
			}
		}
	}
}
