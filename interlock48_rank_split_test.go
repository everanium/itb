package itb

import (
	"math/bits"
	"math/rand"
	"testing"
)

// TestSplitRank48Reciprocals pins the init-time reciprocals to their
// closed forms and the divisor bounds the shifts rely on.
func TestSplitRank48Reciprocals(t *testing.T) {
	if !(1<<interlockB48Shift < interlockB48 && interlockB48 < 1<<(interlockB48Shift+1)) {
		t.Fatalf("B = %d is not in (2^%d, 2^%d)", interlockB48, interlockB48Shift, interlockB48Shift+1)
	}
	if !(1<<interlockA48Shift < interlockA48 && interlockA48 < 1<<(interlockA48Shift+1)) {
		t.Fatalf("A = %d is not in (2^%d, 2^%d)", interlockA48, interlockA48Shift, interlockA48Shift+1)
	}
	if mB, _ := bits.Div64(1<<interlockB48Shift, 0, interlockB48); mB != interlockB48Recip {
		t.Fatalf("B reciprocal %d != %d", interlockB48Recip, mB)
	}
	if mA, _ := bits.Div64(1<<interlockA48Shift, 0, interlockA48); mA != interlockA48Recip {
		t.Fatalf("A reciprocal %d != %d", interlockA48Recip, mA)
	}
}

// splitRank48Check compares the reciprocal path against the Div64
// reference on one rank.
func splitRank48Check(t *testing.T, lane0, lane1 uint64) {
	t.Helper()
	i0, i1 := splitRank48Recip(lane0, lane1)
	e0, e1 := splitRank48Div(lane0, lane1)
	if i0 != e0 || i1 != e1 {
		t.Fatalf("rank (%016x, %016x): reciprocal (%d, %d) != Div64 (%d, %d)", lane1, lane0, i0, i1, e0, e1)
	}
	if d0, d1 := splitRank48(lane0, lane1); d0 != e0 || d1 != e1 {
		t.Fatalf("rank (%016x, %016x): dispatched split (%d, %d) != Div64 (%d, %d)", lane1, lane0, d0, d1, e0, e1)
	}
}

// TestSplitRank48Edges sweeps the structured corner cases of both
// reductions: limbs at 0, 1, all-ones, at multiples of B and A and one
// on either side, at the 32-bit and 42-bit digit boundaries, and every
// pairing of those values across the two limbs.
func TestSplitRank48Edges(t *testing.T) {
	var vals []uint64
	base := []uint64{0, 1, 2, 0xFFFF_FFFF, 1 << 32, 1<<32 + 1, 1<<42 - 1, 1 << 42, 1<<63 - 1, 1 << 63, ^uint64(0) - 1, ^uint64(0)}
	vals = append(vals, base...)
	for _, d := range []uint64{interlockB48, interlockA48} {
		for _, k := range []uint64{1, 2, 3, 7, 1 << 10, 1 << 20, 1 << 21, 1<<22 - 1, 1 << 22, ^uint64(0) / d} {
			for _, off := range []int64{-2, -1, 0, 1, 2} {
				v := k*d + uint64(off)
				vals = append(vals, v)
			}
		}
	}
	for _, s := range []uint{21, 22, 29, 30, 41, 42, 43, 63} {
		vals = append(vals, uint64(1)<<s, uint64(1)<<s-1, uint64(1)<<s+1, uint64(1)<<s|1)
	}
	for _, lo := range vals {
		for _, hi := range vals {
			splitRank48Check(t, lo, hi)
		}
	}
}

// TestSplitRank48VsDiv64 compares the reciprocal path against the Div64
// reference on random 128-bit ranks, including ranks whose low limb is
// biased toward the digit boundaries.
func TestSplitRank48VsDiv64(t *testing.T) {
	rng := rand.New(rand.NewSource(48))
	n := 2_000_000
	if testing.Short() {
		n = 200_000
	}
	for i := 0; i < n; i++ {
		lo, hi := rng.Uint64(), rng.Uint64()
		switch i & 7 {
		case 1:
			hi = 0
		case 2:
			hi &= 0xFFFF_FFFF
		case 3:
			lo &= 0xFFFF_FFFF
		case 4:
			lo |= 0xFFFF_FFFF
		case 5:
			hi = ^uint64(0)
		}
		splitRank48Check(t, lo, hi)
	}
}

// TestRankToMaskTriple48SplitPath pins the mask-triple derivation on the
// reciprocal split against the Div64 split feeding the same unrank.
func TestRankToMaskTriple48SplitPath(t *testing.T) {
	rng := rand.New(rand.NewSource(49))
	for i := 0; i < 20000; i++ {
		lo, hi := rng.Uint64(), rng.Uint64()
		m0, m1, m2 := rankToMaskTriple48(lo, hi)
		e0, e1 := splitRank48Div(lo, hi)
		w0 := unrankCombination48(e0, 16, 48)
		if m0 != w0 {
			t.Fatalf("rank (%016x, %016x): m0 %012x != %012x", hi, lo, m0, w0)
		}
		if m0|m1|m2 != 0x0000_FFFF_FFFF_FFFF || m0&m1 != 0 || m1&m2 != 0 || m0&m2 != 0 {
			t.Fatalf("rank (%016x, %016x): unbalanced triple", hi, lo)
		}
		_ = e1
	}
}

// BenchmarkSplitRank48 measures the reciprocal split against the Div64
// reference on the same ranks (8 ranks per iteration, the batch a mask
// fill hands to the unrank kernels).
func BenchmarkSplitRank48(b *testing.B) {
	rng := rand.New(rand.NewSource(50))
	var lo, hi [8]uint64
	for j := range lo {
		lo[j], hi[j] = rng.Uint64(), rng.Uint64()
	}
	var sink uint64
	b.Run("dispatched", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				i0, i1 := splitRank48(lo[j], hi[j])
				sink += i0 + uint64(i1)
			}
		}
	})
	b.Run("reciprocal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				i0, i1 := splitRank48Recip(lo[j], hi[j])
				sink += i0 + uint64(i1)
			}
		}
	})
	b.Run("div64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				i0, i1 := splitRank48Div(lo[j], hi[j])
				sink += i0 + uint64(i1)
			}
		}
	})
	_ = sink
}
