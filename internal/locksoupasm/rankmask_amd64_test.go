//go:build amd64 && !purego && !noitbasm

package locksoupasm

import (
	"math/rand"
	"testing"
)

// Scalar reference: combinatorial-number-system unrank + balanced-triple
// assembly, identical to the production itb.rankToMaskTriple path. Used only
// to validate the AVX-512 batch kernel bit-for-bit.

var refBinom [25][9]uint64

func init() {
	for n := 0; n <= 24; n++ {
		refBinom[n][0] = 1
		for k := 1; k <= 8 && k <= n; k++ {
			refBinom[n][k] = refBinom[n-1][k-1] + refBinom[n-1][k]
		}
	}
}

func refUnrank(rank uint64, k, n int) uint32 {
	var mask uint32
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && refBinom[c+1][k] <= rank {
			c++
		}
		mask |= uint32(1) << uint(c)
		rank -= refBinom[c][k]
		k--
	}
	return mask
}

func refTriple(idx0, idx1 uint32) (m0, m1, m2 uint32) {
	m0 = refUnrank(uint64(idx0), 8, 24)
	m1Local := refUnrank(uint64(idx1), 8, 16)
	remaining := uint32(0xFFFFFF) & ^m0
	var posIdx uint
	for bit := uint(0); bit < 24; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint32(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

func TestRankToMaskBatchVsScalar(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 500000; iter++ {
		var idx0, idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = uint32(rng.Intn(735471)) // [0, C(24,8))
			idx1[j] = uint32(rng.Intn(12870))  // [0, C(16,8))
		}
		var out [3][8]uint32
		RankToMaskTripleUnrankBatch(&idx0, &idx1, &out)
		for j := 0; j < 8; j++ {
			e0, e1, e2 := refTriple(idx0[j], idx1[j])
			if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
				t.Fatalf("iter=%d lane=%d idx0=%d idx1=%d:\n got (%06x,%06x,%06x)\nwant (%06x,%06x,%06x)",
					iter, j, idx0[j], idx1[j], out[0][j], out[1][j], out[2][j], e0, e1, e2)
			}
		}
	}
}

// Boundary indices: 0 and max for each unrank dimension across all lanes.
func TestRankToMaskBatchBoundary(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	vals0 := []uint32{0, 1, 735470}
	vals1 := []uint32{0, 1, 12869}
	for _, v0 := range vals0 {
		for _, v1 := range vals1 {
			var idx0, idx1 [8]uint32
			for j := 0; j < 8; j++ {
				idx0[j] = v0
				idx1[j] = v1
			}
			var out [3][8]uint32
			RankToMaskTripleUnrankBatch(&idx0, &idx1, &out)
			e0, e1, e2 := refTriple(v0, v1)
			for j := 0; j < 8; j++ {
				if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
					t.Fatalf("v0=%d v1=%d lane=%d: got (%06x,%06x,%06x) want (%06x,%06x,%06x)",
						v0, v1, j, out[0][j], out[1][j], out[2][j], e0, e1, e2)
				}
				// balanced-triple invariant
				if popcount(out[0][j]) != 8 || popcount(out[1][j]) != 8 || popcount(out[2][j]) != 8 {
					t.Fatalf("v0=%d v1=%d lane=%d: unbalanced popcounts %d/%d/%d",
						v0, v1, j, popcount(out[0][j]), popcount(out[1][j]), popcount(out[2][j]))
				}
				if out[0][j]|out[1][j]|out[2][j] != 0xFFFFFF {
					t.Fatalf("v0=%d v1=%d lane=%d: union != 0xFFFFFF", v0, v1, j)
				}
			}
		}
	}
}

func popcount(x uint32) int {
	n := 0
	for x != 0 {
		n += int(x & 1)
		x >>= 1
	}
	return n
}

// refDerivePerm is the scalar Fisher-Yates permutation derivation, identical
// to the production itb.derivePermutation, for validating DerivePermPositions.
func refDerivePerm(prf uint64) (perm [24]byte) {
	var rem [24]byte
	for i := byte(0); i < 24; i++ {
		rem[i] = i
	}
	n := 24
	for i := 0; i < 24; i++ {
		nu := uint64(n)
		d := int(prf % nu)
		prf /= nu
		perm[i] = rem[d]
		copy(rem[d:n-1], rem[d+1:n])
		n--
	}
	return
}

// refDigits extracts the 24 factoradic digits of prf (unrolled constant
// divisors), matching the caller-side Go extraction the kernel relies on.
func refDigits(prf uint64) (d [24]uint32) {
	div := []uint64{24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2}
	for i, m := range div {
		d[i] = uint32(prf % m)
		prf /= m
	}
	d[23] = 0
	return
}

func TestDerivePermPositionsVsScalar(t *testing.T) {
	if !HasAVX512RankPerm {
		t.Skip("AVX-512 VPOPCNTDQ not available")
	}
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 300000; iter++ {
		var prf [8]uint64
		var digits [24][8]uint32
		for lane := 0; lane < 8; lane++ {
			prf[lane] = rng.Uint64()
			d := refDigits(prf[lane])
			for i := 0; i < 24; i++ {
				digits[i][lane] = d[i]
			}
		}
		var out [24][8]uint32
		DerivePermPositions(&digits, &out)
		for lane := 0; lane < 8; lane++ {
			want := refDerivePerm(prf[lane])
			for i := 0; i < 24; i++ {
				if out[i][lane] != uint32(want[i]) {
					t.Fatalf("iter=%d lane=%d i=%d prf=%#x: got pos %d want %d",
						iter, lane, i, prf[lane], out[i][lane], want[i])
				}
			}
		}
	}
}
