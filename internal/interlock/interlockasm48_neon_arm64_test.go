//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"math/rand"
	"testing"
)

const (
	neonA = uint64(2254848913647) // C(48, 16)
	neonB = uint64(601080390)     // C(32, 16)
)

// refUnrank48 — pure-Go combinatorial unrank restricted to the ranges
// consumed by the kernel (k <= 16, n <= 48), reading the canonical
// crow48Table rather than the kernel's repacked rows. Independent
// oracle for this file's parity tests.
func refUnrank48(rank uint64, k, n int) uint64 {
	var mask uint64
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && crow48Table[c+1][k] <= rank {
			c++
		}
		mask |= uint64(1) << uint(c)
		rank -= crow48Table[c][k]
		k--
	}
	return mask
}

// refTriple48 — bit-exact scalar reference for RankToMaskTripleUnrank48NEON:
// the two unranks plus the bit-serial remap onto the positions m0
// leaves free.
func refTriple48(idx0 uint64, idx1 uint32) (m0, m1, m2 uint64) {
	m0 = refUnrank48(idx0, 16, 48)
	m1Local := refUnrank48(uint64(idx1), 16, 32)
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

func checkTripleLanes(t *testing.T, tag string, idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	t.Helper()
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for j := 0; j < 8; j++ {
		e0, e1, e2 := refTriple48(idx0[j], idx1[j])
		if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
			t.Fatalf("%s lane=%d idx0=%d idx1=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
				tag, j, idx0[j], idx1[j], out[0][j], out[1][j], out[2][j], e0, e1, e2)
		}
		if out[0][j]|out[1][j]|out[2][j] != domain || out[0][j]&out[1][j] != 0 || out[0][j]&out[2][j] != 0 || out[1][j]&out[2][j] != 0 {
			t.Fatalf("%s lane=%d: triple is not a balanced partition of the domain", tag, j)
		}
		var gotBytes, wantBytes [24]byte
		for i, v := range []uint64{out[0][j], out[1][j], out[2][j]} {
			for b := 0; b < 8; b++ {
				gotBytes[i*8+b] = byte(v >> (8 * b))
			}
		}
		for i, v := range []uint64{e0, e1, e2} {
			for b := 0; b < 8; b++ {
				wantBytes[i*8+b] = byte(v >> (8 * b))
			}
		}
		if gotBytes != wantBytes {
			t.Fatalf("%s lane=%d: byte-level triple divergence", tag, j)
		}
	}
}

// TestRankToMaskTripleUnrank48NEONFixedVectors pins eight lanes covering
// the rank extremes: idx0 = 0 (the bottom combination, which keeps the
// pick count at 0 down to row 15 and exercises the C(15, 16) = 0 pick),
// A-1 (the top combination), B-1, and mid-range values.
func TestRankToMaskTripleUnrank48NEONFixedVectors(t *testing.T) {
	idx0 := [8]uint64{0, 1, neonA / 7, neonA / 3, neonA / 2, 2 * neonA / 3, neonA - 2, neonA - 1}
	idx1 := [8]uint32{uint32(neonB - 1), uint32(neonB / 2), 0, 1, uint32(neonB / 5), uint32(2 * neonB / 3), uint32(neonB - 2), uint32(neonB / 9)}
	var out [3][8]uint64
	RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
	checkTripleLanes(t, "fixed", &idx0, &idx1, &out)
	if out[0][0] != 0xFFFF {
		t.Fatalf("lane 0 (idx0 = 0): m0 = %012x, want the bottom 16 positions 0xFFFF", out[0][0])
	}
	if out[0][7] != 0xFFFF_0000_0000 {
		t.Fatalf("lane 7 (idx0 = A-1): m0 = %012x, want the top 16 positions", out[0][7])
	}
}

// TestRankToMaskTripleUnrank48NEONVsScalar sweeps random 8-lane index
// batches through the NEON kernel and compares every lane's triple
// against the scalar refTriple48 reference, value- and byte-level.
func TestRankToMaskTripleUnrank48NEONVsScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	const N = 10000
	for iter := 0; iter < N; iter++ {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = rng.Uint64() % neonA
			idx1[j] = uint32(rng.Uint64() % neonB)
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
		checkTripleLanes(t, "random", &idx0, &idx1, &out)
	}
}

// TestRankToMaskTripleUnrank48NEONEdgeRanks concentrates on ranks near
// the row boundaries C(p, k), where the pick predicate flips.
func TestRankToMaskTripleUnrank48NEONEdgeRanks(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	var pool []uint64
	for p := 16; p <= 48; p++ {
		c := crow48Table[p][16]
		for _, d := range []int64{-2, -1, 0, 1, 2} {
			v := int64(c) + d
			if v >= 0 && uint64(v) < neonA {
				pool = append(pool, uint64(v))
			}
		}
	}
	for iter := 0; iter < 2000; iter++ {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = pool[rng.Intn(len(pool))]
			idx1[j] = uint32(rng.Uint64() % neonB)
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
		checkTripleLanes(t, "edge", &idx0, &idx1, &out)
	}
}

// BenchmarkRankToMaskTripleUnrank48NEON measures the NEON 8-lane kernel
// against the scalar reference over the same eight lanes (the divmod
// split is caller-side on both paths and excluded here). Reported per
// 8-lane batch.
func BenchmarkRankToMaskTripleUnrank48NEON(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	var idx0 [8]uint64
	var idx1 [8]uint32
	for j := 0; j < 8; j++ {
		idx0[j] = rng.Uint64() % neonA
		idx1[j] = uint32(rng.Uint64() % neonB)
	}
	var out [3][8]uint64
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
		}
	})
	b.Run("scalar", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				out[0][j], out[1][j], out[2][j] = refTriple48(idx0[j], idx1[j])
			}
		}
	})
}
