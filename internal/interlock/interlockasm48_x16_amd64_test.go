//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"math/bits"
	"math/rand"
	"testing"

	"golang.org/x/sys/cpu"
)

const (
	x16A = uint64(2254848913647) // C(48, 16)
	x16B = uint64(601080390)     // C(32, 16)
)

// TestRankToMaskTripleUnrank48x16VsScalar sweeps random 16-lane index
// batches through the 16-lane kernel and compares every lane's triple
// against the scalar refTriple48 reference, value- and byte-level —
// the 8-lane test's contract widened to 16 lanes.
func TestRankToMaskTripleUnrank48x16VsScalar(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	rng := rand.New(rand.NewSource(16))
	const N = 20000
	for iter := 0; iter < N; iter++ {
		var idx0 [16]uint64
		var idx1 [16]uint32
		for j := 0; j < 16; j++ {
			idx0[j] = rng.Uint64() % x16A
			idx1[j] = uint32(rng.Uint64() % x16B)
		}
		var out [3][16]uint64
		RankToMaskTripleUnrank48x16(&idx0, &idx1, &out)
		for j := 0; j < 16; j++ {
			e0, e1, e2 := refTriple48(idx0[j], idx1[j])
			if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
				t.Fatalf("iter=%d lane=%d idx0=%d idx1=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
					iter, j, idx0[j], idx1[j], out[0][j], out[1][j], out[2][j], e0, e1, e2)
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
				t.Fatalf("iter=%d lane=%d: byte-level triple divergence", iter, j)
			}
		}
	}
}

// TestRankToMaskTripleUnrank48x16VsX8 pins the 16-lane kernel to two
// 8-lane kernel invocations over the same lanes.
func TestRankToMaskTripleUnrank48x16VsX8(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	rng := rand.New(rand.NewSource(32))
	for iter := 0; iter < 5000; iter++ {
		var idx0 [16]uint64
		var idx1 [16]uint32
		for j := 0; j < 16; j++ {
			idx0[j] = rng.Uint64() % x16A
			idx1[j] = uint32(rng.Uint64() % x16B)
		}
		var out16 [3][16]uint64
		RankToMaskTripleUnrank48x16(&idx0, &idx1, &out16)
		for half := 0; half < 16; half += 8 {
			var out8 [3][8]uint64
			RankToMaskTripleUnrank48((*[8]uint64)(idx0[half:half+8]), (*[8]uint32)(idx1[half:half+8]), &out8)
			for j := 0; j < 8; j++ {
				for k := 0; k < 3; k++ {
					if out16[k][half+j] != out8[k][j] {
						t.Fatalf("iter=%d lane=%d k=%d: x16 %012x != x8 %012x", iter, half+j, k, out16[k][half+j], out8[k][j])
					}
				}
			}
		}
	}
}

// TestRankToMaskTripleUnrank48x16FixedVectors pins sixteen distinct
// lanes covering the rank extremes: idx0 = 0 (the bottom combination,
// which keeps krem = 16 down to row 15 and exercises the krem != 0
// predicate at the row where C(15, 16) = 0 must be picked), A-1, B-1,
// and mid-range values, in both batches.
func TestRankToMaskTripleUnrank48x16FixedVectors(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	idx0 := [16]uint64{
		0, 1, x16A / 7, x16A / 3, x16A / 2, 2 * x16A / 3, x16A - 2, x16A - 1,
		x16A - 1, 0, x16A / 5, x16A / 9, 3 * x16A / 4, x16A / 11, 2, x16A / 13,
	}
	idx1 := [16]uint32{
		uint32(x16B - 1), uint32(x16B / 2), 0, 1, uint32(x16B / 5), uint32(2 * x16B / 3), uint32(x16B - 2), uint32(x16B / 9),
		0, uint32(x16B - 1), uint32(x16B / 7), uint32(x16B / 3), 2, uint32(x16B / 11), uint32(x16B - 3), uint32(x16B / 13),
	}
	var out [3][16]uint64
	RankToMaskTripleUnrank48x16(&idx0, &idx1, &out)
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for j := 0; j < 16; j++ {
		e0, e1, e2 := refTriple48(idx0[j], idx1[j])
		if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
			t.Fatalf("lane %d (idx0=%d idx1=%d): got (%012x, %012x, %012x) want (%012x, %012x, %012x)",
				j, idx0[j], idx1[j], out[0][j], out[1][j], out[2][j], e0, e1, e2)
		}
		if out[0][j]|out[1][j]|out[2][j] != domain || out[0][j]&out[1][j] != 0 || out[0][j]&out[2][j] != 0 || out[1][j]&out[2][j] != 0 {
			t.Fatalf("lane %d: triple is not a balanced partition of the domain", j)
		}
	}
	if out[0][0] != 0xFFFF {
		t.Fatalf("lane 0 (idx0 = 0): m0 = %012x, want the bottom 16 positions 0xFFFF", out[0][0])
	}
}

func BenchmarkRankToMaskTripleUnrank48x16AVX512(b *testing.B) {
	if !HasAVX512RankMask {
		b.Skip("AVX-512F not available")
	}
	rng := rand.New(rand.NewSource(1))
	var idx0 [16]uint64
	var idx1 [16]uint32
	for j := 0; j < 16; j++ {
		idx0[j] = rng.Uint64() % x16A
		idx1[j] = uint32(rng.Uint64() % x16B)
	}
	var out [3][16]uint64
	for i := 0; i < b.N; i++ {
		RankToMaskTripleUnrank48x16(&idx0, &idx1, &out)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/16, "ns/triple")
}

// tripleBytes48 serialises a mask triple as three little-endian uint64
// values — the byte-level view the parity tests compare so a per-lane
// endianness or truncation slip cannot hide behind a value compare.
func tripleBytes48(m [3]uint64) [24]byte {
	var b [24]byte
	for i, v := range m {
		for k := 0; k < 8; k++ {
			b[i*8+k] = byte(v >> (8 * k))
		}
	}
	return b
}

// checkX16Lanes runs the 16-lane kernel over (idx0, idx1) and pins every
// lane against the scalar refTriple48 reference, against the 8-lane
// AVX-512 kernel run over the same half on its own, and — when the
// silicon can execute it — against the AVX2 kernel over the same half;
// value- and byte-level, plus the balanced-partition invariants of the
// triple. The fixed-pattern tests below route through it so each case
// carries the full cross-arm agreement check rather than the scalar
// comparison alone. Returns the 16-lane output for callers that compare
// batches across invocations.
func checkX16Lanes(t *testing.T, label string, idx0 *[16]uint64, idx1 *[16]uint32) [3][16]uint64 {
	t.Helper()
	for j := 0; j < 16; j++ {
		if idx0[j] >= x16A || uint64(idx1[j]) >= x16B {
			t.Fatalf("%s lane=%d: test input out of contract (idx0=%d idx1=%d)", label, j, idx0[j], idx1[j])
		}
	}
	var out16 [3][16]uint64
	RankToMaskTripleUnrank48x16(idx0, idx1, &out16)
	avx2OK := cpu.X86.HasAVX2 && cpu.X86.HasBMI2
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for half := 0; half < 16; half += 8 {
		i0 := (*[8]uint64)(idx0[half : half+8])
		i1 := (*[8]uint32)(idx1[half : half+8])
		var out8, outAVX2 [3][8]uint64
		RankToMaskTripleUnrank48(i0, i1, &out8)
		if avx2OK {
			RankToMaskTripleUnrank48AVX2(i0, i1, &outAVX2)
		}
		for j := 0; j < 8; j++ {
			lane := half + j
			e0, e1, e2 := refTriple48(idx0[lane], idx1[lane])
			want := [3]uint64{e0, e1, e2}
			got := [3]uint64{out16[0][lane], out16[1][lane], out16[2][lane]}
			if got != want {
				t.Fatalf("%s lane=%d idx0=%d idx1=%d: x16 (%012x, %012x, %012x), scalar (%012x, %012x, %012x)",
					label, lane, idx0[lane], idx1[lane], got[0], got[1], got[2], want[0], want[1], want[2])
			}
			if tripleBytes48(got) != tripleBytes48(want) {
				t.Fatalf("%s lane=%d: byte-level triple divergence between x16 and scalar", label, lane)
			}
			x8 := [3]uint64{out8[0][j], out8[1][j], out8[2][j]}
			if x8 != want {
				t.Fatalf("%s lane=%d idx0=%d idx1=%d: x8 (%012x, %012x, %012x), scalar (%012x, %012x, %012x)",
					label, lane, idx0[lane], idx1[lane], x8[0], x8[1], x8[2], want[0], want[1], want[2])
			}
			if avx2OK {
				a2 := [3]uint64{outAVX2[0][j], outAVX2[1][j], outAVX2[2][j]}
				if a2 != want {
					t.Fatalf("%s lane=%d idx0=%d idx1=%d: avx2 (%012x, %012x, %012x), scalar (%012x, %012x, %012x)",
						label, lane, idx0[lane], idx1[lane], a2[0], a2[1], a2[2], want[0], want[1], want[2])
				}
			}
			if got[0]|got[1]|got[2] != domain || got[0]&got[1] != 0 || got[0]&got[2] != 0 || got[1]&got[2] != 0 {
				t.Fatalf("%s lane=%d: triple is not a partition of the 48-bit domain", label, lane)
			}
			if bits.OnesCount64(got[0]) != 16 || bits.OnesCount64(got[1]) != 16 || bits.OnesCount64(got[2]) != 16 {
				t.Fatalf("%s lane=%d: triple is not balanced 16/16/16", label, lane)
			}
		}
	}
	return out16
}

// x16SpilloverSamples returns the rank samples that make the C(p, 16)
// slot-0 lookup load-bearing at every reachable row: C(p, 16) − 1
// (no pick, krem stays 16), C(p, 16) (pick exactly at the boundary) and
// C(p, 16) + 1 for p in [16, 47] on the m0 loop and p in [16, 31] on the
// m1 loop, plus the two rank extremes of each loop.
func x16SpilloverSamples() (m0 []uint64, m1 []uint32) {
	for p := 16; p <= 47; p++ {
		c := crow48Table[p][16]
		if c == 0 {
			continue
		}
		m0 = append(m0, c-1, c, c+1)
	}
	m0 = append(m0, crow48Table[48][16]-1, 0)
	for p := 16; p <= 31; p++ {
		c := crow48Table[p][16]
		if c == 0 {
			continue
		}
		m1 = append(m1, uint32(c-1), uint32(c), uint32(c+1))
	}
	m1 = append(m1, uint32(crow48Table[32][16])-1, 0)
	return
}

// TestRankToMaskTripleUnrank48x16Krem16Spillover is the 16-lane mirror
// of TestRankToMaskTripleUnrank48Krem16Spillover. In the 16-lane kernel
// krem = 16 and krem = 0 both index slot 0 of the packed row (the
// permute consumes the low 4 bits of krem), so the krem != 0 predicate
// is the only thing separating a legal krem = 16 pick from a suppressed
// krem = 0 read — on both batches, since each batch carries its own
// predicate register. Every spillover sample is placed in batch a on
// one call and in batch b on the next (adjacent samples share a call),
// so the two predicate paths are exercised on every row with the
// partner batch in a different chain state.
func TestRankToMaskTripleUnrank48x16Krem16Spillover(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	m0s, m1s := x16SpilloverSamples()
	for i, a0 := range m0s {
		b0 := m0s[(i+1)%len(m0s)]
		for k, a1 := range m1s {
			b1 := m1s[(k+1)%len(m1s)]
			var idx0 [16]uint64
			var idx1 [16]uint32
			for j := 0; j < 8; j++ {
				idx0[j], idx1[j] = a0, a1
				idx0[8+j], idx1[8+j] = b0, b1
			}
			checkX16Lanes(t, "krem16 spillover", &idx0, &idx1)
		}
	}
}

// TestRankToMaskTripleUnrank48x16P48MaxRow is the 16-lane mirror of
// TestRankToMaskTripleUnrank48P48MaxRow: the widest row (p = 47, the
// 42-bit C(47, 16) value) through every idx0 boundary point, with idx1
// distinct on every one of the 16 lanes so the m1 chains of the two
// batches never run in lock-step. Batch b additionally carries the next
// idx0 boundary point so the row-47 pick decision differs between the
// batches on the same call.
func TestRankToMaskTripleUnrank48x16P48MaxRow(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	c47_16 := crow48Table[47][16]
	if c47_16 == 0 {
		t.Fatal("crow48Table not initialised")
	}
	cases := []uint64{0, c47_16 - 1, c47_16, c47_16 + 1, crow48Table[48][16] - 1}
	for i, i0 := range cases {
		var idx0 [16]uint64
		var idx1 [16]uint32
		for j := 0; j < 16; j++ {
			idx0[j] = i0
			idx1[j] = uint32(j)
		}
		checkX16Lanes(t, "p48 max row (uniform batches)", &idx0, &idx1)
		next := cases[(i+1)%len(cases)]
		for j := 8; j < 16; j++ {
			idx0[j] = next
			idx1[j] = uint32(x16B) - 1 - uint32(j)
		}
		checkX16Lanes(t, "p48 max row (staggered batches)", &idx0, &idx1)
	}
}

// TestRankToMaskTripleUnrank48x16Boundary is the 16-lane mirror of
// TestRankToMaskTripleUnrank48Boundary: the 5 × 5 cross product of
// (idx0, idx1) corner values on all 16 lanes, then the same product
// with batch b holding the opposite corner of batch a.
func TestRankToMaskTripleUnrank48x16Boundary(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	i0s := []uint64{0, 1, x16A / 2, x16A - 2, x16A - 1}
	i1s := []uint32{0, 1, uint32(x16B / 2), uint32(x16B - 2), uint32(x16B - 1)}
	for a, v0 := range i0s {
		for b, v1 := range i1s {
			var idx0 [16]uint64
			var idx1 [16]uint32
			for j := 0; j < 16; j++ {
				idx0[j], idx1[j] = v0, v1
			}
			checkX16Lanes(t, "boundary (uniform batches)", &idx0, &idx1)
			for j := 8; j < 16; j++ {
				idx0[j], idx1[j] = i0s[len(i0s)-1-a], i1s[len(i1s)-1-b]
			}
			checkX16Lanes(t, "boundary (opposite corners)", &idx0, &idx1)
		}
	}
}

// TestRankToMaskTripleUnrank48x16BatchAsymmetry holds the two 8-lane
// batches of the 16-lane kernel in deliberately different chain states
// — one batch on ranks that keep krem = 16 deep into the row walk
// (idx0 = 0 and C(p, 16) − 1 for small p; idx1 likewise on the m1
// loop), the other on ranks that pick at the very first row (idx0 >=
// C(47, 16), idx1 >= C(31, 16)) — in both assignments. The invariant
// under test: each batch's output equals its own standalone 8-lane
// result and is unchanged when the partner batch is swapped for a
// different one, so no register or predicate of one batch leaks into
// the other.
func TestRankToMaskTripleUnrank48x16BatchAsymmetry(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	c := func(p int) uint64 { return crow48Table[p][16] }
	deep0 := [8]uint64{0, 1, c(17) - 1, c(20) - 1, c(24) - 1, c(32) - 1, c(40) - 1, c(47) - 1}
	deep1 := [8]uint32{0, uint32(c(16)), uint32(c(17) - 1), uint32(c(20) - 1), uint32(c(24) - 1), uint32(c(28) - 1), uint32(c(30) - 1), uint32(c(31) - 1)}
	// Ranks at or above C(47, 16) pick position 47 on the first row;
	// C(47, 16) + C(46, 15) then picks position 46 as well, and so on
	// down the top of the domain (every sum stays below C(48, 16)).
	early0 := [8]uint64{
		c(47), c(47) + 1, c(47) + crow48Table[46][15], x16A - 1, x16A - 2,
		c(47) + crow48Table[46][15] + crow48Table[45][14], (c(47) + x16A - 1) / 2, c(47) + 12345,
	}
	early1 := [8]uint32{
		uint32(c(31)), uint32(c(31) + 1), uint32(c(31) + crow48Table[30][15]), uint32(x16B - 1), uint32(x16B - 2),
		uint32(c(31) + crow48Table[30][15] + crow48Table[29][14]), uint32((c(31) + x16B - 1) / 2), uint32(c(31) + 777),
	}
	rng := rand.New(rand.NewSource(64))
	var rand0 [8]uint64
	var rand1 [8]uint32
	for j := 0; j < 8; j++ {
		rand0[j] = rng.Uint64() % x16A
		rand1[j] = uint32(rng.Uint64() % x16B)
	}
	type batch struct {
		name string
		i0   [8]uint64
		i1   [8]uint32
	}
	batches := []batch{{"deep", deep0, deep1}, {"early", early0, early1}, {"random", rand0, rand1}}

	run := func(a, b batch) [3][16]uint64 {
		var idx0 [16]uint64
		var idx1 [16]uint32
		copy(idx0[:8], a.i0[:])
		copy(idx0[8:], b.i0[:])
		copy(idx1[:8], a.i1[:])
		copy(idx1[8:], b.i1[:])
		return checkX16Lanes(t, "asymmetry a="+a.name+" b="+b.name, &idx0, &idx1)
	}
	// Every ordered pair of distinct batches, then the batch against
	// itself: the a-half must be identical across every partner, and
	// the b-half likewise.
	for _, a := range batches {
		var aHalf [3][8]uint64
		first := true
		for _, b := range batches {
			out := run(a, b)
			var half [3][8]uint64
			for k := 0; k < 3; k++ {
				copy(half[k][:], out[k][:8])
			}
			if first {
				aHalf, first = half, false
			} else if half != aHalf {
				t.Fatalf("batch a=%s: output changed when partner batch b=%s", a.name, b.name)
			}
			swapped := run(b, a)
			for k := 0; k < 3; k++ {
				for j := 0; j < 8; j++ {
					if swapped[k][8+j] != out[k][j] || swapped[k][j] != out[k][8+j] {
						t.Fatalf("batches (%s, %s): swapping the batches changed a lane result", a.name, b.name)
					}
				}
			}
		}
	}
}
