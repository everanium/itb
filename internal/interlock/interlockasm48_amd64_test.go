//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"math/rand"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/everanium/itb/internal/cpuid"
)

// softPEXT48Ref / softPDEP48Ref are local pure-Go references for the
// asm entry points. Structurally identical to the parent package's
// softPEXT48 / softPDEP48, duplicated here so the asm-package tests
// stay self-contained (no import cycle with the parent).
func softPEXT48Ref(x, mask uint64) uint16 {
	var result, outBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		xb := (x >> i) & 1
		result |= (bit & xb) << outBit
		outBit += bit
	}
	return uint16(result)
}

func softPDEP48Ref(v uint16, mask uint64) uint64 {
	var result, inBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		vb := uint64(v>>inBit) & 1
		result |= (bit & vb) << i
		inBit += bit
	}
	return result
}

// randomTripleMask returns a valid (m0, m1, m2) mask triple: popcount
// 16 each, pairwise-disjoint, union = 2^48 - 1. Derived from the same
// combinatorial unrank + remap as the parent package; duplicated here
// to keep this test self-contained.
func randomTripleMask(rng *rand.Rand) (m0, m1, m2 uint64) {
	// Local Pascal table just big enough for k <= 16, n <= 48.
	var c [49][17]uint64
	for n := 0; n <= 48; n++ {
		c[n][0] = 1
		for k := 1; k <= 16 && k <= n; k++ {
			c[n][k] = c[n-1][k-1] + c[n-1][k]
		}
	}
	unrank := func(rank uint64, k, n int) uint64 {
		var mask uint64
		for k > 0 {
			cc := k - 1
			for cc+1 <= n-1 && c[cc+1][k] <= rank {
				cc++
			}
			mask |= uint64(1) << uint(cc)
			rank -= c[cc][k]
			k--
		}
		return mask
	}

	const A = 2254848913647
	const B = 601080390
	idx0 := rng.Uint64() % A
	idx1 := rng.Uint64() % B
	m0 = unrank(idx0, 16, 48)
	m1Local := unrank(idx1, 16, 32)
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

// TestChunk48LockAsmVsSoft compares the BMI2 kernel output byte-for-byte
// against the pure-Go softPEXT48 reference on random 48-bit inputs and
// PRF-derived mask triples. Byte-level rather than value-level: the
// parent-package driver serialises lane outputs as little-endian uint16
// into three per-lane byte buffers; a byte-level assert catches any
// endianness / truncation surprise a value-level compare would miss.
func TestChunk48LockAsmVsSoft(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(1))
	const N = 20000
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for iter := 0; iter < N; iter++ {
		x := rng.Uint64() & domain
		m0, m1, m2 := randomTripleMask(rng)

		l0a, l1a, l2a := Chunk48Lock(x, m0, m1, m2)
		l0s := softPEXT48Ref(x, m0)
		l1s := softPEXT48Ref(x, m1)
		l2s := softPEXT48Ref(x, m2)

		// Value-level.
		if uint16(l0a) != l0s || uint16(l1a) != l1s || uint16(l2a) != l2s {
			t.Fatalf("iter=%d x=%012x masks=(%012x,%012x,%012x): asm=(%04x,%04x,%04x) soft=(%04x,%04x,%04x)",
				iter, x, m0, m1, m2, uint16(l0a), uint16(l1a), uint16(l2a), l0s, l1s, l2s)
		}
		// Byte-level: serialise both lane triples as little-endian uint16 and compare.
		var asmBytes, softBytes [6]byte
		asmBytes[0] = byte(l0a)
		asmBytes[1] = byte(l0a >> 8)
		asmBytes[2] = byte(l1a)
		asmBytes[3] = byte(l1a >> 8)
		asmBytes[4] = byte(l2a)
		asmBytes[5] = byte(l2a >> 8)
		softBytes[0] = byte(l0s)
		softBytes[1] = byte(l0s >> 8)
		softBytes[2] = byte(l1s)
		softBytes[3] = byte(l1s >> 8)
		softBytes[4] = byte(l2s)
		softBytes[5] = byte(l2s >> 8)
		if asmBytes != softBytes {
			t.Fatalf("iter=%d: byte-level lane serialisation differs: asm=%x soft=%x",
				iter, asmBytes, softBytes)
		}
		// Upper bits above the low 16 of each returned uint64 must be zero.
		if l0a>>16 != 0 || l1a>>16 != 0 || l2a>>16 != 0 {
			t.Fatalf("iter=%d: Chunk48Lock leaked bits above position 15: (%016x, %016x, %016x)",
				iter, l0a, l1a, l2a)
		}
	}
}

// TestUnchunk48LockAsmVsSoft compares the BMI2 kernel output against
// the pure-Go softPDEP48 reference. Random 16-bit lane values under
// valid mask triples reconstruct the 48-bit chunk word; both paths
// must produce identical results.
func TestUnchunk48LockAsmVsSoft(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(2))
	const N = 20000
	for iter := 0; iter < N; iter++ {
		l0 := uint16(rng.Uint32())
		l1 := uint16(rng.Uint32())
		l2 := uint16(rng.Uint32())
		m0, m1, m2 := randomTripleMask(rng)

		xAsm := Unchunk48Lock(uint64(l0), uint64(l1), uint64(l2), m0, m1, m2)
		xSoft := softPDEP48Ref(l0, m0) | softPDEP48Ref(l1, m1) | softPDEP48Ref(l2, m2)

		if xAsm != xSoft {
			t.Fatalf("iter=%d lanes=(%04x,%04x,%04x) masks=(%012x,%012x,%012x): asm=%012x soft=%012x",
				iter, l0, l1, l2, m0, m1, m2, xAsm, xSoft)
		}
		if xAsm>>48 != 0 {
			t.Fatalf("iter=%d: Unchunk48Lock wrote outside 48-bit domain: %016x", iter, xAsm)
		}
	}
}

// TestChunk48LockAsmRoundTrip is the self-consistency check: apply the
// forward asm kernel to a random 48-bit chunk then the inverse asm
// kernel; the recovered value must equal the input.
func TestChunk48LockAsmRoundTrip(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(3))
	const N = 20000
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for iter := 0; iter < N; iter++ {
		x := rng.Uint64() & domain
		m0, m1, m2 := randomTripleMask(rng)
		l0, l1, l2 := Chunk48Lock(x, m0, m1, m2)
		back := Unchunk48Lock(l0, l1, l2, m0, m1, m2)
		if back != x {
			t.Fatalf("iter=%d x=%012x: round-trip yielded %012x", iter, x, back)
		}
	}
}

// refUnrank48 — pure-Go combinatorial unrank restricted to the ranges
// consumed by the batch kernel (k <= 16, n <= 48). Used only as an
// independent oracle in this file's parity test.
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

// refTriple48 — bit-exact scalar reference for RankToMaskTripleUnrank48.
// Splits already occurred caller-side; this reproduces the two unranks
// plus the remap that the kernel implements in vector form.
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

// TestRankToMaskTripleUnrank48VsScalar sweeps random (idx0, idx1) pair
// batches through the batched AVX-512 kernel and compares each lane's
// (m0, m1, m2) triple against the scalar refTriple48 reference.
// Byte-level check via memcmp of the packed lane serialisation catches
// any per-lane endianness / VPERMI2Q index / mask-merge slip that a
// value-level compare would miss.
func TestRankToMaskTripleUnrank48VsScalar(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	const A = 2254848913647
	const B = 601080390
	rng := rand.New(rand.NewSource(4))
	const N = 20000
	for iter := 0; iter < N; iter++ {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = rng.Uint64() % A
			idx1[j] = uint32(rng.Uint64() % B)
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48(&idx0, &idx1, &out)
		for j := 0; j < 8; j++ {
			e0, e1, e2 := refTriple48(idx0[j], idx1[j])
			if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
				t.Fatalf("iter=%d lane=%d idx0=%d idx1=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
					iter, j, idx0[j], idx1[j], out[0][j], out[1][j], out[2][j], e0, e1, e2)
			}
			// Byte-level: serialise both triples LE-per-uint64 into 24 bytes.
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
				t.Fatalf("iter=%d lane=%d: byte-level triple divergence:\n got %x\nwant %x",
					iter, j, gotBytes, wantBytes)
			}
		}
	}
}

// TestRankToMaskTripleUnrank48Krem16Spillover directly exercises the
// 17-th row entry path (index 16 wraps to slot 0 of the packed 16-entry
// row table holding C(p, 16)). krem == 16 is only
// possible on the sequence of iterations before the first bit is set
// (each success decrements krem), so this test constructs (idx0, idx1)
// values that keep krem == 16 for several iterations at loop entry,
// making the C(p, 16) lookup load-bearing.
//
// For the m0 loop (p=47..0, krem starts at 16):
//   - idx0 in [0, C(47,16)): first iteration doesn't set bit 47, so
//     krem stays 16 for p=46, 45, ... until either idx0 crosses
//     C(p,16) or the whole loop exhausts.
//   - idx0 = C(47,16) - 1: iteration at p=47 sees rank < C(47,16)
//     (krem=16 path executes, no pick). Then p=46, still krem=16,
//     etc.
//   - idx0 = C(47,16): iteration at p=47 picks (mask-merge value
//     matches, condition true), krem decrements to 15.
//
// The lane-index scanning below marches through every krem == 16
// boundary point (one per remaining position) plus a saturating
// idx0 = C(48,16)-1 case where the 17-th-entry path is used at
// p=47 and again at p=46 until krem drops.
func TestRankToMaskTripleUnrank48Krem16Spillover(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}

	// crow48Table[p][16] for p in [16, 47] — the exact spillover values
	// loaded at slot 0 of the packed row table.
	// Explicit literal calls to crow48Table anchor the test against the
	// live table.
	//
	// For each spillover position p, exercise all three boundary ranks:
	//   C(p,16) - 1 (branch not taken → krem stays 16)
	//   C(p,16)     (branch taken exactly at the boundary → krem drops)
	//   C(p,16) + 1 (branch taken above the boundary → krem drops)
	// This forces both wrap-with-no-pick and wrap-with-pick
	// code paths on the same row.
	type sample struct {
		label string
		idx0  uint64
	}
	var m0Samples []sample
	for p := 16; p <= 47; p++ {
		c := crow48Table[p][16]
		if c == 0 {
			continue
		}
		m0Samples = append(m0Samples,
			sample{label: fmtInt("m0 p=", p, " rank=C-1"), idx0: c - 1},
			sample{label: fmtInt("m0 p=", p, " rank=C"), idx0: c},
			sample{label: fmtInt("m0 p=", p, " rank=C+1"), idx0: c + 1},
		)
	}
	// Saturating rank: forces the krem=16 branch to fire and pick at p=47.
	m0Samples = append(m0Samples,
		sample{label: "m0 idx0=A-1", idx0: crow48Table[48][16] - 1},
		sample{label: "m0 idx0=0", idx0: 0},
	)

	// For m1Local loop (p=31..0, k=16): same layout, so exercise C(p,16)
	// for p in [16, 31]. These are all values idx1 (< C(32,16)) can reach
	// since C(31,16) = 300,540,195 < C(32,16) = 601,080,390.
	var m1Samples []uint32
	for p := 16; p <= 31; p++ {
		c := crow48Table[p][16]
		if c == 0 {
			continue
		}
		m1Samples = append(m1Samples,
			uint32(c-1), uint32(c), uint32(c+1),
		)
	}
	m1Samples = append(m1Samples, uint32(crow48Table[32][16])-1, 0)

	// Cross-product boundaries: every m0 spillover x a small m1 sweep.
	// Enough coverage to hit every (p, krem=16) row-lookup transition
	// under both branch outcomes without ballooning the run time.
	for _, m0s := range m0Samples {
		for _, i1 := range m1Samples {
			var idx0 [8]uint64
			var idx1 [8]uint32
			for j := 0; j < 8; j++ {
				idx0[j] = m0s.idx0
				idx1[j] = i1
			}
			var out [3][8]uint64
			RankToMaskTripleUnrank48(&idx0, &idx1, &out)
			e0, e1, e2 := refTriple48(m0s.idx0, i1)
			for j := 0; j < 8; j++ {
				if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
					t.Fatalf("%s idx1=%d lane=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
						m0s.label, i1, j,
						out[0][j], out[1][j], out[2][j],
						e0, e1, e2)
				}
			}
		}
	}
}

// TestRankToMaskTripleUnrank48P48MaxRow specifically loads the widest
// row in the table (p=47, k=16 → the 42-bit C(47,16) value = 1.58e12)
// and pushes it through every idx0 boundary point. This is the row
// where the 17-th mask-merge broadcast supplies the largest possible
// value and the VPCMPUQ comparison operates on values close to
// uint64's high range for the two-step reduction upstream.
func TestRankToMaskTripleUnrank48P48MaxRow(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	// Row 47 anchor values: C(47, 0..16). C(47, 16) is the widest.
	c47_16 := crow48Table[47][16]
	if c47_16 == 0 {
		t.Fatal("crow48Table not initialised")
	}
	// Cases: idx0 straddling C(47, 16) plus the extremes.
	cases := []uint64{
		0,
		c47_16 - 1,
		c47_16,
		c47_16 + 1,
		crow48Table[48][16] - 1, // A - 1 (max allowed idx0)
	}
	for _, i0 := range cases {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = i0
			idx1[j] = uint32(j) // vary idx1 across lanes to avoid degenerate
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48(&idx0, &idx1, &out)
		for j := 0; j < 8; j++ {
			e0, e1, e2 := refTriple48(i0, uint32(j))
			if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
				t.Fatalf("i0=%d lane=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
					i0, j, out[0][j], out[1][j], out[2][j], e0, e1, e2)
			}
		}
	}
}

// fmtInt is a tiny local helper so the sample-label construction above
// stays readable without depending on fmt in this asm-package test.
func fmtInt(prefix string, p int, suffix string) string {
	digits := []byte{}
	if p == 0 {
		digits = append(digits, '0')
	} else {
		var buf [4]byte
		n := 0
		for p > 0 {
			buf[n] = byte('0' + p%10)
			n++
			p /= 10
		}
		for i := n - 1; i >= 0; i-- {
			digits = append(digits, buf[i])
		}
	}
	out := make([]byte, 0, len(prefix)+len(digits)+len(suffix))
	out = append(out, prefix...)
	out = append(out, digits...)
	out = append(out, suffix...)
	return string(out)
}

// TestRankToMaskTripleUnrank48Boundary hits the (idx0, idx1) corner
// values: 0, 1, one-below-max, max-minus-one across all 8 lanes.
// These stress the row-lookup at every p in the unrank loops and the
// mask-merge broadcast of C(p, 16) at loop entry.
func TestRankToMaskTripleUnrank48Boundary(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	const A = uint64(2254848913647)
	const B = uint32(601080390)
	i0s := []uint64{0, 1, A / 2, A - 2, A - 1}
	i1s := []uint32{0, 1, B / 2, B - 2, B - 1}
	for _, v0 := range i0s {
		for _, v1 := range i1s {
			var idx0 [8]uint64
			var idx1 [8]uint32
			for j := 0; j < 8; j++ {
				idx0[j] = v0
				idx1[j] = v1
			}
			var out [3][8]uint64
			RankToMaskTripleUnrank48(&idx0, &idx1, &out)
			e0, e1, e2 := refTriple48(v0, v1)
			for j := 0; j < 8; j++ {
				if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
					t.Fatalf("v0=%d v1=%d lane=%d: got (%012x, %012x, %012x), want (%012x, %012x, %012x)",
						v0, v1, j, out[0][j], out[1][j], out[2][j], e0, e1, e2)
				}
			}
		}
	}
}

// forceAVX2RankMask arms the AVX2 rank-mask arm for the duration of a
// test the way the parent router selects it on AVX2-only silicon (and
// the way ITB_FORCE_INTERLOCK_TIER=avx2 forces it on wider silicon):
// HasAVX2RankMask on, HasAVX512RankMask off. Returns a restore func for
// defer — the same save/flip/restore idiom the Phase A / Phase B hash
// kernel tests use for their dispatch flags. Skips when the silicon
// cannot execute the AVX2 kernel (AVX2 for the unrank body, BMI2 for
// the scalar-PDEPQ remap tail).
func forceAVX2RankMask(t testing.TB) func() {
	if !cpuid.AVX2 || !cpuid.BMI2 {
		t.Skip("AVX2+BMI2 not available")
	}
	origAVX2, origAVX512 := HasAVX2RankMask, HasAVX512RankMask
	HasAVX2RankMask = true
	HasAVX512RankMask = false
	return func() {
		HasAVX2RankMask = origAVX2
		HasAVX512RankMask = origAVX512
	}
}

// TestRankToMaskTripleUnrank48AVX2VsScalar is the AVX2-arm mirror of
// TestRankToMaskTripleUnrank48VsScalar: random (idx0, idx1) batches
// through the 4-lane AVX2 kernel against the scalar refTriple48
// reference, with the byte-level serialisation check.
func TestRankToMaskTripleUnrank48AVX2VsScalar(t *testing.T) {
	defer forceAVX2RankMask(t)()
	const A = 2254848913647
	const B = 601080390
	rng := rand.New(rand.NewSource(4))
	const N = 20000
	for iter := 0; iter < N; iter++ {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = rng.Uint64() % A
			idx1[j] = uint32(rng.Uint64() % B)
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
		for j := 0; j < 8; j++ {
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
				t.Fatalf("iter=%d lane=%d: byte-level triple divergence:\n got %x\nwant %x",
					iter, j, gotBytes, wantBytes)
			}
		}
	}
}

// TestRankToMaskTripleUnrank48AVX2Krem16Spillover is the AVX2-arm
// mirror of TestRankToMaskTripleUnrank48Krem16Spillover: the C(p, 16)
// value wraps to group 0 slot 0 in the packed 16-entry row;
// the boundary ranks below exercise that path under both branch
// outcomes on every reachable row.
func TestRankToMaskTripleUnrank48AVX2Krem16Spillover(t *testing.T) {
	defer forceAVX2RankMask(t)()
	type sample struct {
		label string
		idx0  uint64
	}
	var m0Samples []sample
	for p := 16; p <= 47; p++ {
		c := crow48Table[p][16]
		if c == 0 {
			continue
		}
		m0Samples = append(m0Samples,
			sample{label: fmtInt("m0 p=", p, " rank=C-1"), idx0: c - 1},
			sample{label: fmtInt("m0 p=", p, " rank=C"), idx0: c},
			sample{label: fmtInt("m0 p=", p, " rank=C+1"), idx0: c + 1},
		)
	}
	m0Samples = append(m0Samples,
		sample{label: "m0 idx0=A-1", idx0: crow48Table[48][16] - 1},
		sample{label: "m0 idx0=0", idx0: 0},
	)
	var m1Samples []uint32
	for p := 16; p <= 31; p++ {
		c := crow48Table[p][16]
		if c == 0 {
			continue
		}
		m1Samples = append(m1Samples,
			uint32(c-1), uint32(c), uint32(c+1),
		)
	}
	m1Samples = append(m1Samples, uint32(crow48Table[32][16])-1, 0)

	for _, m0s := range m0Samples {
		for _, i1 := range m1Samples {
			var idx0 [8]uint64
			var idx1 [8]uint32
			for j := 0; j < 8; j++ {
				idx0[j] = m0s.idx0
				idx1[j] = i1
			}
			var out [3][8]uint64
			RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
			e0, e1, e2 := refTriple48(m0s.idx0, i1)
			for j := 0; j < 8; j++ {
				if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
					t.Fatalf("%s idx1=%d lane=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
						m0s.label, i1, j,
						out[0][j], out[1][j], out[2][j],
						e0, e1, e2)
				}
			}
		}
	}
}

// TestRankToMaskTripleUnrank48AVX2P48MaxRow is the AVX2-arm mirror of
// TestRankToMaskTripleUnrank48P48MaxRow: the widest row (p=47, the
// 42-bit C(47,16) value) through every idx0 boundary point — the row
// where the signed-VPCMPGTQ translation of the unsigned compare
// operates on the largest values the kernel ever sees.
func TestRankToMaskTripleUnrank48AVX2P48MaxRow(t *testing.T) {
	defer forceAVX2RankMask(t)()
	c47_16 := crow48Table[47][16]
	if c47_16 == 0 {
		t.Fatal("crow48Table not initialised")
	}
	cases := []uint64{
		0,
		c47_16 - 1,
		c47_16,
		c47_16 + 1,
		crow48Table[48][16] - 1, // A - 1 (max allowed idx0)
	}
	for _, i0 := range cases {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = i0
			idx1[j] = uint32(j) // vary idx1 across lanes to avoid degenerate
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
		for j := 0; j < 8; j++ {
			e0, e1, e2 := refTriple48(i0, uint32(j))
			if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
				t.Fatalf("i0=%d lane=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
					i0, j, out[0][j], out[1][j], out[2][j], e0, e1, e2)
			}
		}
	}
}

// TestRankToMaskTripleUnrank48AVX2Boundary is the AVX2-arm mirror of
// TestRankToMaskTripleUnrank48Boundary: (idx0, idx1) corner values
// across all 8 lanes, stressing the row lookup at every p and the
// krem == 16 wrap path at loop entry.
func TestRankToMaskTripleUnrank48AVX2Boundary(t *testing.T) {
	defer forceAVX2RankMask(t)()
	const A = uint64(2254848913647)
	const B = uint32(601080390)
	i0s := []uint64{0, 1, A / 2, A - 2, A - 1}
	i1s := []uint32{0, 1, B / 2, B - 2, B - 1}
	for _, v0 := range i0s {
		for _, v1 := range i1s {
			var idx0 [8]uint64
			var idx1 [8]uint32
			for j := 0; j < 8; j++ {
				idx0[j] = v0
				idx1[j] = v1
			}
			var out [3][8]uint64
			RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
			e0, e1, e2 := refTriple48(v0, v1)
			for j := 0; j < 8; j++ {
				if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
					t.Fatalf("v0=%d v1=%d lane=%d: got (%012x, %012x, %012x), want (%012x, %012x, %012x)",
						v0, v1, j, out[0][j], out[1][j], out[2][j], e0, e1, e2)
				}
			}
		}
	}
}

// benchRankIndexBatch yields a fixed random 8-lane (idx0, idx1) batch
// for the rank-unrank kernel benchmarks.
func benchRankIndexBatch() ([8]uint64, [8]uint32) {
	const A = 2254848913647
	const B = 601080390
	rng := rand.New(rand.NewSource(7))
	var idx0 [8]uint64
	var idx1 [8]uint32
	for j := 0; j < 8; j++ {
		idx0[j] = rng.Uint64() % A
		idx1[j] = uint32(rng.Uint64() % B)
	}
	return idx0, idx1
}

// BenchmarkRankToMaskTripleUnrank48AVX512 times the 8-lane ZMM kernel
// per 8-triple batch.
func BenchmarkRankToMaskTripleUnrank48AVX512(b *testing.B) {
	if !HasAVX512RankMask {
		b.Skip("AVX-512F not available")
	}
	idx0, idx1 := benchRankIndexBatch()
	var out [3][8]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RankToMaskTripleUnrank48(&idx0, &idx1, &out)
	}
}

// BenchmarkRankToMaskTripleUnrank48AVX2 times the 4-lane YMM kernel
// (two halves per invocation) per 8-triple batch.
func BenchmarkRankToMaskTripleUnrank48AVX2(b *testing.B) {
	defer forceAVX2RankMask(b)()
	idx0, idx1 := benchRankIndexBatch()
	var out [3][8]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RankToMaskTripleUnrank48AVX2(&idx0, &idx1, &out)
	}
}

// BenchmarkRankToMaskTripleUnrank48Scalar8x times the 8x scalar
// refTriple48 walk — the fallback the batched kernels replace.
func BenchmarkRankToMaskTripleUnrank48Scalar8x(b *testing.B) {
	idx0, idx1 := benchRankIndexBatch()
	var out [3][8]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 8; j++ {
			out[0][j], out[1][j], out[2][j] = refTriple48(idx0[j], idx1[j])
		}
	}
	_ = out
}

//go:noescape
func dumpSIMDRegs(dst *[96]uint64, hasAVX512 bool)

//go:noescape
func dirtySIMDRegForTest(masked uint64)

const (
	interlockResidueGap      = 1 << 10
	interlockResiduePad      = 2 << 10
	interlockResidueWindow   = 16 << 10
	interlockResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
	interlockSIMDWords       = 96
	interlockStackWords      = interlockResidueWindow / 8
	interlockTotalWords      = interlockStackWords + interlockSIMDWords
)

//go:noinline
func interlockResidueGrow(i int) byte {
	var pad [4 * interlockResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
//go:nocheckptr
func interlockResidueProbe(fn func(), res []uint64, regs *[interlockSIMDWords]uint64, hasAVX512 bool) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -interlockResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = interlockResidueSentinel
	}
	interlockResidueDeep(fn, 0, regs, hasAVX512)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func interlockResidueDeep(fn func(), i int, regs *[interlockSIMDWords]uint64, hasAVX512 bool) byte {
	var pad [interlockResiduePad]byte
	pad[i] = 1
	dumpSIMDRegs(regs, hasAVX512)
	fn()
	dumpSIMDRegs(regs, hasAVX512)
	return pad[(i+7)%len(pad)]
}

//go:noinline
func captureInterlockFrameAndRegResidue(call func(), dst *[interlockTotalWords]uint64, hasAVX512 bool) int {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	done := make(chan struct{})
	go func() {
		defer close(done)
		interlockResidueGrow(0)
		var simd [interlockSIMDWords]uint64
		interlockResidueProbe(call, dst[:interlockStackWords], &simd, hasAVX512)
		copy(dst[interlockStackWords:], simd[:])
	}()
	<-done
	written := 0
	for i := 0; i < interlockStackWords; i++ {
		if dst[i] != interlockResidueSentinel {
			written++
		}
	}
	return written
}

var interlockSink uint64

//go:noinline
func leakyInterlockFrame(secret uint64, i int) {
	var frame [64]uint64
	for j := range frame {
		frame[j] = secret
	}
	interlockSink = frame[(i+1)%len(frame)]
}

func scanForInterlockWords(window *[interlockTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i, w := range window {
		if w == 0 || (i < interlockStackWords && w == interlockResidueSentinel) {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func scanForInterlockWordsInStack(window *[interlockTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := 0; i < interlockStackWords; i++ {
		w := window[i]
		if w == 0 || w == interlockResidueSentinel {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func scanForInterlockWordsInRegs(window *[interlockTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := interlockStackWords; i < len(window); i++ {
		w := window[i]
		if w == 0 {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	res := new([interlockTotalWords]uint64)

	t.Run("NegativeControl_Stack", func(t *testing.T) {
		const canary = uint64(0xCAFEBABE13579BDF)
		idx := 3
		written := captureInterlockFrameAndRegResidue(func() {
			leakyInterlockFrame(canary, idx)
		}, res, cpuid.AVX512F)
		runtime.KeepAlive(interlockSink)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForInterlockWordsInStack(res, []uint64{canary}); !found {
			t.Fatal("negative control failed: stack canary written to callee frame was not observed in stack window")
		}
	})

	t.Run("NegativeControl_SIMDAndGPR", func(t *testing.T) {
		const mask = uint64(0x5555555555555555)
		const secret = uint64(0xFEEDFACECAFEBEEF)
		masked := secret ^ mask
		written := captureInterlockFrameAndRegResidue(func() {
			dirtySIMDRegForTest(masked)
		}, res, cpuid.AVX512F)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForInterlockWordsInRegs(res, []uint64{secret}); !found {
			t.Fatal("negative control failed: register canary left in X2/R12 was not observed by post-RET register dump")
		}
	})

	if HasBMI2 {
		t.Run("Chunk48Lock_And_Unchunk48Lock", func(t *testing.T) {
			rng := rand.New(rand.NewSource(99))
			const domain uint64 = 0x0000_FFFF_FFFF_FFFF
			x := (rng.Uint64() & domain) | 0x0000_8000_0000_0001
			m0, m1, m2 := randomTripleMask(rng)
			var l0, l1, l2, back uint64
			if w := captureInterlockFrameAndRegResidue(func() {
				l0, l1, l2 = Chunk48Lock(x, m0, m1, m2)
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("Chunk48Lock: probe missed stack window")
			}
			if word, off, found := scanForInterlockWordsInRegs(res, []uint64{x, m0, m1, m2}); found {
				t.Fatalf("Chunk48Lock leaked word %#016x in register snapshot at offset %d", word, off)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				back = Unchunk48Lock(l0, l1, l2, m0, m1, m2) ^ 1
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("Unchunk48Lock: probe missed stack window")
			}
			back ^= 1
			if back != x {
				t.Fatalf("Unchunk48Lock round-trip mismatch: got %#x, want %#x", back, x)
			}
			if word, off, found := scanForInterlockWordsInRegs(res, []uint64{x, m0, m1, m2}); found {
				t.Fatalf("Unchunk48Lock leaked word %#016x in register snapshot at offset %d", word, off)
			}
		})

		t.Run("Chunk48LockBatch_And_Unchunk48LockBatch", func(t *testing.T) {
			rng := rand.New(rand.NewSource(101))
			const n = 8
			src := make([]byte, 6*n)
			dst := make([]byte, 6*n)
			p0 := make([]byte, 2*n)
			p1 := make([]byte, 2*n)
			p2 := make([]byte, 2*n)
			masks := make([][3]uint64, n)
			var targets []uint64
			for j := 0; j < n; j++ {
				for b := 0; b < 6; b++ {
					src[6*j+b] = byte(rng.Uint32() | 1)
				}
				xw := uint64(src[6*j]) | uint64(src[6*j+1])<<8 | uint64(src[6*j+2])<<16 |
					uint64(src[6*j+3])<<24 | uint64(src[6*j+4])<<32 | uint64(src[6*j+5])<<40
				m0, m1, m2 := randomTripleMask(rng)
				masks[j] = [3]uint64{m0, m1, m2}
				targets = append(targets, xw, m0, m1, m2)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				chunk48LockBatch(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("chunk48LockBatch: probe missed stack window")
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("chunk48LockBatch leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				unchunk48LockBatch(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("unchunk48LockBatch: probe missed stack window")
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("unchunk48LockBatch leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})

		t.Run("Chunk168Lock_And_Unchunk168Lock", func(t *testing.T) {
			rng := rand.New(rand.NewSource(201))
			var src, back [21]byte
			for i := range src {
				src[i] = byte(rng.Uint32() | 1)
			}
			var x0, x1, x2 uint64
			for i := 0; i < 8; i++ {
				x0 |= uint64(src[i]) << (8 * i)
				x1 |= uint64(src[8+i]) << (8 * i)
			}
			for i := 0; i < 5; i++ {
				x2 |= uint64(src[16+i]) << (8 * i)
			}
			m0, m1, m2 := randomTripleMask168(rng)
			var out [3][7]byte
			if w := captureInterlockFrameAndRegResidue(func() {
				Chunk168Lock(&src, m0, m1, m2, &out)
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("Chunk168Lock: probe missed stack window")
			}
			var l0, l1, l2 uint64
			for i := 0; i < 7; i++ {
				l0 |= uint64(out[0][i]) << (8 * i)
				l1 |= uint64(out[1][i]) << (8 * i)
				l2 |= uint64(out[2][i]) << (8 * i)
			}
			targets := []uint64{
				x0, x1, x2,
				l0, l1, l2,
				m0[0], m0[1], m0[2],
				m1[0], m1[1], m1[2],
				m2[0], m2[1], m2[2],
			}
			if word, off, found := scanForInterlockWords(res, []uint64{x0, x1, x2, l0, l1, l2}); found {
				t.Fatalf("Chunk168Lock leaked chunk/lane word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
			if word, off, found := scanForInterlockWordsInRegs(res, targets); found {
				t.Fatalf("Chunk168Lock leaked word %#016x in register snapshot at offset %d", word, off)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				Unchunk168Lock(&out[0], &out[1], &out[2], m0, m1, m2, &back)
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("Unchunk168Lock: probe missed stack window")
			}
			if back != src {
				t.Fatalf("Unchunk168Lock round-trip mismatch: got %x, want %x", back, src)
			}
			if word, off, found := scanForInterlockWords(res, []uint64{x0, x1, x2, l0, l1, l2}); found {
				t.Fatalf("Unchunk168Lock leaked chunk/lane word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
			if word, off, found := scanForInterlockWordsInRegs(res, targets); found {
				t.Fatalf("Unchunk168Lock leaked word %#016x in register snapshot at offset %d", word, off)
			}
		})

		t.Run("Chunk168LockBatch_And_Unchunk168LockBatch", func(t *testing.T) {
			rng := rand.New(rand.NewSource(202))
			const n = 8
			src := make([]byte, 21*n)
			dst := make([]byte, 21*n)
			p0 := make([]byte, 7*n)
			p1 := make([]byte, 7*n)
			p2 := make([]byte, 7*n)
			masks := make([][3][3]uint64, n)
			var targets []uint64
			for j := 0; j < n; j++ {
				for b := 0; b < 21; b++ {
					src[21*j+b] = byte(rng.Uint32() | 1)
				}
				var x0, x1, x2 uint64
				for i := 0; i < 8; i++ {
					x0 |= uint64(src[21*j+i]) << (8 * i)
					x1 |= uint64(src[21*j+8+i]) << (8 * i)
				}
				for i := 0; i < 5; i++ {
					x2 |= uint64(src[21*j+16+i]) << (8 * i)
				}
				m0, m1, m2 := randomTripleMask168(rng)
				masks[j] = [3][3]uint64{m0, m1, m2}
				targets = append(targets,
					x0, x1, x2,
					m0[0], m0[1], m0[2],
					m1[0], m1[1], m1[2],
					m2[0], m2[1], m2[2],
				)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				chunk168LockBatch(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("chunk168LockBatch: probe missed stack window")
			}
			for j := 0; j < n; j++ {
				var l0, l1, l2 uint64
				for i := 0; i < 7; i++ {
					l0 |= uint64(p0[7*j+i]) << (8 * i)
					l1 |= uint64(p1[7*j+i]) << (8 * i)
					l2 |= uint64(p2[7*j+i]) << (8 * i)
				}
				targets = append(targets, l0, l1, l2)
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("chunk168LockBatch leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				unchunk168LockBatch(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
			}, res, cpuid.AVX512F); w == 0 {
				t.Fatal("unchunk168LockBatch: probe missed stack window")
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("unchunk168LockBatch leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})
	}

	if cpuid.AVX2 && cpuid.BMI2 {
		t.Run("RankToMaskTripleUnrank48AVX2", func(t *testing.T) {
			defer forceAVX2RankMask(t)()
			rng := rand.New(rand.NewSource(102))
			const A = 2254848913647
			const B = 601080390
			idx0 := new([8]uint64)
			idx1 := new([8]uint32)
			out := new([3][8]uint64)
			for j := 0; j < 8; j++ {
				idx0[j] = (rng.Uint64() % (A - 256)) + 256
				idx1[j] = uint32((rng.Uint64() % (B - 256)) + 256)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				RankToMaskTripleUnrank48AVX2(idx0, idx1, out)
			}, res, false); w == 0 {
				t.Fatal("RankToMaskTripleUnrank48AVX2: probe missed stack window")
			}
			var targets []uint64
			for j := 0; j < 8; j++ {
				targets = append(targets, idx0[j], out[0][j], out[1][j], out[2][j])
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("RankToMaskTripleUnrank48AVX2 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})

		t.Run("RankToMaskTripleUnrank168AVX2", func(t *testing.T) {
			defer forceAVX2RankMask(t)()
			rng := rand.New(rand.NewSource(203))
			idx0 := new([3][8]uint64)
			idx1 := new([2][8]uint64)
			out := new([3][3][8]uint64)
			for j := 0; j < 8; j++ {
				v0 := randomIdx0_168(rng)
				v1 := randomIdx1_168(rng)
				idx0[0][j] = v0[0]
				idx0[1][j] = v0[1]
				idx0[2][j] = v0[2]
				idx1[0][j] = v1[0]
				idx1[1][j] = v1[1]
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				RankToMaskTripleUnrank168AVX2(idx0, idx1, out)
			}, res, false); w == 0 {
				t.Fatal("RankToMaskTripleUnrank168AVX2: probe missed stack window")
			}
			const dom2 = (uint64(1) << 40) - 1
			var targets []uint64
			for j := 0; j < 8; j++ {
				m1Local := refUnrank168([3]uint64{idx1[0][j], idx1[1][j], 0}, 56, 112)
				targets = append(targets,
					idx0[0][j], idx0[1][j], idx0[2][j],
					idx1[0][j], idx1[1][j],
					m1Local[0], m1Local[1],
					^out[0][0][j], ^out[0][1][j], (^out[0][2][j])&dom2,
					out[0][0][j], out[0][1][j], out[0][2][j],
					out[1][0][j], out[1][1][j], out[1][2][j],
					out[2][0][j], out[2][1][j], out[2][2][j],
				)
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("RankToMaskTripleUnrank168AVX2 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})
	}

	if HasAVX512RankMask {
		t.Run("RankToMaskTripleUnrank48AVX512", func(t *testing.T) {
			rng := rand.New(rand.NewSource(103))
			const A = 2254848913647
			const B = 601080390
			idx0 := new([8]uint64)
			idx1 := new([8]uint32)
			out := new([3][8]uint64)
			for j := 0; j < 8; j++ {
				idx0[j] = (rng.Uint64() % (A - 256)) + 256
				idx1[j] = uint32((rng.Uint64() % (B - 256)) + 256)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				RankToMaskTripleUnrank48(idx0, idx1, out)
			}, res, true); w == 0 {
				t.Fatal("RankToMaskTripleUnrank48: probe missed stack window")
			}
			var targets []uint64
			for j := 0; j < 8; j++ {
				targets = append(targets, idx0[j], out[0][j], out[1][j], out[2][j])
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("RankToMaskTripleUnrank48 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})

		t.Run("RankToMaskTripleUnrank48x16AVX512", func(t *testing.T) {
			rng := rand.New(rand.NewSource(104))
			const A = 2254848913647
			const B = 601080390
			idx0 := new([16]uint64)
			idx1 := new([16]uint32)
			out := new([3][16]uint64)
			for j := 0; j < 16; j++ {
				idx0[j] = (rng.Uint64() % (A - 256)) + 256
				idx1[j] = uint32((rng.Uint64() % (B - 256)) + 256)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				RankToMaskTripleUnrank48x16(idx0, idx1, out)
			}, res, true); w == 0 {
				t.Fatal("RankToMaskTripleUnrank48x16: probe missed stack window")
			}
			var targets []uint64
			for j := 0; j < 16; j++ {
				targets = append(targets, idx0[j], out[0][j], out[1][j], out[2][j])
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("RankToMaskTripleUnrank48x16 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})

		t.Run("RankToMaskTripleUnrank168AVX512", func(t *testing.T) {
			rng := rand.New(rand.NewSource(204))
			idx0 := new([3][8]uint64)
			idx1 := new([2][8]uint64)
			out := new([3][3][8]uint64)
			for j := 0; j < 8; j++ {
				v0 := randomIdx0_168(rng)
				v1 := randomIdx1_168(rng)
				idx0[0][j] = v0[0]
				idx0[1][j] = v0[1]
				idx0[2][j] = v0[2]
				idx1[0][j] = v1[0]
				idx1[1][j] = v1[1]
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				RankToMaskTripleUnrank168(idx0, idx1, out)
			}, res, true); w == 0 {
				t.Fatal("RankToMaskTripleUnrank168: probe missed stack window")
			}
			const dom2 = (uint64(1) << 40) - 1
			var targets []uint64
			for j := 0; j < 8; j++ {
				m1Local := refUnrank168([3]uint64{idx1[0][j], idx1[1][j], 0}, 56, 112)
				targets = append(targets,
					idx0[0][j], idx0[1][j], idx0[2][j],
					idx1[0][j], idx1[1][j],
					m1Local[0], m1Local[1],
					^out[0][0][j], ^out[0][1][j], (^out[0][2][j])&dom2,
					out[0][0][j], out[0][1][j], out[0][2][j],
					out[1][0][j], out[1][1][j], out[1][2][j],
					out[2][0][j], out[2][1][j], out[2][2][j],
				)
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("RankToMaskTripleUnrank168 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})
	}
}
