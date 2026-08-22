//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"math/rand"
	"testing"
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
// mask-merge broadcast path for the 17-th row entry (index 16 exceeds
// VPERMI2Q's two-source 16-lane range and falls through to a scalar
// VPBROADCASTQ under mask K5 == "krem == 16"). krem == 16 is only
// possible on the sequence of iterations before the first bit is set
// (each success decrements krem), so this test constructs (idx0, idx1)
// values that keep krem == 16 for several iterations at loop entry,
// making the C(p, 16) lookup load-bearing.
//
// For the m0 loop (p=47..0, krem starts at 16):
//   * idx0 in [0, C(47,16)): first iteration doesn't set bit 47, so
//     krem stays 16 for p=46, 45, ... until either idx0 crosses
//     C(p,16) or the whole loop exhausts.
//   * idx0 = C(47,16) - 1: iteration at p=47 sees rank < C(47,16)
//     (krem=16 path executes, no pick). Then p=46, still krem=16,
//     etc.
//   * idx0 = C(47,16): iteration at p=47 picks (mask-merge value
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
	// that VPERMI2Q cannot reach and the mask-merge broadcast must supply.
	// Explicit literal calls to crow48Table anchor the test against the
	// live table.
	//
	// For each spillover position p, exercise all three boundary ranks:
	//   C(p,16) - 1 (branch not taken → krem stays 16)
	//   C(p,16)     (branch taken exactly at the boundary → krem drops)
	//   C(p,16) + 1 (branch taken above the boundary → krem drops)
	// This forces both K5-broadcast-with-no-pick and K5-broadcast-with-pick
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
