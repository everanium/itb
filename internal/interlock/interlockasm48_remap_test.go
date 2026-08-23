//go:build amd64 && !purego && !noitbasm

package interlock

import "testing"

// remapBitSerial48 is the bit-serial reference for the kernel's remap
// stage: walk the 48 domain positions in ascending order, and at every
// position where remaining (= domain & ^m0) has a set bit, deposit the
// next bit of m1Local. Equivalent to m1 = PDEP(m1Local, remaining);
// kept in this bit-serial form so the asm kernel's scalar-PDEPQ remap
// is asserted against an independent formulation of the same walk.
func remapBitSerial48(m0, m1Local uint64) (m1, m2 uint64) {
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

// TestRankToMaskTripleUnrank48RemapFixedVectors pins the kernel's remap
// stage bit-exactly against [remapBitSerial48] on a fixed vector of
// per-lane (idx0, idx1) pairs — every lane distinct, covering the rank
// extremes and mid-range values. The unrank halves are reproduced via
// refUnrank48 so any divergence isolates to the remap.
func TestRankToMaskTripleUnrank48RemapFixedVectors(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F not available")
	}
	const A = uint64(2254848913647) // C(48, 16)
	const B = uint64(601080390)     // C(32, 16)

	idx0 := [8]uint64{0, 1, A / 7, A / 3, A / 2, 2 * A / 3, A - 2, A - 1}
	idx1 := [8]uint32{uint32(B - 1), uint32(B / 2), 0, 1, uint32(B / 5),
		uint32(2 * B / 3), uint32(B - 2), uint32(B / 9)}

	var out [3][8]uint64
	RankToMaskTripleUnrank48(&idx0, &idx1, &out)

	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for j := 0; j < 8; j++ {
		m0 := refUnrank48(idx0[j], 16, 48)
		m1Local := refUnrank48(uint64(idx1[j]), 16, 32)
		wantM1, wantM2 := remapBitSerial48(m0, m1Local)
		if out[0][j] != m0 {
			t.Fatalf("lane=%d idx0=%d: m0 %012x, want %012x", j, idx0[j], out[0][j], m0)
		}
		if out[1][j] != wantM1 || out[2][j] != wantM2 {
			t.Fatalf("lane=%d idx0=%d idx1=%d: remap (m1=%012x, m2=%012x), want (%012x, %012x)",
				j, idx0[j], idx1[j], out[1][j], out[2][j], wantM1, wantM2)
		}
		// Structural invariants of the triple.
		if out[0][j]|out[1][j]|out[2][j] != domain {
			t.Fatalf("lane=%d: union %012x != domain", j, out[0][j]|out[1][j]|out[2][j])
		}
		if out[0][j]&out[1][j] != 0 || out[0][j]&out[2][j] != 0 || out[1][j]&out[2][j] != 0 {
			t.Fatalf("lane=%d: masks not pairwise disjoint", j)
		}
	}
}
