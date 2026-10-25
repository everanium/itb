//go:build arm64 && !purego && !noitbasm

package interlock

import "math/bits"

// crow168Table holds the 3-limb little-endian binomial coefficients
// C(n, k) for n in [0..168] and k in [0..56]. It serves as the init
// source for the kernel-facing [crow168PackedNEON] table and as the
// canonical oracle for parity tests in this package.
var crow168Table [169][57][3]uint64

func init() {
	var c [169][57][3]uint64
	for n := 0; n <= 168; n++ {
		c[n][0] = [3]uint64{1, 0, 0}
		for k := 1; k <= 56 && k <= n; k++ {
			lo, c0 := bits.Add64(c[n-1][k-1][0], c[n-1][k][0], 0)
			mid, c1 := bits.Add64(c[n-1][k-1][1], c[n-1][k][1], c0)
			hi, _ := bits.Add64(c[n-1][k-1][2], c[n-1][k][2], c1)
			c[n][k] = [3]uint64{lo, mid, hi}
		}
	}
	crow168Table = c
}

// crow168PackedNEON is the tiered binomial table repacked in descending
// position order (p = 167..0, 303 limb-rows of 64 uint64 = 155,136 bytes)
// for the NEON kernel's two-half byte-index VTBX gather:
//   - p = 167..134 (34 steps, 3 limbs lo, mid, hi = 102 rows, rows 0..101)
//   - p = 133..67  (67 steps, 2 limbs lo, mid     = 134 rows, rows 102..235;
//     p = 111 for m1Local starts at row 146, byte offset 74,752)
//   - p = 66..0    (67 steps, 1 limb  lo          = 67 rows,  rows 236..302)
//
// Within each 64-qword limb row, slot s (s = 0..55) is indexed by
// picked = 56 - krem and holds C(p, 56 - s)[limb] (0 when 56 - s > p);
// slots 56..63 hold ^uint64(0). When krem == 0 (picked == 56), the
// second-half VTBX byte index (56 - 32)*8 + {0..7} = 192..199 falls
// outside the 3-window (192-byte) second half W4..W6, preserving the
// 0xFF sentinel pre-loaded into C_hi so rem >= UINT64_MAX evaluates to
// false automatically.
var crow168PackedNEON [303][64]uint64

func init() {
	fillRow := func(dst *[64]uint64, pos, limb int) {
		for s := 0; s < 56; s++ {
			dst[s] = crow168Table[pos][56-s][limb]
		}
		for s := 56; s < 64; s++ {
			dst[s] = ^uint64(0)
		}
	}

	row := 0
	for pos := 167; pos >= 134; pos-- {
		fillRow(&crow168PackedNEON[row], pos, 0)
		fillRow(&crow168PackedNEON[row+1], pos, 1)
		fillRow(&crow168PackedNEON[row+2], pos, 2)
		row += 3
	}
	for pos := 133; pos >= 67; pos-- {
		fillRow(&crow168PackedNEON[row], pos, 0)
		fillRow(&crow168PackedNEON[row+1], pos, 1)
		row += 2
	}
	for pos := 66; pos >= 0; pos-- {
		fillRow(&crow168PackedNEON[row], pos, 0)
		row++
	}
}

// RankToMaskTripleUnrank168NEON derives 8 balanced (m0, m1, m2) 168-bit
// mask triples from 8 precomputed combinadic index pairs — the same
// contract as the amd64 [RankToMaskTripleUnrank168] — via the NEON
// batched kernel. Caller gates on [HasNEONInterlock].
//
// Constant-time: row addresses depend only on the public descending
// position p; the secret per-lane picked count is consumed by
// register-only two-half VTBX gathers and VCMHS predicates, and the
// remap stage executes a fixed 168-step vector deposit walk.
func RankToMaskTripleUnrank168NEON(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64) {
	rankToMaskTripleUnrank168NEON(idx0, idx1, &crow168PackedNEON, out)
}

//go:noescape
func rankToMaskTripleUnrank168NEON(idx0 *[3][8]uint64, idx1 *[2][8]uint64, crow *[303][64]uint64, out *[3][3][8]uint64)
