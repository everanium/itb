//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"math/bits"
	"unsafe"
)

// Chunk168Lock applies the 168-bit interlock keyed bit-permutation to
// a 21-byte chunk in src under three balanced 56-of-168 masks
// (m0, m1, m2) and writes the three 7-byte (56-bit) lane outputs in
// little-endian order into out[0], out[1], and out[2].
//
// Each lane is extracted across the three words (w0, w1, w2) of the
// 168-bit chunk via three BMI2 PEXTQ instructions and stitched using
// POPCNTQ(m[0]) and POPCNTQ(m[1]) shifts. Because each mask has total
// weight 56 < 64 across all three words, neither shift count ever
// reaches 64.
//
// Caller must supply pairwise-disjoint masks of popcount 56 each whose
// union covers the 168-bit domain (w0 = all-ones, w1 = all-ones,
// w2 = 0x0000_00FF_FFFF_FFFF). Caller gates on [HasBMI2].
//
//go:noescape
func Chunk168Lock(src *[21]byte, m0, m1, m2 [3]uint64, out *[3][7]byte)

// Unchunk168Lock is the inverse of [Chunk168Lock]. Given three 7-byte
// (56-bit) lane values in p0, p1, p2 and the same mask triple
// (m0, m1, m2), it deposits each lane's bits back into the three words
// of the 168-bit chunk via BMI2 PDEPQ and writes the reconstructed
// 21-byte chunk in little-endian order to dst. Caller gates on
// [HasBMI2].
//
//go:noescape
func Unchunk168Lock(p0, p1, p2 *[7]byte, m0, m1, m2 [3]uint64, dst *[21]byte)

// crow168Table holds the 3-limb little-endian binomial coefficients
// C(n, k) for n in [0..168] and k in [0..56]. It serves as the init
// source for the kernel-facing [crow168Packed] table and as the
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

// crow168Packed points at a 64-byte-aligned [303][64]uint64 view
// (155,136 bytes) of the tiered binomial rows repacked in descending
// position order (p = 167..0) for direct 64-slot krem indexing:
//   - p = 167..134 (34 steps, 3 limbs lo, mid, hi = 102 rows, rows 0..101)
//   - p = 133..67  (67 steps, 2 limbs lo, mid     = 134 rows, rows 102..235;
//     p = 111 for m1Local starts at row 146, byte offset 74,752)
//   - p = 66..0    (67 steps, 1 limb  lo          = 67 rows,  rows 236..302)
//
// Within each 64-qword limb row:
//   - slot 0      = ^uint64(0) (0xFFFFFFFFFFFFFFFF)
//   - slot k      = C(p, k)[limb] for k = 1..56 (0 when k > p)
//   - slot 57..63 = ^uint64(0) (0xFFFFFFFFFFFFFFFF)
//
// Storing ^uint64(0) in slot 0 ensures that when krem == 0 (all 56
// bits already chosen and running remainder rem == 0), the unsigned
// comparison rem >= C_val evaluates to false (0 >= UINT64_MAX)
// automatically across both the AVX-512 and AVX2 kernels without
// requiring a separate krem != 0 mask instruction. Preserving 0 in
// slots k in [1..56] with k > p ensures that when krem == p + 1 and
// rem == 0, rem >= 0 evaluates to true and selects all remaining bit
// positions.
var crow168Packed *[303][64]uint64

// crow168PackedBacking over-allocates by 8 qwords so init can carve a
// 64-byte-aligned window regardless of the allocator's base alignment.
var crow168PackedBacking [303*64 + 8]uint64

func init() {
	base := uintptr(unsafe.Pointer(&crow168PackedBacking[0]))
	off := ((64 - base%64) % 64) / 8
	p := (*[303][64]uint64)(unsafe.Pointer(&crow168PackedBacking[off]))

	fillRow := func(dst *[64]uint64, pos, limb int) {
		dst[0] = ^uint64(0)
		for k := 1; k <= 56; k++ {
			dst[k] = crow168Table[pos][k][limb]
		}
		for k := 57; k < 64; k++ {
			dst[k] = ^uint64(0)
		}
	}

	row := 0
	for pos := 167; pos >= 134; pos-- {
		fillRow(&p[row], pos, 0)
		fillRow(&p[row+1], pos, 1)
		fillRow(&p[row+2], pos, 2)
		row += 3
	}
	for pos := 133; pos >= 67; pos-- {
		fillRow(&p[row], pos, 0)
		fillRow(&p[row+1], pos, 1)
		row += 2
	}
	for pos := 66; pos >= 0; pos-- {
		fillRow(&p[row], pos, 0)
		row++
	}
	crow168Packed = p
}

// RankToMaskTripleUnrank168 derives 8 balanced (m0, m1, m2) 168-bit
// mask triples in parallel from 8 precomputed combinadic index pairs
// stored in Structure-of-Arrays (SoA) layout:
//   - idx0[0..2][j] holds the 3 little-endian limbs of lane j's first
//     combinadic index in [0, C(168, 56))
//   - idx1[0..1][j] holds the 2 little-endian limbs of lane j's second
//     combinadic index in [0, C(112, 56))
//   - out[lane][word][j] receives word in 0..2 of mask m_{lane} for
//     chunk j in 0..7.
//
// Constant-time: row addresses depend only on the public descending
// position p; C(p, krem) is selected across the 4-window row via
// register-only VPERMT2Q + VPBLENDMQ instructions, and the remap tail
// uses fixed-latency BMI2 PDEPQ and arithmetic shifts. Caller gates on
// [HasAVX512RankMask].
func RankToMaskTripleUnrank168(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64) {
	rankToMaskTripleUnrank168AVX512(idx0, idx1, crow168Packed, out)
}

//go:noescape
func rankToMaskTripleUnrank168AVX512(idx0 *[3][8]uint64, idx1 *[2][8]uint64, crow *[303][64]uint64, out *[3][3][8]uint64)

// RankToMaskTripleUnrank168AVX2 derives 8 balanced (m0, m1, m2) 168-bit
// mask triples from 8 precomputed combinadic index pairs — the same
// contract as [RankToMaskTripleUnrank168] — via the AVX2 4-lane batched
// kernel (two YMM halves per invocation). Caller gates on
// [HasAVX2RankMask].
func RankToMaskTripleUnrank168AVX2(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64) {
	rankToMaskTripleUnrank168AVX2(idx0, idx1, crow168Packed, out)
}

//go:noescape
func rankToMaskTripleUnrank168AVX2(idx0 *[3][8]uint64, idx1 *[2][8]uint64, crow *[303][64]uint64, out *[3][3][8]uint64)
