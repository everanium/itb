//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func Chunk48Lock(x, m0, m1, m2 uint64) (l0, l1, l2 uint64)
//
// Frame layout (ABI0, all uint64 = 8 bytes):
//   x   at FP+0
//   m0  at FP+8
//   m1  at FP+16
//   m2  at FP+24
//   l0  at FP+32  (return)
//   l1  at FP+40  (return)
//   l2  at FP+48  (return)
//
// Three BMI2 PEXTQ instructions extract the lane values by mask. Each
// PEXT compresses x's bits selected by mask_i into a contiguous low
// segment. Since each mask has popcount 16, the result fits in 16 bits;
// the upper bits of the 64-bit output are zero. Caller takes uint16().
TEXT ·Chunk48Lock(SB),NOSPLIT,$0-56
	MOVQ x+0(FP), AX
	MOVQ m0+8(FP), BX
	PEXTQ BX, AX, CX
	MOVQ CX, l0+32(FP)
	MOVQ m1+16(FP), BX
	PEXTQ BX, AX, CX
	MOVQ CX, l1+40(FP)
	MOVQ m2+24(FP), BX
	PEXTQ BX, AX, CX
	MOVQ CX, l2+48(FP)
	RET

// func Unchunk48Lock(l0, l1, l2, m0, m1, m2 uint64) (x uint64)
//
// Frame layout (ABI0, all uint64 = 8 bytes):
//   l0  at FP+0
//   l1  at FP+8
//   l2  at FP+16
//   m0  at FP+24
//   m1  at FP+32
//   m2  at FP+40
//   x   at FP+48  (return)
//
// Three PDEPQ instructions expand each 16-bit lane value's bits into
// the 48-bit positions selected by mask_i; the three results are
// disjoint (m0|m1|m2 covers all 48 bits with no overlap), so OR-ing
// them reconstructs x. Upper 16 bits of the returned uint64 are zero.
TEXT ·Unchunk48Lock(SB),NOSPLIT,$0-56
	MOVQ l0+0(FP), AX
	MOVQ m0+24(FP), BX
	PDEPQ BX, AX, R8
	MOVQ l1+8(FP), AX
	MOVQ m1+32(FP), BX
	PDEPQ BX, AX, R9
	ORQ R9, R8
	MOVQ l2+16(FP), AX
	MOVQ m2+40(FP), BX
	PDEPQ BX, AX, R9
	ORQ R9, R8
	MOVQ R8, x+48(FP)
	RET

// func rankToMaskTripleUnrank48AVX512(idx0 *[8]uint64, idx1 *[8]uint32,
//                                     crow *[49][17]uint64, out *[3][8]uint64)
//
// Lane-parallel combinatorial-number-system unrank for 8 lanes on qwords
// (all 8 ZMM qword lanes carry payload). Mirrors the bit-exact Go
// reference in the parent package: two unranks (16-of-48 from idx0,
// 16-of-32 from idx1) plus the remap onto the bits m0 leaves free.
//
// Row lookup: per descending position p, c = C(p, krem) is selected by
// loading two ZMM halves of the 17-entry row (Z3 = C(p, 0..7), Z4 =
// C(p, 8..15)) and combining via VPERMI2Q with per-lane index krem & 15.
// The 17-th entry C(p, 16) is fetched as a scalar and broadcast into
// lanes where krem == 16 via a masked VPBROADCASTQ. The pick is applied
// via mask registers throughout — neither memory access nor control flow
// depends on secret indices — constant-time.
//
// Frame: 4 pointer args = 32 bytes.
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)
TEXT ·rankToMaskTripleUnrank48AVX512(SB), NOSPLIT, $0-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	// Global broadcast constants.
	MOVQ $1, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z6            // Z6 = 1 (per qword lane)
	MOVQ $16, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z28           // Z28 = 16 (krem == 16 comparator)
	MOVQ $15, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z29           // Z29 = 15 (VPERMI2Q index mask)

	// ---- unrank m0: rank = idx0, n = 48, k = 16 ----
	VMOVDQU64 (AX), Z0              // Z0 = idx0[0..7]
	VMOVDQA64 Z28, Z1               // Z1 = krem = 16
	VPXORQ Z2, Z2, Z2               // Z2 = mask = 0
	MOVQ $47, R10                   // p = 47

m0Loop:
	// Row byte offset: p * 136 = p * 128 + p * 8.
	MOVQ R10, R11
	SHLQ $7, R11                    // R11 = p * 128
	LEAQ (R11)(R10*8), R11          // R11 = p * 128 + p * 8 = p * 136
	LEAQ (R14)(R11*1), R12          // R12 = &crow[p][0]

	VMOVDQU64 (R12), Z3             // Z3 = crow[p][0..7]
	VMOVDQU64 64(R12), Z4           // Z4 = crow[p][8..15]
	MOVQ 128(R12), R13              // R13 = crow[p][16] (scalar spillover)

	VPANDQ Z29, Z1, Z7              // Z7 = krem & 15 (VPERMI2Q per-lane index)
	VPERMI2Q Z4, Z3, Z7             // Z7 = concat(Z3, Z4)[Z7 & 15] per lane
	//                                  = per-lane C(p, krem) for krem in [0, 15]

	// Mask-merge C(p, 16) into lanes where krem == 16.
	VPCMPEQQ Z28, Z1, K5            // K5 = (krem == 16)
	MOVQ R13, X14
	VPBROADCASTQ X14, K5, Z7        // Z7[K5 lanes] = C(p, 16)

	VPCMPUQ $5, Z7, Z0, K1          // K1 = (rank >= c)
	VPTESTMQ Z1, Z1, K2             // K2 = (krem != 0)
	KANDW K1, K2, K3                // K3 = pick

	MOVQ $1, R8
	MOVQ R10, CX
	SHLQ CX, R8                     // R8 = 1 << p
	MOVQ R8, X14
	VPBROADCASTQ X14, Z5
	VPORQ Z5, Z2, K3, Z2            // mask |= (1<<p) on picked lanes
	VPSUBQ Z7, Z0, K3, Z0           // rank -= c on picked lanes
	VPSUBQ Z6, Z1, K3, Z1           // krem -= 1 on picked lanes

	SUBQ $1, R10
	JGE m0Loop

	VMOVDQA64 Z2, Z10               // Z10 = m0

	// ---- unrank m1Local: rank = idx1, n = 32, k = 16 ----
	// idx1 is *[8]uint32 = 32 bytes; zero-extend to 8 qwords.
	VPMOVZXDQ (BX), Z0
	VMOVDQA64 Z28, Z1               // Z1 = krem = 16
	VPXORQ Z2, Z2, Z2
	MOVQ $31, R10                   // p = 31

m1Loop:
	MOVQ R10, R11
	SHLQ $7, R11
	LEAQ (R11)(R10*8), R11
	LEAQ (R14)(R11*1), R12

	VMOVDQU64 (R12), Z3
	VMOVDQU64 64(R12), Z4
	MOVQ 128(R12), R13

	VPANDQ Z29, Z1, Z7
	VPERMI2Q Z4, Z3, Z7
	VPCMPEQQ Z28, Z1, K5
	MOVQ R13, X14
	VPBROADCASTQ X14, K5, Z7

	VPCMPUQ $5, Z7, Z0, K1
	VPTESTMQ Z1, Z1, K2
	KANDW K1, K2, K3

	MOVQ $1, R8
	MOVQ R10, CX
	SHLQ CX, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z5
	VPORQ Z5, Z2, K3, Z2
	VPSUBQ Z7, Z0, K3, Z0
	VPSUBQ Z6, Z1, K3, Z1

	SUBQ $1, R10
	JGE m1Loop

	VMOVDQA64 Z2, Z11               // Z11 = m1Local

	// ---- remap: deposit m1Local's bits onto positions m0 leaves free ----
	MOVQ $0x0000FFFFFFFFFFFF, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z27           // Z27 = 0xFFFF_FFFF_FFFF (48-bit domain)
	VPANDNQ Z27, Z10, Z0            // Z0 = remaining = (~m0) & domain
	VPXORQ Z12, Z12, Z12            // Z12 = m1 = 0
	VPXORQ Z13, Z13, Z13            // Z13 = posIdx = 0
	XORQ R10, R10                   // bit = 0
	// Remap temporaries use Z16..Z21 (their low halves X16..X21 never
	// serve as scratch), so the shift-count xmm X15 is not clobbered
	// mid-iteration. Z14/Z15 would alias X14/X15 — avoided.

remapLoop:
	MOVQ R10, X15
	VPSRLQ X15, Z0, Z16             // remaining >> bit
	VPANDQ Z6, Z16, Z17             // remBit = (...) & 1
	VPSRLVQ Z13, Z11, Z18           // m1Local >> posIdx (per lane)
	VPANDQ Z6, Z18, Z19             // mlBit = (...) & 1
	VPANDQ Z17, Z19, Z20            // set = remBit & mlBit
	VPSLLQ X15, Z20, Z21            // set << bit
	VPORQ Z21, Z12, Z12             // m1 |= set << bit
	VPADDQ Z17, Z13, Z13            // posIdx += remBit
	INCQ R10
	CMPQ R10, $48
	JLT remapLoop

	VPANDNQ Z0, Z12, Z8             // Z8 = m2 = (~m1) & remaining

	VMOVDQU64 Z10, (DI)             // out[0] = m0
	VMOVDQU64 Z12, 64(DI)           // out[1] = m1
	VMOVDQU64 Z8, 128(DI)           // out[2] = m2
	VZEROUPPER
	RET
