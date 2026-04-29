//go:build amd64 && !purego

#include "textflag.h"

// func Chunk24Lock(x, m0, m1, m2 uint32) (l0, l1, l2 uint32)
//
// Frame layout (ABI0, all uint32 = 4 bytes):
//   x   at FP+0
//   m0  at FP+4
//   m1  at FP+8
//   m2  at FP+12
//   l0  at FP+16  (return)
//   l1  at FP+20  (return)
//   l2  at FP+24  (return)
//
// Three BMI2 PEXTL instructions extract the lane bytes by mask. Each
// PEXT compresses x's bits selected by mask_i into a contiguous low
// byte. Since each mask has popcount 8, the result fits in 8 bits;
// the upper bits of the 32-bit output are zero. Caller takes byte().
TEXT ·Chunk24Lock(SB),NOSPLIT,$0-28
	MOVL x+0(FP), AX
	MOVL m0+4(FP), BX
	PEXTL BX, AX, CX
	MOVL CX, l0+16(FP)
	MOVL m1+8(FP), BX
	PEXTL BX, AX, CX
	MOVL CX, l1+20(FP)
	MOVL m2+12(FP), BX
	PEXTL BX, AX, CX
	MOVL CX, l2+24(FP)
	RET

// func Unchunk24Lock(l0, l1, l2, m0, m1, m2 uint32) (x uint32)
//
// Frame layout (ABI0, all uint32 = 4 bytes):
//   l0  at FP+0
//   l1  at FP+4
//   l2  at FP+8
//   m0  at FP+12
//   m1  at FP+16
//   m2  at FP+20
//   x   at FP+24  (return)
//
// Three PDEPL instructions expand each lane byte's bits into the
// 24-bit positions selected by mask_i; the three results are disjoint
// (m0|m1|m2 covers all 24 bits with no overlap), so OR-ing them
// reconstructs x.
TEXT ·Unchunk24Lock(SB),NOSPLIT,$0-28
	MOVL l0+0(FP), AX
	MOVL m0+12(FP), BX
	PDEPL BX, AX, R8
	MOVL l1+4(FP), AX
	MOVL m1+16(FP), BX
	PDEPL BX, AX, R9
	ORL R9, R8
	MOVL l2+8(FP), AX
	MOVL m2+20(FP), BX
	PDEPL BX, AX, R9
	ORL R9, R8
	MOVL R8, x+24(FP)
	RET

// func Permute24Avx512(x uint32, perm *[32]byte) (y uint32)
//
// Frame layout (ABI0):
//   x    at FP+0   (uint32, 4 bytes)
//   perm at FP+8   (pointer, 8 bytes; +4 padding for 8-byte alignment)
//   y    at FP+16  (uint32, 4 bytes return)
//
// Total arg+ret span is 20 bytes; declared frame is 24 to satisfy
// 8-byte alignment of the call's stack argument area (matches the
// existing $0-24 patterns used elsewhere in the codebase).
//
// Approach (AVX-512 VBMI bit-spread + VPERMB + bit-pack):
//   Step 1: KMOVD AX → K1 spreads x's low 24 bits across mask register.
//   Step 2: VPMOVM2B K1 → Y0 produces -1/0 per byte (24 active bytes,
//           upper 8 of YMM zero by AVX-512VL semantics).
//   Step 3: VPABSB Y0 → Y0 collapses -1/0 to 1/0 per byte.
//   Step 4: VMOVDQU loads perm[0..31] into Y1.
//   Step 5: VPERMB Y0 (table), Y1 (idx) → Y2, where Y2[i] = Y0[Y1[i]&63].
//           For i in 0..23 this gathers bit perm[i] of x into byte i of Y2.
//   Step 6: VPTESTMB Y2 → K2 sets a mask bit per nonzero byte of Y2.
//   Step 7: KMOVD K2 → AX, masked to 24 bits (the high bytes of Y2 may
//           hold gather artifacts from perm[24..31]; the AND clears them).
//
// VZEROUPPER on exit per Go convention to keep upper YMM/ZMM state
// from polluting downstream non-AVX code.
TEXT ·Permute24Avx512(SB),NOSPLIT,$0-24
	MOVL    x+0(FP), AX            // AX = x
	ANDL    $0x00FFFFFF, AX        // mask to low 24 bits (defensive)
	MOVQ    perm+8(FP), DX         // DX = &perm[0]

	KMOVD   AX, K1                 // K1 = bit-mask of x
	VPMOVM2B K1, Y0                // Y0 byte = -1 / 0 per K1 bit
	VPABSB  Y0, Y0                 // Y0 byte = 1 / 0

	VMOVDQU (DX), Y1               // Y1 = perm[0..31]
	VPERMB  Y0, Y1, Y2             // Y2[i] = Y0[Y1[i] & 0x3F]
	VPTESTMB Y2, Y2, K2            // K2[i] = (Y2[i] != 0)

	KMOVD   K2, AX                 // AX = K2 low 32 bits
	ANDL    $0x00FFFFFF, AX        // mask to low 24 bits

	MOVL    AX, ret+16(FP)
	VZEROUPPER
	RET
