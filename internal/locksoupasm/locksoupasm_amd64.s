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
