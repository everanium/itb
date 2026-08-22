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
