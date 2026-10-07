//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX)
// AES-ITB noise filler kernel, eight blocks per iteration. Block j of
// the run is the folded schedule of noisefill.go applied to counter
// (lo + j, hi): the counter base plus the increment table entry j,
// one XOR with the pre-whitening block C, five VAESENC rounds under
// RK[0..4], one 16-byte store. The eight blocks are independent AES
// chains, so the eight VAESENC of a round issue back to back. See
// noisefill.go for the construction and the in-package parity tests
// for the bit-exact pin against the pure-Go sponge.
//
// Register allocation:
//   X0..X7   the eight block states
//   X8       counter base [lo, hi], advanced by eight per iteration
//   X9       C (pre-whitening)
//   X10..X14 RK[0..4]
//   X15      increment [8, 0]
//
// Frame: none. VZEROALL before RET wipes every state, the counter and
// the schedule from the register file.

#include "textflag.h"

#define ROUND8(RK) \
	VAESENC RK, X0, X0; \
	VAESENC RK, X1, X1; \
	VAESENC RK, X2, X2; \
	VAESENC RK, X3, X3; \
	VAESENC RK, X4, X4; \
	VAESENC RK, X5, X5; \
	VAESENC RK, X6, X6; \
	VAESENC RK, X7, X7

// func noiseFillX8VexAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
TEXT ·noiseFillX8VexAsm(SB), NOSPLIT, $0-40
	MOVQ sched+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ nblk+16(FP), CX
	MOVQ lo+24(FP), SI
	MOVQ hi+32(FP), DX
	VMOVQ SI, X8
	VPINSRQ $1, DX, X8, X8
	VMOVDQU 0(AX), X9
	VMOVDQU 16(AX), X10
	VMOVDQU 32(AX), X11
	VMOVDQU 48(AX), X12
	VMOVDQU 64(AX), X13
	VMOVDQU 80(AX), X14
	VMOVDQU ·noiseIncTab+128(SB), X15

loop:
	VPADDQ ·noiseIncTab+0(SB), X8, X0
	VPADDQ ·noiseIncTab+16(SB), X8, X1
	VPADDQ ·noiseIncTab+32(SB), X8, X2
	VPADDQ ·noiseIncTab+48(SB), X8, X3
	VPADDQ ·noiseIncTab+64(SB), X8, X4
	VPADDQ ·noiseIncTab+80(SB), X8, X5
	VPADDQ ·noiseIncTab+96(SB), X8, X6
	VPADDQ ·noiseIncTab+112(SB), X8, X7
	VPXOR X9, X0, X0
	VPXOR X9, X1, X1
	VPXOR X9, X2, X2
	VPXOR X9, X3, X3
	VPXOR X9, X4, X4
	VPXOR X9, X5, X5
	VPXOR X9, X6, X6
	VPXOR X9, X7, X7
	ROUND8(X10)
	ROUND8(X11)
	ROUND8(X12)
	ROUND8(X13)
	ROUND8(X14)
	VMOVDQU X0, 0(DI)
	VMOVDQU X1, 16(DI)
	VMOVDQU X2, 32(DI)
	VMOVDQU X3, 48(DI)
	VMOVDQU X4, 64(DI)
	VMOVDQU X5, 80(DI)
	VMOVDQU X6, 96(DI)
	VMOVDQU X7, 112(DI)
	VPADDQ X15, X8, X8
	ADDQ $128, DI
	SUBQ $8, CX
	JNZ loop
	// Wipe the block states, the counter and the key-derived schedule
	// from the whole vector register file before returning.
	VZEROALL
	RET
