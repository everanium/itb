//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM AES-ITB noise filler kernel, eight blocks per
// iteration — the tier for AES-NI hosts without AVX, so no VEX-encoded
// instruction appears here. Block j of the run is the folded schedule
// of noisefill.go applied to counter (lo + j, hi): one XOR with the
// pre-whitening block C, five AESENC rounds under RK[0..4], one 16-byte
// store. The eight blocks are independent AES chains, so the eight
// AESENC of a round issue back to back. See noisefill.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go sponge.
//
// Register allocation:
//   X0..X7   the eight block states
//   X8       running counter [lo, hi], advanced by one per block
//   X9       C (pre-whitening)
//   X10..X14 RK[0..4]
//   X15      increment [1, 0]
//
// Frame: none. Every register that held a state, the counter or a
// schedule entry is zeroed before RET.

#include "textflag.h"

#define ROUND8(RK) \
	AESENC RK, X0; \
	AESENC RK, X1; \
	AESENC RK, X2; \
	AESENC RK, X3; \
	AESENC RK, X4; \
	AESENC RK, X5; \
	AESENC RK, X6; \
	AESENC RK, X7

#define GEN1(DST) \
	MOVOU X8, DST; \
	PXOR X9, DST; \
	PADDQ X15, X8

// func noiseFillX8AesNiAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
TEXT ·noiseFillX8AesNiAsm(SB), NOSPLIT, $0-40
	MOVQ sched+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ nblk+16(FP), CX
	MOVQ lo+24(FP), SI
	MOVQ hi+32(FP), DX
	MOVQ SI, X8
	PINSRQ $1, DX, X8
	MOVOU 0(AX), X9
	MOVOU 16(AX), X10
	MOVOU 32(AX), X11
	MOVOU 48(AX), X12
	MOVOU 64(AX), X13
	MOVOU 80(AX), X14
	MOVOU ·noiseIncTab+16(SB), X15

loop:
	GEN1(X0)
	GEN1(X1)
	GEN1(X2)
	GEN1(X3)
	GEN1(X4)
	GEN1(X5)
	GEN1(X6)
	GEN1(X7)
	ROUND8(X10)
	ROUND8(X11)
	ROUND8(X12)
	ROUND8(X13)
	ROUND8(X14)
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	ADDQ $128, DI
	SUBQ $8, CX
	JNZ loop
	// Wipe the block states, the counter and the key-derived schedule
	// from the register file before returning.
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X7, X7
	PXOR X8, X8
	PXOR X9, X9
	PXOR X10, X10
	PXOR X11, X11
	PXOR X12, X12
	PXOR X13, X13
	PXOR X14, X14
	RET
