//go:build amd64 && !purego && !noitbasm

// VAES YMM (two blocks per register) AES-ITB noise filler kernel,
// sixteen blocks per iteration. Lane l of register Yj carries counter
// (lo + 2j + l, hi): the broadcast counter base plus the increment
// table pair at offset 32·j, one XOR with the broadcast pre-whitening
// block C, five VAESENC rounds under the broadcast RK[0..4], one
// 32-byte store. The sixteen blocks are independent AES chains. See
// noisefill.go for the construction and the in-package parity tests
// for the bit-exact pin against the pure-Go reference.
//
// Register allocation:
//   Y0..Y7   the eight state registers (two blocks each)
//   Y8       counter base [lo, hi, lo, hi], advanced by sixteen per iteration
//   Y9       C (pre-whitening), broadcast
//   Y10..Y14 RK[0..4], broadcast
//   Y15      increment [16, 0, 16, 0]
//
// Frame: none. VZEROALL before RET wipes every state, the counter and
// the schedule from the register file and clears the upper halves.

#include "textflag.h"

#define ROUND8(RK) \
	VAESENC RK, Y0, Y0; \
	VAESENC RK, Y1, Y1; \
	VAESENC RK, Y2, Y2; \
	VAESENC RK, Y3, Y3; \
	VAESENC RK, Y4, Y4; \
	VAESENC RK, Y5, Y5; \
	VAESENC RK, Y6, Y6; \
	VAESENC RK, Y7, Y7

// func noiseFillX16VaesAvx2Asm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
TEXT ·noiseFillX16VaesAvx2Asm(SB), NOSPLIT, $0-40
	MOVQ sched+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ nblk+16(FP), CX
	MOVQ lo+24(FP), SI
	MOVQ hi+32(FP), DX
	VMOVQ SI, X8
	VPINSRQ $1, DX, X8, X8
	VINSERTI128 $1, X8, Y8, Y8
	VBROADCASTI128 0(AX), Y9
	VBROADCASTI128 16(AX), Y10
	VBROADCASTI128 32(AX), Y11
	VBROADCASTI128 48(AX), Y12
	VBROADCASTI128 64(AX), Y13
	VBROADCASTI128 80(AX), Y14
	VBROADCASTI128 ·noiseIncTab+256(SB), Y15

loop:
	VPADDQ ·noiseIncTab+0(SB), Y8, Y0
	VPADDQ ·noiseIncTab+32(SB), Y8, Y1
	VPADDQ ·noiseIncTab+64(SB), Y8, Y2
	VPADDQ ·noiseIncTab+96(SB), Y8, Y3
	VPADDQ ·noiseIncTab+128(SB), Y8, Y4
	VPADDQ ·noiseIncTab+160(SB), Y8, Y5
	VPADDQ ·noiseIncTab+192(SB), Y8, Y6
	VPADDQ ·noiseIncTab+224(SB), Y8, Y7
	VPXOR Y9, Y0, Y0
	VPXOR Y9, Y1, Y1
	VPXOR Y9, Y2, Y2
	VPXOR Y9, Y3, Y3
	VPXOR Y9, Y4, Y4
	VPXOR Y9, Y5, Y5
	VPXOR Y9, Y6, Y6
	VPXOR Y9, Y7, Y7
	ROUND8(Y10)
	ROUND8(Y11)
	ROUND8(Y12)
	ROUND8(Y13)
	ROUND8(Y14)
	VMOVDQU Y0, 0(DI)
	VMOVDQU Y1, 32(DI)
	VMOVDQU Y2, 64(DI)
	VMOVDQU Y3, 96(DI)
	VMOVDQU Y4, 128(DI)
	VMOVDQU Y5, 160(DI)
	VMOVDQU Y6, 192(DI)
	VMOVDQU Y7, 224(DI)
	VPADDQ Y15, Y8, Y8
	ADDQ $256, DI
	SUBQ $16, CX
	JNZ loop
	// VZEROALL wipes every state, the counter and the key-derived
	// schedule from the register file and leaves the upper halves
	// clean, which also serves as the VZEROUPPER on exit.
	VZEROALL
	RET
