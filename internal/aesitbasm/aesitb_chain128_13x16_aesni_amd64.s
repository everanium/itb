//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM (AESENC xmm, xmm) 16-lane chain-absorb kernel for AES-ITB-128 at the
// 13-byte per-lane shape (1 PKCS#7 block, 3 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of the x4 path.

#include "textflag.h"

// func aesITB128ChainAbsorb13x16AesNiAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128ChainAbsorb13x16AesNiAsm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ out+32(FP), DI
	MOVQ groupIdxBase+24(FP), R8

	// Load key and seed pair, compute template
	MOVOU 0(AX), X13
	MOVQ seed0+8(FP), X14
	PINSRQ $1, seed1+16(FP), X14
	PXOR X13, X14
	PXOR ·absorb13Block(SB), X14

	// Load round constants
	MOVOU ·RC+0(SB), X9
	MOVOU ·RC+16(SB), X10

	// Process 16 lanes, 8 per batch to stay within register limits
	// Reuse registers: X0-X7 for state, X15 for scratch

	// ========== BATCH 1: lanes 0–7 ==========

	// Lane 0: idx = base
	MOVQ R8, R9
	MOVQ R9, X0
	MOVQ R9, X15
	PSLLQ $8, X0
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X0
	PXOR X14, X0

	// Lane 1: idx = base + 1
	MOVQ R8, R9
	ADDQ $1, R9
	MOVQ R9, X1
	MOVQ R9, X15
	PSLLQ $8, X1
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X1
	PXOR X14, X1

	// Lane 2: idx = base + 2
	MOVQ R8, R9
	ADDQ $2, R9
	MOVQ R9, X2
	MOVQ R9, X15
	PSLLQ $8, X2
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X2
	PXOR X14, X2

	// Lane 3: idx = base + 3
	MOVQ R8, R9
	ADDQ $3, R9
	MOVQ R9, X3
	MOVQ R9, X15
	PSLLQ $8, X3
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X3
	PXOR X14, X3

	// Lane 4: idx = base + 4
	MOVQ R8, R9
	ADDQ $4, R9
	MOVQ R9, X4
	MOVQ R9, X15
	PSLLQ $8, X4
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X4
	PXOR X14, X4

	// Lane 5: idx = base + 5
	MOVQ R8, R9
	ADDQ $5, R9
	MOVQ R9, X5
	MOVQ R9, X15
	PSLLQ $8, X5
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X5
	PXOR X14, X5

	// Lane 6: idx = base + 6
	MOVQ R8, R9
	ADDQ $6, R9
	MOVQ R9, X6
	MOVQ R9, X15
	PSLLQ $8, X6
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X6
	PXOR X14, X6

	// Lane 7: idx = base + 7
	MOVQ R8, R9
	ADDQ $7, R9
	MOVQ R9, X7
	MOVQ R9, X15
	PSLLQ $8, X7
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X7
	PXOR X14, X7

	// AES rounds for batch 1 (3 rounds × 8 lanes)
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X10, X0; AESENC X10, X1; AESENC X10, X2; AESENC X10, X3; AESENC X10, X4; AESENC X10, X5; AESENC X10, X6; AESENC X10, X7

	// Store batch 1 outputs
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)

	// ========== BATCH 2: lanes 8–15 ==========

	// Lane 8: idx = base + 8
	MOVQ R8, R9
	ADDQ $8, R9
	MOVQ R9, X0
	MOVQ R9, X15
	PSLLQ $8, X0
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X0
	PXOR X14, X0

	// Lane 9: idx = base + 9
	MOVQ R8, R9
	ADDQ $9, R9
	MOVQ R9, X1
	MOVQ R9, X15
	PSLLQ $8, X1
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X1
	PXOR X14, X1

	// Lane 10: idx = base + 10
	MOVQ R8, R9
	ADDQ $10, R9
	MOVQ R9, X2
	MOVQ R9, X15
	PSLLQ $8, X2
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X2
	PXOR X14, X2

	// Lane 11: idx = base + 11
	MOVQ R8, R9
	ADDQ $11, R9
	MOVQ R9, X3
	MOVQ R9, X15
	PSLLQ $8, X3
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X3
	PXOR X14, X3

	// Lane 12: idx = base + 12
	MOVQ R8, R9
	ADDQ $12, R9
	MOVQ R9, X4
	MOVQ R9, X15
	PSLLQ $8, X4
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X4
	PXOR X14, X4

	// Lane 13: idx = base + 13
	MOVQ R8, R9
	ADDQ $13, R9
	MOVQ R9, X5
	MOVQ R9, X15
	PSLLQ $8, X5
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X5
	PXOR X14, X5

	// Lane 14: idx = base + 14
	MOVQ R8, R9
	ADDQ $14, R9
	MOVQ R9, X6
	MOVQ R9, X15
	PSLLQ $8, X6
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X6
	PXOR X14, X6

	// Lane 15: idx = base + 15
	MOVQ R8, R9
	ADDQ $15, R9
	MOVQ R9, X7
	MOVQ R9, X15
	PSLLQ $8, X7
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X7
	PXOR X14, X7

	// AES rounds for batch 2
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X10, X0; AESENC X10, X1; AESENC X10, X2; AESENC X10, X3; AESENC X10, X4; AESENC X10, X5; AESENC X10, X6; AESENC X10, X7

	// Store batch 2 outputs
	MOVOU X0, 128(DI)
	MOVOU X1, 144(DI)
	MOVOU X2, 160(DI)
	MOVOU X3, 176(DI)
	MOVOU X4, 192(DI)
	MOVOU X5, 208(DI)
	MOVOU X6, 224(DI)
	MOVOU X7, 240(DI)

	RET
