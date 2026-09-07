//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM (AESENC xmm, xmm) 16-lane fused ChainHash cascade kernel for AES-ITB-128
// at the 13-byte per-lane fill shape (1 PKCS#7 block, 3 AES rounds per lane and cascade round).
// See aesitbasm_fused.go for the construction; every tier is pinned to
// the pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of
// the x4 path. The synthesised block is round-invariant per lane; every
// cascade round XORs key XOR (c0 || c1) and the block into the state and
// runs the three AES rounds (absorb, finaliser RC[0], finaliser RC[1]).
//
// Batch layout: two batches of 8 lanes; each batch runs the whole cascade
// before the next starts. The 16 blocks are staged once into the frame
// (16 bytes per lane) in the prologue. Per batch: X0–X7 states, X9–X10
// RC[0] / RC[1], X13 key, X14 key XOR pair (per round), X15 scratch.

#include "textflag.h"

// func aesITB128FusedChain13x16AesNiAsm(key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128FusedChain13x16AesNiAsm(SB), NOSPLIT, $256-40
	MOVQ key+0(FP), AX
	MOVQ out+32(FP), DI
	MOVQ groupIdxBase+24(FP), R8

	// Stage the 16 fill blocks into the frame at 16*lane(SP)
	MOVOU ·absorb13Block(SB), X12

	// Lane 0: idx = base
	MOVQ R8, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 0(SP)

	// Lane 1: idx = base + 1
	MOVQ R8, R9
	ADDQ $1, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 16(SP)

	// Lane 2: idx = base + 2
	MOVQ R8, R9
	ADDQ $2, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 32(SP)

	// Lane 3: idx = base + 3
	MOVQ R8, R9
	ADDQ $3, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 48(SP)

	// Lane 4: idx = base + 4
	MOVQ R8, R9
	ADDQ $4, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 64(SP)

	// Lane 5: idx = base + 5
	MOVQ R8, R9
	ADDQ $5, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 80(SP)

	// Lane 6: idx = base + 6
	MOVQ R8, R9
	ADDQ $6, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 96(SP)

	// Lane 7: idx = base + 7
	MOVQ R8, R9
	ADDQ $7, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 112(SP)

	// Lane 8: idx = base + 8
	MOVQ R8, R9
	ADDQ $8, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 128(SP)

	// Lane 9: idx = base + 9
	MOVQ R8, R9
	ADDQ $9, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 144(SP)

	// Lane 10: idx = base + 10
	MOVQ R8, R9
	ADDQ $10, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 160(SP)

	// Lane 11: idx = base + 11
	MOVQ R8, R9
	ADDQ $11, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 176(SP)

	// Lane 12: idx = base + 12
	MOVQ R8, R9
	ADDQ $12, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 192(SP)

	// Lane 13: idx = base + 13
	MOVQ R8, R9
	ADDQ $13, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 208(SP)

	// Lane 14: idx = base + 14
	MOVQ R8, R9
	ADDQ $14, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 224(SP)

	// Lane 15: idx = base + 15
	MOVQ R8, R9
	ADDQ $15, R9
	MOVQ R9, X11
	MOVQ R9, X15
	PSLLQ $8, X11
	PSRLQ $56, X15
	PUNPCKLQDQ X15, X11
	PXOR X12, X11
	MOVOU X11, 240(SP)

	// Load round constants and key
	MOVOU ·RC+0(SB), X9
	MOVOU ·RC+16(SB), X10
	MOVOU 0(AX), X13

	// ========== BATCH 1: lanes 0–7 ==========
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X7, X7

loop0:
	MOVOU 0(BX), X14
	PXOR X13, X14
	PXOR X14, X0
	PXOR X14, X1
	PXOR X14, X2
	PXOR X14, X3
	PXOR X14, X4
	PXOR X14, X5
	PXOR X14, X6
	PXOR X14, X7
	MOVOU 0(SP), X15
	PXOR X15, X0
	MOVOU 16(SP), X15
	PXOR X15, X1
	MOVOU 32(SP), X15
	PXOR X15, X2
	MOVOU 48(SP), X15
	PXOR X15, X3
	MOVOU 64(SP), X15
	PXOR X15, X4
	MOVOU 80(SP), X15
	PXOR X15, X5
	MOVOU 96(SP), X15
	PXOR X15, X6
	MOVOU 112(SP), X15
	PXOR X15, X7
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X10, X0; AESENC X10, X1; AESENC X10, X2; AESENC X10, X3; AESENC X10, X4; AESENC X10, X5; AESENC X10, X6; AESENC X10, X7
	ADDQ $16, BX
	DECQ CX
	JNZ loop0

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
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X7, X7

loop1:
	MOVOU 0(BX), X14
	PXOR X13, X14
	PXOR X14, X0
	PXOR X14, X1
	PXOR X14, X2
	PXOR X14, X3
	PXOR X14, X4
	PXOR X14, X5
	PXOR X14, X6
	PXOR X14, X7
	MOVOU 128(SP), X15
	PXOR X15, X0
	MOVOU 144(SP), X15
	PXOR X15, X1
	MOVOU 160(SP), X15
	PXOR X15, X2
	MOVOU 176(SP), X15
	PXOR X15, X3
	MOVOU 192(SP), X15
	PXOR X15, X4
	MOVOU 208(SP), X15
	PXOR X15, X5
	MOVOU 224(SP), X15
	PXOR X15, X6
	MOVOU 240(SP), X15
	PXOR X15, X7
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3; AESENC X9, X4; AESENC X9, X5; AESENC X9, X6; AESENC X9, X7
	AESENC X10, X0; AESENC X10, X1; AESENC X10, X2; AESENC X10, X3; AESENC X10, X4; AESENC X10, X5; AESENC X10, X6; AESENC X10, X7
	ADDQ $16, BX
	DECQ CX
	JNZ loop1

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
