//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX) 16-lane chain-absorb kernel for AES-ITB-128 at the
// 13-byte per-lane shape (1 PKCS#7 block, 3 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of the x4 path.
//
// Batch layout: two batches of 8 lanes each. Per lane: state initialized with
// key XOR seed pair, block loaded as [0x03 | LE64(groupIdx) | pad_tail],
// then 3 AES rounds (1 absorb + 2 finaliser) with RC[0], RC[0], RC[1].

#include "textflag.h"

// func aesITB128ChainAbsorb13x16VexAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128ChainAbsorb13x16VexAsm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ out+32(FP), DI
	MOVQ groupIdxBase+24(FP), R8

	// Load key and seed pair, compute template
	VMOVDQU 0(AX), X13
	VMOVQ seed0+8(FP), X14
	VPINSRQ $1, seed1+16(FP), X14, X14
	VPXOR X13, X14, X14
	VPXOR ·absorb13Block(SB), X14, X14

	// Load round constants
	VMOVDQU ·RC+0(SB), X9
	VMOVDQU ·RC+16(SB), X10

	// ========== BATCH 1: lanes 0–7 ==========

	// Lane 0: idx = base
	MOVQ R8, R9
	VMOVQ R9, X0
	VMOVQ R9, X15
	VPSLLQ $8, X0, X0
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X0, X0
	VPXOR X14, X0, X0

	// Lane 1: idx = base + 1
	MOVQ R8, R9
	ADDQ $1, R9
	VMOVQ R9, X1
	VMOVQ R9, X15
	VPSLLQ $8, X1, X1
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X1, X1
	VPXOR X14, X1, X1

	// Lane 2: idx = base + 2
	MOVQ R8, R9
	ADDQ $2, R9
	VMOVQ R9, X2
	VMOVQ R9, X15
	VPSLLQ $8, X2, X2
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X2, X2
	VPXOR X14, X2, X2

	// Lane 3: idx = base + 3
	MOVQ R8, R9
	ADDQ $3, R9
	VMOVQ R9, X3
	VMOVQ R9, X15
	VPSLLQ $8, X3, X3
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X3, X3
	VPXOR X14, X3, X3

	// Lane 4: idx = base + 4
	MOVQ R8, R9
	ADDQ $4, R9
	VMOVQ R9, X4
	VMOVQ R9, X15
	VPSLLQ $8, X4, X4
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X4, X4
	VPXOR X14, X4, X4

	// Lane 5: idx = base + 5
	MOVQ R8, R9
	ADDQ $5, R9
	VMOVQ R9, X5
	VMOVQ R9, X15
	VPSLLQ $8, X5, X5
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X5, X5
	VPXOR X14, X5, X5

	// Lane 6: idx = base + 6
	MOVQ R8, R9
	ADDQ $6, R9
	VMOVQ R9, X6
	VMOVQ R9, X15
	VPSLLQ $8, X6, X6
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X6, X6
	VPXOR X14, X6, X6

	// Lane 7: idx = base + 7
	MOVQ R8, R9
	ADDQ $7, R9
	VMOVQ R9, X7
	VMOVQ R9, X15
	VPSLLQ $8, X7, X7
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X7, X7
	VPXOR X14, X7, X7

	// AES rounds for batch 1 (3 rounds × 8 lanes)
	VAESENC X9, X0, X0; VAESENC X9, X1, X1; VAESENC X9, X2, X2; VAESENC X9, X3, X3; VAESENC X9, X4, X4; VAESENC X9, X5, X5; VAESENC X9, X6, X6; VAESENC X9, X7, X7
	VAESENC X9, X0, X0; VAESENC X9, X1, X1; VAESENC X9, X2, X2; VAESENC X9, X3, X3; VAESENC X9, X4, X4; VAESENC X9, X5, X5; VAESENC X9, X6, X6; VAESENC X9, X7, X7
	VAESENC X10, X0, X0; VAESENC X10, X1, X1; VAESENC X10, X2, X2; VAESENC X10, X3, X3; VAESENC X10, X4, X4; VAESENC X10, X5, X5; VAESENC X10, X6, X6; VAESENC X10, X7, X7

	// Store batch 1 outputs
	VMOVDQU X0, 0(DI)
	VMOVDQU X1, 16(DI)
	VMOVDQU X2, 32(DI)
	VMOVDQU X3, 48(DI)
	VMOVDQU X4, 64(DI)
	VMOVDQU X5, 80(DI)
	VMOVDQU X6, 96(DI)
	VMOVDQU X7, 112(DI)

	// ========== BATCH 2: lanes 8–15 ==========

	// Lane 8: idx = base + 8
	MOVQ R8, R9
	ADDQ $8, R9
	VMOVQ R9, X0
	VMOVQ R9, X15
	VPSLLQ $8, X0, X0
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X0, X0
	VPXOR X14, X0, X0

	// Lane 9: idx = base + 9
	MOVQ R8, R9
	ADDQ $9, R9
	VMOVQ R9, X1
	VMOVQ R9, X15
	VPSLLQ $8, X1, X1
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X1, X1
	VPXOR X14, X1, X1

	// Lane 10: idx = base + 10
	MOVQ R8, R9
	ADDQ $10, R9
	VMOVQ R9, X2
	VMOVQ R9, X15
	VPSLLQ $8, X2, X2
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X2, X2
	VPXOR X14, X2, X2

	// Lane 11: idx = base + 11
	MOVQ R8, R9
	ADDQ $11, R9
	VMOVQ R9, X3
	VMOVQ R9, X15
	VPSLLQ $8, X3, X3
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X3, X3
	VPXOR X14, X3, X3

	// Lane 12: idx = base + 12
	MOVQ R8, R9
	ADDQ $12, R9
	VMOVQ R9, X4
	VMOVQ R9, X15
	VPSLLQ $8, X4, X4
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X4, X4
	VPXOR X14, X4, X4

	// Lane 13: idx = base + 13
	MOVQ R8, R9
	ADDQ $13, R9
	VMOVQ R9, X5
	VMOVQ R9, X15
	VPSLLQ $8, X5, X5
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X5, X5
	VPXOR X14, X5, X5

	// Lane 14: idx = base + 14
	MOVQ R8, R9
	ADDQ $14, R9
	VMOVQ R9, X6
	VMOVQ R9, X15
	VPSLLQ $8, X6, X6
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X6, X6
	VPXOR X14, X6, X6

	// Lane 15: idx = base + 15
	MOVQ R8, R9
	ADDQ $15, R9
	VMOVQ R9, X7
	VMOVQ R9, X15
	VPSLLQ $8, X7, X7
	VPSRLQ $56, X15, X15
	VPUNPCKLQDQ X15, X7, X7
	VPXOR X14, X7, X7

	// AES rounds for batch 2
	VAESENC X9, X0, X0; VAESENC X9, X1, X1; VAESENC X9, X2, X2; VAESENC X9, X3, X3; VAESENC X9, X4, X4; VAESENC X9, X5, X5; VAESENC X9, X6, X6; VAESENC X9, X7, X7
	VAESENC X9, X0, X0; VAESENC X9, X1, X1; VAESENC X9, X2, X2; VAESENC X9, X3, X3; VAESENC X9, X4, X4; VAESENC X9, X5, X5; VAESENC X9, X6, X6; VAESENC X9, X7, X7
	VAESENC X10, X0, X0; VAESENC X10, X1, X1; VAESENC X10, X2, X2; VAESENC X10, X3, X3; VAESENC X10, X4, X4; VAESENC X10, X5, X5; VAESENC X10, X6, X6; VAESENC X10, X7, X7

	// Store batch 2 outputs
	VMOVDQU X0, 128(DI)
	VMOVDQU X1, 144(DI)
	VMOVDQU X2, 160(DI)
	VMOVDQU X3, 176(DI)
	VMOVDQU X4, 192(DI)
	VMOVDQU X5, 208(DI)
	VMOVDQU X6, 224(DI)
	VMOVDQU X7, 240(DI)

	RET
