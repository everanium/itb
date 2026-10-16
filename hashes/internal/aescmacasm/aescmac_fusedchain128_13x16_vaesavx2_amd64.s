//go:build amd64 && !purego && !noitbasm

// VAES YMM, two lanes per 256-bit register (needs VAES + AVX2) 16-lane fused ChainHash cascade kernel
// for AES-CMAC at the 13-byte per-lane fill shape (1 zero-padded block,
// 1 AES-128 permutation per lane and cascade round). See
// aescmacasm_fused.go for the construction; every tier is pinned to the
// pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 8 YMM states, two lanes per YMM (lanes 2i and 2i+1 in Y[i]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// VPUNPCKLQDQ, avoiding per-lane pointer gather overhead of the x4 path.
// The 8 block pairs are staged to the frame with 32-byte stores in the
// prologue and read back as 32-byte VPXOR operands in every cascade
// round. K1..K6 stay resident; every cascade round broadcasts K0 from the
// schedule and folds it into the pair, and broadcasts K7..K10 into the
// two temps ahead of their rounds, so the eight states, the pair and the
// eleven keys share the register file without any key or key-derived
// value reaching the frame, which holds the public blocks only.
//
// Register allocation:
//   Y0–Y7      states, pair i = lanes (2i, 2i+1)
//   Y8–Y13     K1..K6 broadcasts
//   Y14, Y15   pair ^ K0 per cascade round, then K7..K10 in turn
//   Y9, Y10, Y11, Y15   scratch during block synthesis (prologue only)
//   0(SP)..255(SP)    the 8 staged block pairs
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X15 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with the template (absorb13Block ^ [13 | 13 ^ (v << 8)], the
//     length tag with the interlock-nonce fold in its second qword),
//     store to the frame

#include "textflag.h"

// func aesCMAC128FusedChain13x16VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64, v uint32)
TEXT ·aesCMAC128FusedChain13x16VaesAvx2Asm(SB), NOSPLIT, $256-44
	MOVQ roundKeys+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ out+32(FP), DI
	MOVQ groupIdxBase+24(FP), R8

	// Template Y10 = absorb13Block ^ [13 | 13 ^ (v << 8)] in both halves: the length
	// tag with the interlock-nonce fold v in bytes 9..12 of each second qword
	VBROADCASTI128 ·absorb13Block(SB), Y10
	MOVQ $13, R12
	MOVL v+40(FP), R9
	SHLQ $8, R9
	ORQ R12, R9
	VMOVQ R12, X9
	VPINSRQ $1, R9, X9, X9
	VINSERTI128 $1, X9, Y9, Y9
	VPXOR Y9, Y10, Y10

	// Stage the 8 block pairs into the frame at 32*pair(SP)
	// ========== Pair 0: lanes 0–1 ==========
	MOVQ R8, R9
	VMOVQ R9, X11
	LEAQ 1(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 0(SP)

	// ========== Pair 1: lanes 2–3 ==========
	LEAQ 2(R8), R9
	VMOVQ R9, X11
	LEAQ 3(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 32(SP)

	// ========== Pair 2: lanes 4–5 ==========
	LEAQ 4(R8), R9
	VMOVQ R9, X11
	LEAQ 5(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 64(SP)

	// ========== Pair 3: lanes 6–7 ==========
	LEAQ 6(R8), R9
	VMOVQ R9, X11
	LEAQ 7(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 96(SP)

	// ========== Pair 4: lanes 8–9 ==========
	LEAQ 8(R8), R9
	VMOVQ R9, X11
	LEAQ 9(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 128(SP)

	// ========== Pair 5: lanes 10–11 ==========
	LEAQ 10(R8), R9
	VMOVQ R9, X11
	LEAQ 11(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 160(SP)

	// ========== Pair 6: lanes 12–13 ==========
	LEAQ 12(R8), R9
	VMOVQ R9, X11
	LEAQ 13(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 192(SP)

	// ========== Pair 7: lanes 14–15 ==========
	LEAQ 14(R8), R9
	VMOVQ R9, X11
	LEAQ 15(R8), R9
	VMOVQ R9, X15
	VINSERTI128 $1, X15, Y11, Y11
	VPSRLQ $56, Y11, Y15
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y15, Y11, Y11
	VPXOR Y10, Y11, Y11
	VMOVDQU Y11, 224(SP)

	// Load K1..K6
	VBROADCASTI128 16(AX), Y8
	VBROADCASTI128 32(AX), Y9
	VBROADCASTI128 48(AX), Y10
	VBROADCASTI128 64(AX), Y11
	VBROADCASTI128 80(AX), Y12
	VBROADCASTI128 96(AX), Y13
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1
	VPXOR Y2, Y2, Y2
	VPXOR Y3, Y3, Y3
	VPXOR Y4, Y4, Y4
	VPXOR Y5, Y5, Y5
	VPXOR Y6, Y6, Y6
	VPXOR Y7, Y7, Y7

loop:
	// Pair ^ K0 into every state, then the block
	VBROADCASTI128 0(BX), Y14
	VBROADCASTI128 0(AX), Y15
	VPXOR Y15, Y14, Y14
	VPXOR Y14, Y0, Y0
	VPXOR Y14, Y1, Y1
	VPXOR Y14, Y2, Y2
	VPXOR Y14, Y3, Y3
	VPXOR Y14, Y4, Y4
	VPXOR Y14, Y5, Y5
	VPXOR Y14, Y6, Y6
	VPXOR Y14, Y7, Y7
	VPXOR 0(SP), Y0, Y0
	VPXOR 32(SP), Y1, Y1
	VPXOR 64(SP), Y2, Y2
	VPXOR 96(SP), Y3, Y3
	VPXOR 128(SP), Y4, Y4
	VPXOR 160(SP), Y5, Y5
	VPXOR 192(SP), Y6, Y6
	VPXOR 224(SP), Y7, Y7
	// AES rounds 1..6 under the resident K1..K6, 7..10 under K7..K10 broadcast into Y14 / Y15
	VAESENC Y8, Y0, Y0; VAESENC Y8, Y1, Y1; VAESENC Y8, Y2, Y2; VAESENC Y8, Y3, Y3; VAESENC Y8, Y4, Y4; VAESENC Y8, Y5, Y5; VAESENC Y8, Y6, Y6; VAESENC Y8, Y7, Y7
	VAESENC Y9, Y0, Y0; VAESENC Y9, Y1, Y1; VAESENC Y9, Y2, Y2; VAESENC Y9, Y3, Y3; VAESENC Y9, Y4, Y4; VAESENC Y9, Y5, Y5; VAESENC Y9, Y6, Y6; VAESENC Y9, Y7, Y7
	VAESENC Y10, Y0, Y0; VAESENC Y10, Y1, Y1; VAESENC Y10, Y2, Y2; VAESENC Y10, Y3, Y3; VAESENC Y10, Y4, Y4; VAESENC Y10, Y5, Y5; VAESENC Y10, Y6, Y6; VAESENC Y10, Y7, Y7
	VAESENC Y11, Y0, Y0; VAESENC Y11, Y1, Y1; VAESENC Y11, Y2, Y2; VAESENC Y11, Y3, Y3; VAESENC Y11, Y4, Y4; VAESENC Y11, Y5, Y5; VAESENC Y11, Y6, Y6; VAESENC Y11, Y7, Y7
	VAESENC Y12, Y0, Y0; VAESENC Y12, Y1, Y1; VAESENC Y12, Y2, Y2; VAESENC Y12, Y3, Y3; VAESENC Y12, Y4, Y4; VAESENC Y12, Y5, Y5; VAESENC Y12, Y6, Y6; VAESENC Y12, Y7, Y7
	VAESENC Y13, Y0, Y0; VAESENC Y13, Y1, Y1; VAESENC Y13, Y2, Y2; VAESENC Y13, Y3, Y3; VAESENC Y13, Y4, Y4; VAESENC Y13, Y5, Y5; VAESENC Y13, Y6, Y6; VAESENC Y13, Y7, Y7
	VBROADCASTI128 112(AX), Y14
	VAESENC Y14, Y0, Y0; VAESENC Y14, Y1, Y1; VAESENC Y14, Y2, Y2; VAESENC Y14, Y3, Y3; VAESENC Y14, Y4, Y4; VAESENC Y14, Y5, Y5; VAESENC Y14, Y6, Y6; VAESENC Y14, Y7, Y7
	VBROADCASTI128 128(AX), Y15
	VAESENC Y15, Y0, Y0; VAESENC Y15, Y1, Y1; VAESENC Y15, Y2, Y2; VAESENC Y15, Y3, Y3; VAESENC Y15, Y4, Y4; VAESENC Y15, Y5, Y5; VAESENC Y15, Y6, Y6; VAESENC Y15, Y7, Y7
	VBROADCASTI128 144(AX), Y14
	VAESENC Y14, Y0, Y0; VAESENC Y14, Y1, Y1; VAESENC Y14, Y2, Y2; VAESENC Y14, Y3, Y3; VAESENC Y14, Y4, Y4; VAESENC Y14, Y5, Y5; VAESENC Y14, Y6, Y6; VAESENC Y14, Y7, Y7
	VBROADCASTI128 160(AX), Y15
	VAESENCLAST Y15, Y0, Y0; VAESENCLAST Y15, Y1, Y1; VAESENCLAST Y15, Y2, Y2; VAESENCLAST Y15, Y3, Y3; VAESENCLAST Y15, Y4, Y4; VAESENCLAST Y15, Y5, Y5; VAESENCLAST Y15, Y6, Y6; VAESENCLAST Y15, Y7, Y7
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	// Store outputs: pair i at [32i..32i+32]
	VMOVDQU Y0, 0(DI)
	VMOVDQU Y1, 32(DI)
	VMOVDQU Y2, 64(DI)
	VMOVDQU Y3, 96(DI)
	VMOVDQU Y4, 128(DI)
	VMOVDQU Y5, 160(DI)
	VMOVDQU Y6, 192(DI)
	VMOVDQU Y7, 224(DI)

	VZEROUPPER
	RET
