//go:build amd64 && !purego && !noitbasm

// VAES YMM, two lanes per 256-bit register (needs VAES + AVX2) 16-lane fused ChainHash cascade kernel
// for AES-ITB-128 at the 13-byte per-lane fill shape (1 PKCS#7 block, 3 AES rounds per lane and cascade round).
// See aesitbasm_fused.go for the construction; every tier is pinned to
// the pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 8 YMM states, two lanes per YMM (lanes 2i and 2i+1 in Y[i]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// VPUNPCKLQDQ, avoiding per-lane pointer gather overhead of the x4 path.
// The 8 block pairs are staged to a 256-byte frame with 32-byte stores in
// the prologue and read back as 32-byte VPXOR operands in every cascade
// round (the register file cannot hold states, constants and blocks).
//
// Register allocation:
//   Y0–Y7      states, pair i = lanes (2i, 2i+1)
//   Y8–Y9      RC[0], RC[1] broadcasts
//   Y10        absorb13Block broadcast (prologue only)
//   Y11, Y15   scratch for per-lane groupIdx synthesis
//   Y13        key broadcast
//   Y14        key XOR component pair, broadcast per cascade round
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X15 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with absorb13Block to form the fill block, store to the frame

#include "textflag.h"

// func aesITB128FusedChain13x16VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128FusedChain13x16VaesAvx2Asm(SB), NOSPLIT, $256-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ out+32(FP), DI
	MOVQ groupIdxBase+24(FP), R8

	// Stage the 8 block pairs into the frame at 32*pair(SP)
	VBROADCASTI128 ·absorb13Block(SB), Y10

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

	// Load round constants and key
	VBROADCASTI128 ·RC+0(SB), Y8
	VBROADCASTI128 ·RC+16(SB), Y9
	VBROADCASTI128 0(AX), Y13
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1
	VPXOR Y2, Y2, Y2
	VPXOR Y3, Y3, Y3
	VPXOR Y4, Y4, Y4
	VPXOR Y5, Y5, Y5
	VPXOR Y6, Y6, Y6
	VPXOR Y7, Y7, Y7

loop:
	VBROADCASTI128 0(BX), Y14
	VPXOR Y13, Y14, Y14
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
	// AES rounds: 3 rounds on all 8 YMM pairs (RC[0], RC[0], RC[1])
	VAESENC Y8, Y0, Y0; VAESENC Y8, Y1, Y1; VAESENC Y8, Y2, Y2; VAESENC Y8, Y3, Y3; VAESENC Y8, Y4, Y4; VAESENC Y8, Y5, Y5; VAESENC Y8, Y6, Y6; VAESENC Y8, Y7, Y7
	VAESENC Y8, Y0, Y0; VAESENC Y8, Y1, Y1; VAESENC Y8, Y2, Y2; VAESENC Y8, Y3, Y3; VAESENC Y8, Y4, Y4; VAESENC Y8, Y5, Y5; VAESENC Y8, Y6, Y6; VAESENC Y8, Y7, Y7
	VAESENC Y9, Y0, Y0; VAESENC Y9, Y1, Y1; VAESENC Y9, Y2, Y2; VAESENC Y9, Y3, Y3; VAESENC Y9, Y4, Y4; VAESENC Y9, Y5, Y5; VAESENC Y9, Y6, Y6; VAESENC Y9, Y7, Y7
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
