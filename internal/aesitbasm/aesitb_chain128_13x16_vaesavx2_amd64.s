//go:build amd64 && !purego && !noitbasm

// VAES YMM, two lanes per 256-bit register (needs VAES + AVX2) 16-lane chain-absorb kernel
// for AES-ITB-128 at the 13-byte per-lane shape (1 PKCS#7 block, 3 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Batch layout: 8 YMM states, two lanes per YMM (lanes 2i and 2i+1 in Y[i]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// VPUNPCKLQDQ, avoiding per-lane pointer gather overhead of the x4 path.
//
// Register allocation:
//   Y0–Y7      states, pair i = lanes (2i, 2i+1)
//   Y8–Y9      RC[0], RC[1] broadcasts
//   Y10        template (key XOR seeds XOR absorb13Block)
//   Y11–Y14    scratch for per-lane groupIdx synthesis
//   Y15        free
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X14 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with template to form initial state

#include "textflag.h"

// func aesITB128ChainAbsorb13x16VaesAvx2Asm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128ChainAbsorb13x16VaesAvx2Asm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ out+32(FP), DI
	MOVQ groupIdxBase+24(FP), R8

	// Load key and seed pair, compute template
	VMOVQ seed0+8(FP), X10
	VPINSRQ $1, seed1+16(FP), X10, X10
	VPXOR 0(AX), X10, X10
	VPXOR ·absorb13Block(SB), X10, X10
	VINSERTI128 $1, X10, Y10, Y10

	// Load round constants
	VBROADCASTI128 ·RC+0(SB), Y8
	VBROADCASTI128 ·RC+16(SB), Y9

	// ========== Pair 0: lanes 0–1 ==========
	MOVQ R8, R9
	VMOVQ R9, X11
	LEAQ 1(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y0

	// ========== Pair 1: lanes 2–3 ==========
	LEAQ 2(R8), R9
	VMOVQ R9, X11
	LEAQ 3(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y1

	// ========== Pair 2: lanes 4–5 ==========
	LEAQ 4(R8), R9
	VMOVQ R9, X11
	LEAQ 5(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y2

	// ========== Pair 3: lanes 6–7 ==========
	LEAQ 6(R8), R9
	VMOVQ R9, X11
	LEAQ 7(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y3

	// ========== Pair 4: lanes 8–9 ==========
	LEAQ 8(R8), R9
	VMOVQ R9, X11
	LEAQ 9(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y4

	// ========== Pair 5: lanes 10–11 ==========
	LEAQ 10(R8), R9
	VMOVQ R9, X11
	LEAQ 11(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y5

	// ========== Pair 6: lanes 12–13 ==========
	LEAQ 12(R8), R9
	VMOVQ R9, X11
	LEAQ 13(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y6

	// ========== Pair 7: lanes 14–15 ==========
	LEAQ 14(R8), R9
	VMOVQ R9, X11
	LEAQ 15(R8), R9
	VMOVQ R9, X14
	VINSERTI128 $1, X14, Y11, Y11
	VPSRLQ $56, Y11, Y14
	VPSLLQ $8, Y11, Y11
	VPUNPCKLQDQ Y14, Y11, Y11
	VPXOR Y10, Y11, Y7

	// AES rounds: 3 rounds on all 8 YMM pairs (RC[0], RC[0], RC[1])
	VAESENC Y8, Y0, Y0; VAESENC Y8, Y1, Y1; VAESENC Y8, Y2, Y2; VAESENC Y8, Y3, Y3; VAESENC Y8, Y4, Y4; VAESENC Y8, Y5, Y5; VAESENC Y8, Y6, Y6; VAESENC Y8, Y7, Y7
	VAESENC Y8, Y0, Y0; VAESENC Y8, Y1, Y1; VAESENC Y8, Y2, Y2; VAESENC Y8, Y3, Y3; VAESENC Y8, Y4, Y4; VAESENC Y8, Y5, Y5; VAESENC Y8, Y6, Y6; VAESENC Y8, Y7, Y7
	VAESENC Y9, Y0, Y0; VAESENC Y9, Y1, Y1; VAESENC Y9, Y2, Y2; VAESENC Y9, Y3, Y3; VAESENC Y9, Y4, Y4; VAESENC Y9, Y5, Y5; VAESENC Y9, Y6, Y6; VAESENC Y9, Y7, Y7

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
