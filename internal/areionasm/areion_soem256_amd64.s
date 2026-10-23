//go:build amd64 && !purego && !noitbasm

// Fused AVX-512 + VAES kernel for the two permutations of the
// Areion-SoEM-256 4-way batched PRF: P1 (round constants `·AreionRC4x`)
// on state1 and P2 (round constants `·AreionRC4x2`) on state2. Compared
// with calling the per-half permutation kernels twice plus a Go-side XOR
// finalize, this kernel:
//
//  1. Pre-loads the 10 P1 round constants into registers once and
//     reads the P2 constants as memory operands of the second chain's
//     VAESENC.
//  2. Interleaves the state1 and state2 round bodies — independent
//     dependency chains issued in lock-step, masking the 5-cycle
//     VAESENC latency on Intel Sunny Cove / Cypress Cove (Rocket
//     Lake i7-11700K) and AMD Zen 4. With one ZMM-VAESENC issuing
//     per cycle and the 2-VAESENC critical path per round leaving
//     8 idle cycles, the interleaved second state fills the gap.
//  3. Performs the output XOR (P1(state1) ⊕ P2(state2)) in registers
//     before writing back, eliminating the Go-side per-lane uint64
//     XOR loop that runs after the two separate permute calls.
//
// Caller is responsible for the SoEM input setup:
//   s1b0, s1b1 = input ⊕ key1   (in SoA Block4 layout)
//   s2b0, s2b1 = input ⊕ key2
// The fused result `P1(state1) ⊕ P2(state2)` is written back into the
// state1 buffers (s1b0, s1b1); the (s2b0, s2b1) buffers are left
// intact. The SoEM22 whitening `⊕ key1 ⊕ key2` is the caller's.

#include "textflag.h"

// func Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *areion.Block4)
//
// Runs the 10-round Areion256 permutation P1 on (s1b0, s1b1) and P2
// on (s2b0, s2b1) interleaved, XORs the two outputs together, and
// stores the result back into (s1b0, s1b1).
//
// Per round (10 rounds total, alternating x0/x1 roles; rc = P1's
// constant, rc2 = P2's):
//   even r:  t1 = RoundNoKey(s1_x0) ⊕ rc[r];  t2 = RoundNoKey(s2_x0) ⊕ rc2[r]
//            s1_x0 = FinalRoundNoKey(s1_x0);  s2_x0 = FinalRoundNoKey(s2_x0)
//            s1_x1 = RoundNoKey(t1) ⊕ s1_x1;  s2_x1 = RoundNoKey(t2) ⊕ s2_x1
//   odd r:   symmetric with x0/x1 roles swapped
//
// The `RoundNoKey + XOR(rc)` and `RoundNoKey + XOR(other_half)` fuses
// follow the 3-operand `VAESENC k, s, dst` identity —
// `AESENC(s, k) = MixColumns(ShiftRows(SubBytes(s))) XOR k`.
TEXT ·Areion256SoEMPermutex4Interleaved(SB), NOSPLIT, $0-32
	MOVQ s1b0+0(FP),  AX
	MOVQ s1b1+8(FP),  BX
	MOVQ s2b0+16(FP), CX
	MOVQ s2b1+24(FP), DX

	// Load the four SoA Block4 buffers.
	VMOVDQU64 (AX), Z0    // s1_x0
	VMOVDQU64 (BX), Z1    // s1_x1
	VMOVDQU64 (CX), Z4    // s2_x0
	VMOVDQU64 (DX), Z5    // s2_x1

	// Z3 = zero (used by VAESENCLAST as the FinalRoundNoKey "round key").
	VPXORD Z3, Z3, Z3

	// Pre-load all 10 P1 round constants into Z16..Z25; the P2 constants
	// are memory operands below.
	VMOVDQU64 ·AreionRC4x+0(SB),   Z16  // rc[0]
	VMOVDQU64 ·AreionRC4x+64(SB),  Z17  // rc[1]
	VMOVDQU64 ·AreionRC4x+128(SB), Z18  // rc[2]
	VMOVDQU64 ·AreionRC4x+192(SB), Z19  // rc[3]
	VMOVDQU64 ·AreionRC4x+256(SB), Z20  // rc[4]
	VMOVDQU64 ·AreionRC4x+320(SB), Z21  // rc[5]
	VMOVDQU64 ·AreionRC4x+384(SB), Z22  // rc[6]
	VMOVDQU64 ·AreionRC4x+448(SB), Z23  // rc[7]
	VMOVDQU64 ·AreionRC4x+512(SB), Z24  // rc[8]
	VMOVDQU64 ·AreionRC4x+576(SB), Z25  // rc[9]

	// ===== Round 0 (even)
	VAESENC     Z16, Z0, Z2
	VAESENC     ·AreionRC4x2+0(SB), Z4, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VAESENC     Z1, Z2, Z1
	VAESENC     Z5, Z6, Z5

	// ===== Round 1 (odd)
	VAESENC     Z17, Z1, Z2
	VAESENC     ·AreionRC4x2+64(SB), Z5, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VAESENC     Z0, Z2, Z0
	VAESENC     Z4, Z6, Z4

	// ===== Round 2 (even)
	VAESENC     Z18, Z0, Z2
	VAESENC     ·AreionRC4x2+128(SB), Z4, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VAESENC     Z1, Z2, Z1
	VAESENC     Z5, Z6, Z5

	// ===== Round 3 (odd)
	VAESENC     Z19, Z1, Z2
	VAESENC     ·AreionRC4x2+192(SB), Z5, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VAESENC     Z0, Z2, Z0
	VAESENC     Z4, Z6, Z4

	// ===== Round 4 (even)
	VAESENC     Z20, Z0, Z2
	VAESENC     ·AreionRC4x2+256(SB), Z4, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VAESENC     Z1, Z2, Z1
	VAESENC     Z5, Z6, Z5

	// ===== Round 5 (odd)
	VAESENC     Z21, Z1, Z2
	VAESENC     ·AreionRC4x2+320(SB), Z5, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VAESENC     Z0, Z2, Z0
	VAESENC     Z4, Z6, Z4

	// ===== Round 6 (even)
	VAESENC     Z22, Z0, Z2
	VAESENC     ·AreionRC4x2+384(SB), Z4, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VAESENC     Z1, Z2, Z1
	VAESENC     Z5, Z6, Z5

	// ===== Round 7 (odd)
	VAESENC     Z23, Z1, Z2
	VAESENC     ·AreionRC4x2+448(SB), Z5, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VAESENC     Z0, Z2, Z0
	VAESENC     Z4, Z6, Z4

	// ===== Round 8 (even)
	VAESENC     Z24, Z0, Z2
	VAESENC     ·AreionRC4x2+512(SB), Z4, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VAESENC     Z1, Z2, Z1
	VAESENC     Z5, Z6, Z5

	// ===== Round 9 (odd)
	VAESENC     Z25, Z1, Z2
	VAESENC     ·AreionRC4x2+576(SB), Z5, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VAESENC     Z0, Z2, Z0
	VAESENC     Z4, Z6, Z4

	// Output: P1(state1) ⊕ P2(state2), written back to (s1b0, s1b1).
	VPXORD Z4, Z0, Z0           // s1_x0 = s1_x0' ⊕ s2_x0'
	VPXORD Z5, Z1, Z1           // s1_x1 = s1_x1' ⊕ s2_x1'

	VMOVDQU64 Z0, (AX)
	VMOVDQU64 Z1, (BX)

	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X4, X4, X4
	VPXORD X5, X5, X5
	VPXORD X6, X6, X6
	VPXORD X16, X16, X16
	VPXORD X17, X17, X17
	VPXORD X18, X18, X18
	VPXORD X19, X19, X19
	VPXORD X20, X20, X20
	VPXORD X21, X21, X21
	VPXORD X22, X22, X22
	VPXORD X23, X23, X23
	VPXORD X24, X24, X24
	VPXORD X25, X25, X25
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	VZEROUPPER
	RET

// func Areion256SoEMPermutex4VaesAvx2(s1b0, s1b1, s2b0, s2b1 *areion.Block4)
TEXT ·Areion256SoEMPermutex4VaesAvx2(SB), NOSPLIT, $0-32
	MOVQ s1b0+0(FP), AX
	MOVQ s1b1+8(FP), BX
	MOVQ s2b0+16(FP), CX
	MOVQ s2b1+24(FP), DX
	VMOVDQU 0(AX), Y0
	VMOVDQU 32(AX), Y1
	VMOVDQU 0(BX), Y2
	VMOVDQU 32(BX), Y3
	VMOVDQU 0(CX), Y4
	VMOVDQU 32(CX), Y5
	VMOVDQU 0(DX), Y6
	VMOVDQU 32(DX), Y7
	VPXOR Y15, Y15, Y15
	VMOVDQU ·AreionRC4x+0(SB), Y12
	VMOVDQU ·AreionRC4x2+0(SB), Y13
	VAESENC Y12, Y0, Y8
	VAESENC Y12, Y1, Y9
	VAESENC Y13, Y4, Y10
	VAESENC Y13, Y5, Y11
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENC Y2, Y8, Y2
	VAESENC Y3, Y9, Y3
	VAESENC Y6, Y10, Y6
	VAESENC Y7, Y11, Y7
	VMOVDQU ·AreionRC4x+64(SB), Y12
	VMOVDQU ·AreionRC4x2+64(SB), Y13
	VAESENC Y12, Y2, Y8
	VAESENC Y12, Y3, Y9
	VAESENC Y13, Y6, Y10
	VAESENC Y13, Y7, Y11
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENC Y0, Y8, Y0
	VAESENC Y1, Y9, Y1
	VAESENC Y4, Y10, Y4
	VAESENC Y5, Y11, Y5
	VMOVDQU ·AreionRC4x+128(SB), Y12
	VMOVDQU ·AreionRC4x2+128(SB), Y13
	VAESENC Y12, Y0, Y8
	VAESENC Y12, Y1, Y9
	VAESENC Y13, Y4, Y10
	VAESENC Y13, Y5, Y11
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENC Y2, Y8, Y2
	VAESENC Y3, Y9, Y3
	VAESENC Y6, Y10, Y6
	VAESENC Y7, Y11, Y7
	VMOVDQU ·AreionRC4x+192(SB), Y12
	VMOVDQU ·AreionRC4x2+192(SB), Y13
	VAESENC Y12, Y2, Y8
	VAESENC Y12, Y3, Y9
	VAESENC Y13, Y6, Y10
	VAESENC Y13, Y7, Y11
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENC Y0, Y8, Y0
	VAESENC Y1, Y9, Y1
	VAESENC Y4, Y10, Y4
	VAESENC Y5, Y11, Y5
	VMOVDQU ·AreionRC4x+256(SB), Y12
	VMOVDQU ·AreionRC4x2+256(SB), Y13
	VAESENC Y12, Y0, Y8
	VAESENC Y12, Y1, Y9
	VAESENC Y13, Y4, Y10
	VAESENC Y13, Y5, Y11
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENC Y2, Y8, Y2
	VAESENC Y3, Y9, Y3
	VAESENC Y6, Y10, Y6
	VAESENC Y7, Y11, Y7
	VMOVDQU ·AreionRC4x+320(SB), Y12
	VMOVDQU ·AreionRC4x2+320(SB), Y13
	VAESENC Y12, Y2, Y8
	VAESENC Y12, Y3, Y9
	VAESENC Y13, Y6, Y10
	VAESENC Y13, Y7, Y11
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENC Y0, Y8, Y0
	VAESENC Y1, Y9, Y1
	VAESENC Y4, Y10, Y4
	VAESENC Y5, Y11, Y5
	VMOVDQU ·AreionRC4x+384(SB), Y12
	VMOVDQU ·AreionRC4x2+384(SB), Y13
	VAESENC Y12, Y0, Y8
	VAESENC Y12, Y1, Y9
	VAESENC Y13, Y4, Y10
	VAESENC Y13, Y5, Y11
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENC Y2, Y8, Y2
	VAESENC Y3, Y9, Y3
	VAESENC Y6, Y10, Y6
	VAESENC Y7, Y11, Y7
	VMOVDQU ·AreionRC4x+448(SB), Y12
	VMOVDQU ·AreionRC4x2+448(SB), Y13
	VAESENC Y12, Y2, Y8
	VAESENC Y12, Y3, Y9
	VAESENC Y13, Y6, Y10
	VAESENC Y13, Y7, Y11
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENC Y0, Y8, Y0
	VAESENC Y1, Y9, Y1
	VAESENC Y4, Y10, Y4
	VAESENC Y5, Y11, Y5
	VMOVDQU ·AreionRC4x+512(SB), Y12
	VMOVDQU ·AreionRC4x2+512(SB), Y13
	VAESENC Y12, Y0, Y8
	VAESENC Y12, Y1, Y9
	VAESENC Y13, Y4, Y10
	VAESENC Y13, Y5, Y11
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENC Y2, Y8, Y2
	VAESENC Y3, Y9, Y3
	VAESENC Y6, Y10, Y6
	VAESENC Y7, Y11, Y7
	VMOVDQU ·AreionRC4x+576(SB), Y12
	VMOVDQU ·AreionRC4x2+576(SB), Y13
	VAESENC Y12, Y2, Y8
	VAESENC Y12, Y3, Y9
	VAESENC Y13, Y6, Y10
	VAESENC Y13, Y7, Y11
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENC Y0, Y8, Y0
	VAESENC Y1, Y9, Y1
	VAESENC Y4, Y10, Y4
	VAESENC Y5, Y11, Y5
	VPXOR Y4, Y0, Y0
	VPXOR Y5, Y1, Y1
	VPXOR Y6, Y2, Y2
	VPXOR Y7, Y3, Y3
	VMOVDQU Y0, 0(AX)
	VMOVDQU Y1, 32(AX)
	VMOVDQU Y2, 0(BX)
	VMOVDQU Y3, 32(BX)
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X3, X3, X3
	VPXORD X4, X4, X4
	VPXORD X5, X5, X5
	VPXORD X6, X6, X6
	VPXORD X7, X7, X7
	VPXORD X8, X8, X8
	VPXORD X9, X9, X9
	VPXORD X10, X10, X10
	VPXORD X11, X11, X11
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	VZEROUPPER
	RET

