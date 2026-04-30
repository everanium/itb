//go:build amd64 && !purego

// Fused AVX-512 + VAES kernel for the Areion-SoEM-256 4-way batched
// PRF. Compared with calling `Areion256Permutex4` twice (once per
// SoEM half-state) plus a Go-side XOR finalize, this kernel:
//
//  1. Loads the 10 Areion256 round constants once for both halves
//     instead of twice. Reuses the same `·AreionRC4x` 64-byte
//     pre-broadcast round-constant table as the per-half kernel.
//  2. Interleaves the state1 and state2 round bodies — independent
//     dependency chains issued in lock-step, masking the 5-cycle
//     VAESENC latency on Intel Sunny Cove / Cypress Cove (Rocket
//     Lake i7-11700K) and AMD Zen 4. With one ZMM-VAESENC issuing
//     per cycle and the 2-VAESENC critical path per round leaving
//     8 idle cycles, the interleaved second state fills the gap.
//  3. Performs the SoEM output XOR (state1' ⊕ state2') in registers
//     before writing back, eliminating the Go-side per-lane uint64
//     XOR loop that runs after the two separate permute calls.
//
// Caller is responsible for the SoEM input setup:
//   s1b0, s1b1 = input ⊕ key1   (in SoA Block4 layout)
//   s2b0, s2b1 = input ⊕ key2 ⊕ domainSep
// The fused result `state1' ⊕ state2'` is written back into the
// state1 buffers (s1b0, s1b1); the (s2b0, s2b1) buffers are scratch
// and their contents after the call are unspecified.

#include "textflag.h"

// func Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *aes.Block4)
//
// Runs the 10-round Areion256 permutation on (s1b0, s1b1) and
// (s2b0, s2b1) interleaved, XORs the two output halves together,
// and stores the SoEM output back into (s1b0, s1b1).
//
// Per round (10 rounds total, alternating x0/x1 roles):
//   even r:  t1 = s1_x0;  t2 = s2_x0
//            t1 = RoundNoKey(t1) ⊕ rc[r];  t2 = RoundNoKey(t2) ⊕ rc[r]
//            t1 = RoundNoKey(t1) ⊕ s1_x1;  t2 = RoundNoKey(t2) ⊕ s2_x1
//            s1_x0 = FinalRoundNoKey(s1_x0); s2_x0 = FinalRoundNoKey(s2_x0)
//            s1_x1 = t1;  s2_x1 = t2
//   odd r:   symmetric with x0/x1 roles swapped
//
// The `RoundNoKey + XOR(rc)` and `RoundNoKey + XOR(other_half)` fuses
// follow the same `VAESENC k, s, s` identity as the upstream
// per-half kernel — `AESENC(s, k) = MixColumns(ShiftRows(SubBytes(s))) XOR k`.
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

	// Pre-load all 10 round constants into Z16..Z25.
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

	// ===== Round 0 (even): t = s_x0; ...; s_x0 = FinalRoundNoKey(s_x0); s_x1 = t
	VMOVDQA64   Z0, Z2          // t1 = s1_x0
	VMOVDQA64   Z4, Z6          // t2 = s2_x0
	VAESENC     Z16, Z2, Z2     // t1 = RoundNoKey(t1) ⊕ rc[0]
	VAESENC     Z16, Z6, Z6     // t2 = RoundNoKey(t2) ⊕ rc[0]
	VAESENC     Z1, Z2, Z2      // t1 = RoundNoKey(t1) ⊕ s1_x1
	VAESENC     Z5, Z6, Z6      // t2 = RoundNoKey(t2) ⊕ s2_x1
	VAESENCLAST Z3, Z0, Z0      // s1_x0 = FinalRoundNoKey(s1_x0)
	VAESENCLAST Z3, Z4, Z4      // s2_x0 = FinalRoundNoKey(s2_x0)
	VMOVDQA64   Z2, Z1          // s1_x1 = t1
	VMOVDQA64   Z6, Z5          // s2_x1 = t2

	// ===== Round 1 (odd): t = s_x1; ...; s_x1 = FinalRoundNoKey(s_x1); s_x0 = t
	VMOVDQA64   Z1, Z2
	VMOVDQA64   Z5, Z6
	VAESENC     Z17, Z2, Z2     // rc[1]
	VAESENC     Z17, Z6, Z6
	VAESENC     Z0, Z2, Z2
	VAESENC     Z4, Z6, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VMOVDQA64   Z2, Z0
	VMOVDQA64   Z6, Z4

	// ===== Round 2 (even)
	VMOVDQA64   Z0, Z2
	VMOVDQA64   Z4, Z6
	VAESENC     Z18, Z2, Z2     // rc[2]
	VAESENC     Z18, Z6, Z6
	VAESENC     Z1, Z2, Z2
	VAESENC     Z5, Z6, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VMOVDQA64   Z2, Z1
	VMOVDQA64   Z6, Z5

	// ===== Round 3 (odd)
	VMOVDQA64   Z1, Z2
	VMOVDQA64   Z5, Z6
	VAESENC     Z19, Z2, Z2     // rc[3]
	VAESENC     Z19, Z6, Z6
	VAESENC     Z0, Z2, Z2
	VAESENC     Z4, Z6, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VMOVDQA64   Z2, Z0
	VMOVDQA64   Z6, Z4

	// ===== Round 4 (even)
	VMOVDQA64   Z0, Z2
	VMOVDQA64   Z4, Z6
	VAESENC     Z20, Z2, Z2     // rc[4]
	VAESENC     Z20, Z6, Z6
	VAESENC     Z1, Z2, Z2
	VAESENC     Z5, Z6, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VMOVDQA64   Z2, Z1
	VMOVDQA64   Z6, Z5

	// ===== Round 5 (odd)
	VMOVDQA64   Z1, Z2
	VMOVDQA64   Z5, Z6
	VAESENC     Z21, Z2, Z2     // rc[5]
	VAESENC     Z21, Z6, Z6
	VAESENC     Z0, Z2, Z2
	VAESENC     Z4, Z6, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VMOVDQA64   Z2, Z0
	VMOVDQA64   Z6, Z4

	// ===== Round 6 (even)
	VMOVDQA64   Z0, Z2
	VMOVDQA64   Z4, Z6
	VAESENC     Z22, Z2, Z2     // rc[6]
	VAESENC     Z22, Z6, Z6
	VAESENC     Z1, Z2, Z2
	VAESENC     Z5, Z6, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VMOVDQA64   Z2, Z1
	VMOVDQA64   Z6, Z5

	// ===== Round 7 (odd)
	VMOVDQA64   Z1, Z2
	VMOVDQA64   Z5, Z6
	VAESENC     Z23, Z2, Z2     // rc[7]
	VAESENC     Z23, Z6, Z6
	VAESENC     Z0, Z2, Z2
	VAESENC     Z4, Z6, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VMOVDQA64   Z2, Z0
	VMOVDQA64   Z6, Z4

	// ===== Round 8 (even)
	VMOVDQA64   Z0, Z2
	VMOVDQA64   Z4, Z6
	VAESENC     Z24, Z2, Z2     // rc[8]
	VAESENC     Z24, Z6, Z6
	VAESENC     Z1, Z2, Z2
	VAESENC     Z5, Z6, Z6
	VAESENCLAST Z3, Z0, Z0
	VAESENCLAST Z3, Z4, Z4
	VMOVDQA64   Z2, Z1
	VMOVDQA64   Z6, Z5

	// ===== Round 9 (odd)
	VMOVDQA64   Z1, Z2
	VMOVDQA64   Z5, Z6
	VAESENC     Z25, Z2, Z2     // rc[9]
	VAESENC     Z25, Z6, Z6
	VAESENC     Z0, Z2, Z2
	VAESENC     Z4, Z6, Z6
	VAESENCLAST Z3, Z1, Z1
	VAESENCLAST Z3, Z5, Z5
	VMOVDQA64   Z2, Z0
	VMOVDQA64   Z6, Z4

	// SoEM output: state1' ⊕ state2', written back to (s1b0, s1b1).
	VPXORD Z4, Z0, Z0           // s1_x0 = s1_x0' ⊕ s2_x0'
	VPXORD Z5, Z1, Z1           // s1_x1 = s1_x1' ⊕ s2_x1'

	VMOVDQU64 Z0, (AX)
	VMOVDQU64 Z1, (BX)

	VZEROUPPER
	RET
