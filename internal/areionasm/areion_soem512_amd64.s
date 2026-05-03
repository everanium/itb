//go:build amd64 && !purego && !noitbasm

// Fused AVX-512 + VAES kernel for the Areion-SoEM-512 4-way batched
// PRF. Mirrors the SoEM-256 fused kernel one tier up:
//
//  1. Loads the 15 Areion512 round constants once (vs twice for two
//     separate `Areion512Permutex4` calls).
//  2. Interleaves the state1 and state2 round bodies — two
//     independent VAES dependency chains issued in lock-step,
//     masking the 5-cycle VAESENC latency on Intel Sunny Cove /
//     Cypress Cove (Rocket Lake i7-11700K) and AMD Zen 4. With one
//     ZMM-VAESENC issuing per cycle and a 9-instruction round body
//     ending in a multi-step `c = FinalRoundNoKey(c) ⊕ rc; c =
//     RoundNoKey(c)` dependency chain, the second state's VAESENC
//     instructions slot into the latency gaps left by the first.
//  3. Performs the final cyclic state rotation `(x0,x1,x2,x3) →
//     (x3,x0,x1,x2)` fused with the SoEM output XOR and the
//     writeback to (a1, b1, c1, d1) — the rotation only renames
//     register roles, so the rotated XOR pattern (Z3⊕Z11 → a1, ...)
//     uses the existing register contents directly.
//  4. Reuses the same `·AreionRC4x` 64-byte pre-broadcast round-
//     constant table as the per-half kernel.

#include "textflag.h"

// func Areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4)
//
// Caller is responsible for the SoEM input setup:
//
//   (a1, b1, c1, d1) = input ⊕ key1                    (SoA Block4 layout)
//   (a2, b2, c2, d2) = input ⊕ key2 ⊕ domainSep
//
// The kernel runs both 15-round Areion512 permutations interleaved,
// applies the final cyclic rotation `(x0,x1,x2,x3) → (x3,x0,x1,x2)`
// fused with the SoEM XOR `state1' ⊕ state2'`, and writes the
// result back to (a1, b1, c1, d1). The state2 buffers are scratch
// and their contents after the call are unspecified.
//
// Per round (15 rounds, (a,b,c,d) rotates by `i%4`):
//
//   temp1 = a;  temp1 = RoundNoKey(temp1);  b ^= temp1
//   temp2 = c;  temp2 = RoundNoKey(temp2);  d ^= temp2
//   a = FinalRoundNoKey(a)
//   c = FinalRoundNoKey(c) ⊕ rc;  c = RoundNoKey(c)
//
// In the interleaved layout, every state1 step is followed by the
// corresponding state2 step on independent registers (Z0..Z3 vs
// Z8..Z11, with temps Z4/Z5 vs Z12/Z13).
TEXT ·Areion512SoEMPermutex4Interleaved(SB), NOSPLIT, $0-64
	MOVQ a1+0(FP),  AX
	MOVQ b1+8(FP),  BX
	MOVQ c1+16(FP), CX
	MOVQ d1+24(FP), DX
	MOVQ a2+32(FP), SI
	MOVQ b2+40(FP), DI
	MOVQ c2+48(FP), R8
	MOVQ d2+56(FP), R9

	// Load both states. After this point SI/DI/R8/R9 are unused —
	// the SoEM output writeback at the end goes back through
	// AX/BX/CX/DX (the state1 buffers).
	VMOVDQU64 (AX), Z0   // state1.x0
	VMOVDQU64 (BX), Z1   // state1.x1
	VMOVDQU64 (CX), Z2   // state1.x2
	VMOVDQU64 (DX), Z3   // state1.x3
	VMOVDQU64 (SI), Z8   // state2.x0
	VMOVDQU64 (DI), Z9   // state2.x1
	VMOVDQU64 (R8), Z10  // state2.x2
	VMOVDQU64 (R9), Z11  // state2.x3

	VPXORD Z6, Z6, Z6    // Z6 = zero (RoundNoKey / FinalRoundNoKey "key")

	// Pre-load all 15 round constants Z16..Z30.
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
	VMOVDQU64 ·AreionRC4x+640(SB), Z26  // rc[10]
	VMOVDQU64 ·AreionRC4x+704(SB), Z27  // rc[11]
	VMOVDQU64 ·AreionRC4x+768(SB), Z28  // rc[12]
	VMOVDQU64 ·AreionRC4x+832(SB), Z29  // rc[13]
	VMOVDQU64 ·AreionRC4x+896(SB), Z30  // rc[14]

	// ===== Round 0 (i%4=0): (a,b,c,d) = (x0,x1,x2,x3); rc=Z16
	// state1: a=Z0, b=Z1, c=Z2, d=Z3 ; state2: a=Z8, b=Z9, c=Z10, d=Z11
	VMOVDQA64   Z0, Z4
	VMOVDQA64   Z8, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z1, Z1
	VPXORD      Z12, Z9, Z9
	VMOVDQA64   Z2, Z5
	VMOVDQA64   Z10, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z3, Z3
	VPXORD      Z13, Z11, Z11
	VAESENCLAST Z6, Z0, Z0
	VAESENCLAST Z6, Z8, Z8
	VAESENCLAST Z16, Z2, Z2
	VAESENCLAST Z16, Z10, Z10
	VAESENC     Z6, Z2, Z2
	VAESENC     Z6, Z10, Z10

	// ===== Round 1 (i%4=1): (a,b,c,d) = (x1,x2,x3,x0); rc=Z17
	// state1: a=Z1, b=Z2, c=Z3, d=Z0 ; state2: a=Z9, b=Z10, c=Z11, d=Z8
	VMOVDQA64   Z1, Z4
	VMOVDQA64   Z9, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z2, Z2
	VPXORD      Z12, Z10, Z10
	VMOVDQA64   Z3, Z5
	VMOVDQA64   Z11, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z0, Z0
	VPXORD      Z13, Z8, Z8
	VAESENCLAST Z6, Z1, Z1
	VAESENCLAST Z6, Z9, Z9
	VAESENCLAST Z17, Z3, Z3
	VAESENCLAST Z17, Z11, Z11
	VAESENC     Z6, Z3, Z3
	VAESENC     Z6, Z11, Z11

	// ===== Round 2 (i%4=2): (a,b,c,d) = (x2,x3,x0,x1); rc=Z18
	// state1: a=Z2, b=Z3, c=Z0, d=Z1 ; state2: a=Z10, b=Z11, c=Z8, d=Z9
	VMOVDQA64   Z2, Z4
	VMOVDQA64   Z10, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z3, Z3
	VPXORD      Z12, Z11, Z11
	VMOVDQA64   Z0, Z5
	VMOVDQA64   Z8, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z1, Z1
	VPXORD      Z13, Z9, Z9
	VAESENCLAST Z6, Z2, Z2
	VAESENCLAST Z6, Z10, Z10
	VAESENCLAST Z18, Z0, Z0
	VAESENCLAST Z18, Z8, Z8
	VAESENC     Z6, Z0, Z0
	VAESENC     Z6, Z8, Z8

	// ===== Round 3 (i%4=3): (a,b,c,d) = (x3,x0,x1,x2); rc=Z19
	// state1: a=Z3, b=Z0, c=Z1, d=Z2 ; state2: a=Z11, b=Z8, c=Z9, d=Z10
	VMOVDQA64   Z3, Z4
	VMOVDQA64   Z11, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z0, Z0
	VPXORD      Z12, Z8, Z8
	VMOVDQA64   Z1, Z5
	VMOVDQA64   Z9, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z2, Z2
	VPXORD      Z13, Z10, Z10
	VAESENCLAST Z6, Z3, Z3
	VAESENCLAST Z6, Z11, Z11
	VAESENCLAST Z19, Z1, Z1
	VAESENCLAST Z19, Z9, Z9
	VAESENC     Z6, Z1, Z1
	VAESENC     Z6, Z9, Z9

	// ===== Round 4 (i%4=0); rc=Z20
	VMOVDQA64   Z0, Z4
	VMOVDQA64   Z8, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z1, Z1
	VPXORD      Z12, Z9, Z9
	VMOVDQA64   Z2, Z5
	VMOVDQA64   Z10, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z3, Z3
	VPXORD      Z13, Z11, Z11
	VAESENCLAST Z6, Z0, Z0
	VAESENCLAST Z6, Z8, Z8
	VAESENCLAST Z20, Z2, Z2
	VAESENCLAST Z20, Z10, Z10
	VAESENC     Z6, Z2, Z2
	VAESENC     Z6, Z10, Z10

	// ===== Round 5 (i%4=1); rc=Z21
	VMOVDQA64   Z1, Z4
	VMOVDQA64   Z9, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z2, Z2
	VPXORD      Z12, Z10, Z10
	VMOVDQA64   Z3, Z5
	VMOVDQA64   Z11, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z0, Z0
	VPXORD      Z13, Z8, Z8
	VAESENCLAST Z6, Z1, Z1
	VAESENCLAST Z6, Z9, Z9
	VAESENCLAST Z21, Z3, Z3
	VAESENCLAST Z21, Z11, Z11
	VAESENC     Z6, Z3, Z3
	VAESENC     Z6, Z11, Z11

	// ===== Round 6 (i%4=2); rc=Z22
	VMOVDQA64   Z2, Z4
	VMOVDQA64   Z10, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z3, Z3
	VPXORD      Z12, Z11, Z11
	VMOVDQA64   Z0, Z5
	VMOVDQA64   Z8, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z1, Z1
	VPXORD      Z13, Z9, Z9
	VAESENCLAST Z6, Z2, Z2
	VAESENCLAST Z6, Z10, Z10
	VAESENCLAST Z22, Z0, Z0
	VAESENCLAST Z22, Z8, Z8
	VAESENC     Z6, Z0, Z0
	VAESENC     Z6, Z8, Z8

	// ===== Round 7 (i%4=3); rc=Z23
	VMOVDQA64   Z3, Z4
	VMOVDQA64   Z11, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z0, Z0
	VPXORD      Z12, Z8, Z8
	VMOVDQA64   Z1, Z5
	VMOVDQA64   Z9, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z2, Z2
	VPXORD      Z13, Z10, Z10
	VAESENCLAST Z6, Z3, Z3
	VAESENCLAST Z6, Z11, Z11
	VAESENCLAST Z23, Z1, Z1
	VAESENCLAST Z23, Z9, Z9
	VAESENC     Z6, Z1, Z1
	VAESENC     Z6, Z9, Z9

	// ===== Round 8 (i%4=0); rc=Z24
	VMOVDQA64   Z0, Z4
	VMOVDQA64   Z8, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z1, Z1
	VPXORD      Z12, Z9, Z9
	VMOVDQA64   Z2, Z5
	VMOVDQA64   Z10, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z3, Z3
	VPXORD      Z13, Z11, Z11
	VAESENCLAST Z6, Z0, Z0
	VAESENCLAST Z6, Z8, Z8
	VAESENCLAST Z24, Z2, Z2
	VAESENCLAST Z24, Z10, Z10
	VAESENC     Z6, Z2, Z2
	VAESENC     Z6, Z10, Z10

	// ===== Round 9 (i%4=1); rc=Z25
	VMOVDQA64   Z1, Z4
	VMOVDQA64   Z9, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z2, Z2
	VPXORD      Z12, Z10, Z10
	VMOVDQA64   Z3, Z5
	VMOVDQA64   Z11, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z0, Z0
	VPXORD      Z13, Z8, Z8
	VAESENCLAST Z6, Z1, Z1
	VAESENCLAST Z6, Z9, Z9
	VAESENCLAST Z25, Z3, Z3
	VAESENCLAST Z25, Z11, Z11
	VAESENC     Z6, Z3, Z3
	VAESENC     Z6, Z11, Z11

	// ===== Round 10 (i%4=2); rc=Z26
	VMOVDQA64   Z2, Z4
	VMOVDQA64   Z10, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z3, Z3
	VPXORD      Z12, Z11, Z11
	VMOVDQA64   Z0, Z5
	VMOVDQA64   Z8, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z1, Z1
	VPXORD      Z13, Z9, Z9
	VAESENCLAST Z6, Z2, Z2
	VAESENCLAST Z6, Z10, Z10
	VAESENCLAST Z26, Z0, Z0
	VAESENCLAST Z26, Z8, Z8
	VAESENC     Z6, Z0, Z0
	VAESENC     Z6, Z8, Z8

	// ===== Round 11 (i%4=3); rc=Z27
	VMOVDQA64   Z3, Z4
	VMOVDQA64   Z11, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z0, Z0
	VPXORD      Z12, Z8, Z8
	VMOVDQA64   Z1, Z5
	VMOVDQA64   Z9, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z2, Z2
	VPXORD      Z13, Z10, Z10
	VAESENCLAST Z6, Z3, Z3
	VAESENCLAST Z6, Z11, Z11
	VAESENCLAST Z27, Z1, Z1
	VAESENCLAST Z27, Z9, Z9
	VAESENC     Z6, Z1, Z1
	VAESENC     Z6, Z9, Z9

	// ===== Round 12 (i%4=0); rc=Z28 — first of final 3
	VMOVDQA64   Z0, Z4
	VMOVDQA64   Z8, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z1, Z1
	VPXORD      Z12, Z9, Z9
	VMOVDQA64   Z2, Z5
	VMOVDQA64   Z10, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z3, Z3
	VPXORD      Z13, Z11, Z11
	VAESENCLAST Z6, Z0, Z0
	VAESENCLAST Z6, Z8, Z8
	VAESENCLAST Z28, Z2, Z2
	VAESENCLAST Z28, Z10, Z10
	VAESENC     Z6, Z2, Z2
	VAESENC     Z6, Z10, Z10

	// ===== Round 13 (i%4=1); rc=Z29
	VMOVDQA64   Z1, Z4
	VMOVDQA64   Z9, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z2, Z2
	VPXORD      Z12, Z10, Z10
	VMOVDQA64   Z3, Z5
	VMOVDQA64   Z11, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z0, Z0
	VPXORD      Z13, Z8, Z8
	VAESENCLAST Z6, Z1, Z1
	VAESENCLAST Z6, Z9, Z9
	VAESENCLAST Z29, Z3, Z3
	VAESENCLAST Z29, Z11, Z11
	VAESENC     Z6, Z3, Z3
	VAESENC     Z6, Z11, Z11

	// ===== Round 14 (i%4=2); rc=Z30
	VMOVDQA64   Z2, Z4
	VMOVDQA64   Z10, Z12
	VAESENC     Z6, Z4, Z4
	VAESENC     Z6, Z12, Z12
	VPXORD      Z4, Z3, Z3
	VPXORD      Z12, Z11, Z11
	VMOVDQA64   Z0, Z5
	VMOVDQA64   Z8, Z13
	VAESENC     Z6, Z5, Z5
	VAESENC     Z6, Z13, Z13
	VPXORD      Z5, Z1, Z1
	VPXORD      Z13, Z9, Z9
	VAESENCLAST Z6, Z2, Z2
	VAESENCLAST Z6, Z10, Z10
	VAESENCLAST Z30, Z0, Z0
	VAESENCLAST Z30, Z8, Z8
	VAESENC     Z6, Z0, Z0
	VAESENC     Z6, Z8, Z8

	// ===== Final cyclic rotation fused with SoEM XOR + writeback.
	//
	// Pre-rotation state1 = (Z0, Z1, Z2, Z3) holding (x0, x1, x2, x3).
	// Rotation: (x0', x1', x2', x3') = (x3, x0, x1, x2).
	// SoEM output: state1' ⊕ state2' per Block4, written to (a1..d1).
	//
	//   *a1 = rotated_x0 = (state1.x3) ⊕ (state2.x3) = Z3 ⊕ Z11
	//   *b1 = rotated_x1 = (state1.x0) ⊕ (state2.x0) = Z0 ⊕ Z8
	//   *c1 = rotated_x2 = (state1.x1) ⊕ (state2.x1) = Z1 ⊕ Z9
	//   *d1 = rotated_x3 = (state1.x2) ⊕ (state2.x2) = Z2 ⊕ Z10
	//
	// 8 instructions (4 XOR + 4 store) — no VMOVDQA64 rotation chain.
	VPXORD     Z11, Z3, Z3
	VMOVDQU64  Z3, (AX)
	VPXORD     Z8, Z0, Z0
	VMOVDQU64  Z0, (BX)
	VPXORD     Z9, Z1, Z1
	VMOVDQU64  Z1, (CX)
	VPXORD     Z10, Z2, Z2
	VMOVDQU64  Z2, (DX)

	VZEROUPPER
	RET
