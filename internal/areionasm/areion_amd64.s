//go:build amd64 && !purego

// AVX-512 + VAES assembly path for 4-way batched Areion permutations.
//
// Each function processes four independent Areion states in parallel
// using `VAESENC` / `VAESENCLAST` on 512-bit ZMM registers. Per round
// the work pattern matches the serial reference in
// `github.com/jedisct1/go-aes/areion.go:areion256PermuteSoftware` /
// `areion512PermuteSoftware` exactly; the only difference is each AES
// operation runs on four lanes simultaneously via VAES instead of
// per-lane AES-NI.
//
// Round constants live in `·AreionRC4x(SB)` (defined in `areion.go`'s
// `init()`), pre-broadcast to four 128-bit copies per ZMM register.
//
// The optimization fusing `RoundNoKey + XOR(rc)` into a single
// `VAESENC RC, state, state` instruction (because `AESENC(s, k) =
// MixColumns(ShiftRows(SubBytes(s))) XOR k` and `RoundNoKey + XOR(k)`
// produces the same result) follows the upstream single-block
// `areion256PermuteAsm` in `jedisct1/go-aes/areion_amd64.s`.

#include "textflag.h"

// func areion256Permutex4Asm(x0, x1 *aes.Block4)
//
// Applies the 10-round Areion256 permutation to four lanes packed in
// SoA layout: `*x0` holds the four lanes' first-half AES blocks
// (Block4 = 64 bytes), `*x1` holds the second-half AES blocks. The
// caller (Go side) is responsible for the AoS <-> SoA pack and the
// matching unpack on return.
//
// Per round (10 rounds total, alternating x0/x1 roles):
//   even r:  temp = x0
//            temp = RoundNoKey(temp) XOR rc[r]      // VAESENC rc, temp
//            temp = RoundNoKey(temp) XOR x1         // VAESENC x1, temp
//            x0   = FinalRoundNoKey(x0)             // VAESENCLAST 0, x0
//            x1   = temp
//   odd r:   symmetric with x0/x1 roles swapped
TEXT ·Areion256Permutex4(SB), NOSPLIT, $0-16
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX

	// Load the two SoA Block4 buffers into Z0 (x0) and Z1 (x1).
	VMOVDQU64 (AX), Z0
	VMOVDQU64 (BX), Z1

	// Z3 = zero (used by VAESENCLAST as the round key for FinalRoundNoKey).
	VPXORD Z3, Z3, Z3

	// Pre-load all 10 round constants into Z16..Z25 (broadcast form already
	// stored in areionRC4x, so a single VMOVDQU64 per RC is sufficient).
	VMOVDQU64 ·AreionRC4x+0(SB), Z16   // rc[0]
	VMOVDQU64 ·AreionRC4x+64(SB), Z17  // rc[1]
	VMOVDQU64 ·AreionRC4x+128(SB), Z18 // rc[2]
	VMOVDQU64 ·AreionRC4x+192(SB), Z19 // rc[3]
	VMOVDQU64 ·AreionRC4x+256(SB), Z20 // rc[4]
	VMOVDQU64 ·AreionRC4x+320(SB), Z21 // rc[5]
	VMOVDQU64 ·AreionRC4x+384(SB), Z22 // rc[6]
	VMOVDQU64 ·AreionRC4x+448(SB), Z23 // rc[7]
	VMOVDQU64 ·AreionRC4x+512(SB), Z24 // rc[8]
	VMOVDQU64 ·AreionRC4x+576(SB), Z25 // rc[9]

	// ----- Round 0 (even): temp=x0; ...; x0=FinalRoundNoKey(x0); x1=temp
	VMOVDQA64 Z0, Z2          // temp = x0
	VAESENC Z16, Z2, Z2       // temp = RoundNoKey(temp) XOR rc[0]
	VAESENC Z1, Z2, Z2        // temp = RoundNoKey(temp) XOR x1
	VAESENCLAST Z3, Z0, Z0    // x0 = FinalRoundNoKey(x0)
	VMOVDQA64 Z2, Z1          // x1 = temp

	// ----- Round 1 (odd): temp=x1; ...; x1=FinalRoundNoKey(x1); x0=temp
	VMOVDQA64 Z1, Z2          // temp = x1
	VAESENC Z17, Z2, Z2       // temp = RoundNoKey(temp) XOR rc[1]
	VAESENC Z0, Z2, Z2        // temp = RoundNoKey(temp) XOR x0
	VAESENCLAST Z3, Z1, Z1    // x1 = FinalRoundNoKey(x1)
	VMOVDQA64 Z2, Z0          // x0 = temp

	// ----- Round 2 (even)
	VMOVDQA64 Z0, Z2
	VAESENC Z18, Z2, Z2       // rc[2]
	VAESENC Z1, Z2, Z2
	VAESENCLAST Z3, Z0, Z0
	VMOVDQA64 Z2, Z1

	// ----- Round 3 (odd)
	VMOVDQA64 Z1, Z2
	VAESENC Z19, Z2, Z2       // rc[3]
	VAESENC Z0, Z2, Z2
	VAESENCLAST Z3, Z1, Z1
	VMOVDQA64 Z2, Z0

	// ----- Round 4 (even)
	VMOVDQA64 Z0, Z2
	VAESENC Z20, Z2, Z2       // rc[4]
	VAESENC Z1, Z2, Z2
	VAESENCLAST Z3, Z0, Z0
	VMOVDQA64 Z2, Z1

	// ----- Round 5 (odd)
	VMOVDQA64 Z1, Z2
	VAESENC Z21, Z2, Z2       // rc[5]
	VAESENC Z0, Z2, Z2
	VAESENCLAST Z3, Z1, Z1
	VMOVDQA64 Z2, Z0

	// ----- Round 6 (even)
	VMOVDQA64 Z0, Z2
	VAESENC Z22, Z2, Z2       // rc[6]
	VAESENC Z1, Z2, Z2
	VAESENCLAST Z3, Z0, Z0
	VMOVDQA64 Z2, Z1

	// ----- Round 7 (odd)
	VMOVDQA64 Z1, Z2
	VAESENC Z23, Z2, Z2       // rc[7]
	VAESENC Z0, Z2, Z2
	VAESENCLAST Z3, Z1, Z1
	VMOVDQA64 Z2, Z0

	// ----- Round 8 (even)
	VMOVDQA64 Z0, Z2
	VAESENC Z24, Z2, Z2       // rc[8]
	VAESENC Z1, Z2, Z2
	VAESENCLAST Z3, Z0, Z0
	VMOVDQA64 Z2, Z1

	// ----- Round 9 (odd)
	VMOVDQA64 Z1, Z2
	VAESENC Z25, Z2, Z2       // rc[9]
	VAESENC Z0, Z2, Z2
	VAESENCLAST Z3, Z1, Z1
	VMOVDQA64 Z2, Z0

	// Store final state back to caller buffers.
	VMOVDQU64 Z0, (AX)
	VMOVDQU64 Z1, (BX)

	VZEROUPPER
	RET

// func Areion512Permutex4(x0, x1, x2, x3 *aes.Block4)
//
// Applies the 15-round Areion512 permutation to four lanes packed in
// SoA layout: each `*xN` holds the four lanes' N-th 16-byte AES block
// contiguously (Block4 = 64 bytes).
//
// Per round (12 main + 3 final = 15 total, four-way state rotation
// `(a,b,c,d) = (x_{i%4}, x_{(i+1)%4}, x_{(i+2)%4}, x_{(i+3)%4})`):
//   temp1 = a; temp1 = RoundNoKey(temp1); b = temp1 XOR b
//   temp2 = c; temp2 = RoundNoKey(temp2); d = temp2 XOR d
//   a = FinalRoundNoKey(a)
//   c = FinalRoundNoKey(c) XOR rc; c = RoundNoKey(c)
//
// The `FinalRoundNoKey(c) XOR rc` step fuses into a single
// `VAESENCLAST rc, c, c` because `AESENCLAST(c, k) = ShiftRows(SubBytes(c)) XOR k`
// and the no-key final round is exactly `ShiftRows(SubBytes(c))`.
//
// After 15 rounds: cyclic state rotation `(x0, x1, x2, x3) →
// (x3, x0, x1, x2)`.
TEXT ·Areion512Permutex4(SB), NOSPLIT, $0-32
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX
	MOVQ x2+16(FP), CX
	MOVQ x3+24(FP), DX

	VMOVDQU64 (AX), Z0  // x0
	VMOVDQU64 (BX), Z1  // x1
	VMOVDQU64 (CX), Z2  // x2
	VMOVDQU64 (DX), Z3  // x3

	VPXORD Z15, Z15, Z15  // Z15 = zero (RoundNoKey / FinalRoundNoKey)

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

	// ===== Round 0 (i=0, i%4=0): a=x0,b=x1,c=x2,d=x3, rc=Z16
	VMOVDQA64 Z0, Z4
	VAESENC Z15, Z4, Z4         // temp1 = RoundNoKey(x0)
	VPXORD Z4, Z1, Z1           // x1 ^= temp1
	VMOVDQA64 Z2, Z5
	VAESENC Z15, Z5, Z5         // temp2 = RoundNoKey(x2)
	VPXORD Z5, Z3, Z3           // x3 ^= temp2
	VAESENCLAST Z15, Z0, Z0     // x0 = FinalRoundNoKey(x0)
	VAESENCLAST Z16, Z2, Z2     // x2 = FinalRoundNoKey(x2) XOR rc[0]
	VAESENC Z15, Z2, Z2         // x2 = RoundNoKey(x2)

	// ===== Round 1 (i=1, i%4=1): a=x1,b=x2,c=x3,d=x0, rc=Z17
	VMOVDQA64 Z1, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z2, Z2
	VMOVDQA64 Z3, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z0, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST Z17, Z3, Z3
	VAESENC Z15, Z3, Z3

	// ===== Round 2 (i=2, i%4=2): a=x2,b=x3,c=x0,d=x1, rc=Z18
	VMOVDQA64 Z2, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z3, Z3
	VMOVDQA64 Z0, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z1, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST Z18, Z0, Z0
	VAESENC Z15, Z0, Z0

	// ===== Round 3 (i=3, i%4=3): a=x3,b=x0,c=x1,d=x2, rc=Z19
	VMOVDQA64 Z3, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z0, Z0
	VMOVDQA64 Z1, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z2, Z2
	VAESENCLAST Z15, Z3, Z3
	VAESENCLAST Z19, Z1, Z1
	VAESENC Z15, Z1, Z1

	// ===== Round 4 (i=4, i%4=0): a=x0,b=x1,c=x2,d=x3, rc=Z20
	VMOVDQA64 Z0, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z1, Z1
	VMOVDQA64 Z2, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z3, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST Z20, Z2, Z2
	VAESENC Z15, Z2, Z2

	// ===== Round 5 (i=5, i%4=1): a=x1,b=x2,c=x3,d=x0, rc=Z21
	VMOVDQA64 Z1, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z2, Z2
	VMOVDQA64 Z3, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z0, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST Z21, Z3, Z3
	VAESENC Z15, Z3, Z3

	// ===== Round 6 (i=6, i%4=2): a=x2,b=x3,c=x0,d=x1, rc=Z22
	VMOVDQA64 Z2, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z3, Z3
	VMOVDQA64 Z0, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z1, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST Z22, Z0, Z0
	VAESENC Z15, Z0, Z0

	// ===== Round 7 (i=7, i%4=3): a=x3,b=x0,c=x1,d=x2, rc=Z23
	VMOVDQA64 Z3, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z0, Z0
	VMOVDQA64 Z1, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z2, Z2
	VAESENCLAST Z15, Z3, Z3
	VAESENCLAST Z23, Z1, Z1
	VAESENC Z15, Z1, Z1

	// ===== Round 8 (i=8, i%4=0): a=x0,b=x1,c=x2,d=x3, rc=Z24
	VMOVDQA64 Z0, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z1, Z1
	VMOVDQA64 Z2, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z3, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST Z24, Z2, Z2
	VAESENC Z15, Z2, Z2

	// ===== Round 9 (i=9, i%4=1): a=x1,b=x2,c=x3,d=x0, rc=Z25
	VMOVDQA64 Z1, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z2, Z2
	VMOVDQA64 Z3, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z0, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST Z25, Z3, Z3
	VAESENC Z15, Z3, Z3

	// ===== Round 10 (i=10, i%4=2): a=x2,b=x3,c=x0,d=x1, rc=Z26
	VMOVDQA64 Z2, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z3, Z3
	VMOVDQA64 Z0, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z1, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST Z26, Z0, Z0
	VAESENC Z15, Z0, Z0

	// ===== Round 11 (i=11, i%4=3): a=x3,b=x0,c=x1,d=x2, rc=Z27
	VMOVDQA64 Z3, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z0, Z0
	VMOVDQA64 Z1, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z2, Z2
	VAESENCLAST Z15, Z3, Z3
	VAESENCLAST Z27, Z1, Z1
	VAESENC Z15, Z1, Z1

	// ===== Final 3 rounds (no rotation across rounds; rolled in
	// (a,b,c,d) the same way as the main loop continues).
	// ===== Round 12 (i=12, i%4=0): a=x0,b=x1,c=x2,d=x3, rc=Z28
	VMOVDQA64 Z0, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z1, Z1
	VMOVDQA64 Z2, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z3, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST Z28, Z2, Z2
	VAESENC Z15, Z2, Z2

	// ===== Round 13 (i=13, i%4=1): a=x1,b=x2,c=x3,d=x0, rc=Z29
	VMOVDQA64 Z1, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z2, Z2
	VMOVDQA64 Z3, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z0, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST Z29, Z3, Z3
	VAESENC Z15, Z3, Z3

	// ===== Round 14 (i=14, i%4=2): a=x2,b=x3,c=x0,d=x1, rc=Z30
	VMOVDQA64 Z2, Z4
	VAESENC Z15, Z4, Z4
	VPXORD Z4, Z3, Z3
	VMOVDQA64 Z0, Z5
	VAESENC Z15, Z5, Z5
	VPXORD Z5, Z1, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST Z30, Z0, Z0
	VAESENC Z15, Z0, Z0

	// Final cyclic rotation: temp=x0; x0=x3; x3=x2; x2=x1; x1=temp
	// Effect: new (x0,x1,x2,x3) = old (x3,x0,x1,x2).
	VMOVDQA64 Z0, Z6   // temp = x0
	VMOVDQA64 Z3, Z0   // x0 = x3
	VMOVDQA64 Z2, Z3   // x3 = x2
	VMOVDQA64 Z1, Z2   // x2 = x1
	VMOVDQA64 Z6, Z1   // x1 = temp

	VMOVDQU64 Z0, (AX)
	VMOVDQU64 Z1, (BX)
	VMOVDQU64 Z2, (CX)
	VMOVDQU64 Z3, (DX)

	VZEROUPPER
	RET

// ─── AVX2 + VAES path (YMM, 256-bit registers, 2 AES blocks per VAES) ────
//
// Drop-in alternative to the AVX-512 functions above for x86_64 CPUs that
// have VAES but no AVX-512 (e.g. Intel Alder Lake E-cores when isolated,
// some AMD Zen 3 SKUs). The same 4-way batched API; instead of packing
// all four lanes into one ZMM, the four lanes are split into two pairs
// and each pair occupies a YMM register. Each VAESENC operates on 2 AES
// blocks per instruction (two lanes' worth of one Areion block); per
// round body the work pattern from the AVX-512 version is replicated
// twice — once for lanes 0-1 and once for lanes 2-3.
//
// Round constants reuse the existing 64-byte AreionRC4x table: a
// 32-byte VMOVDQU load from offset r*64 picks up the first two of the
// four broadcast copies, which is exactly the 2-copy form a YMM
// register wants.
//
// Bit-exact parity invariant identical to the AVX-512 path; verified
// via Test*Avx2*Parity in areion_test.go on every test run.

// func Areion256Permutex4Avx2(x0, x1 *aes.Block4)
//
// State layout in YMM (AVX2 / VEX encoding restricts to Y0..Y15):
//   Y0 = x0 lanes 0-1 (32 bytes)
//   Y1 = x0 lanes 2-3
//   Y2 = x1 lanes 0-1
//   Y3 = x1 lanes 2-3
//   Y4, Y5 = temp pair (a-side and b-side respectively)
//   Y6     = current round constant (loaded fresh per round)
//   Y15    = zero (FinalRoundNoKey)
//   CX     = AreionRC4x base pointer
//
// Round constants are loaded on demand each round (one VMOVDQU into Y6
// per round) rather than pre-loaded into Y16..Y25, because the upper
// 16 YMM registers are EVEX-only and not addressable from VEX-encoded
// AVX2 instructions. Cost: +1 load per round = +10 instructions across
// the function vs the AVX-512 variant; throughput impact negligible
// because the loads pipeline freely with VAESENC issue.
TEXT ·Areion256Permutex4Avx2(SB), NOSPLIT, $0-16
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX

	// Load Block4 buffers as two YMM each (lanes 0-1, lanes 2-3).
	VMOVDQU (AX), Y0
	VMOVDQU 32(AX), Y1
	VMOVDQU (BX), Y2
	VMOVDQU 32(BX), Y3

	VPXOR Y15, Y15, Y15

	LEAQ ·AreionRC4x(SB), CX

	// ===== Round 0 (even): temp = x0; ...; x0 = FinalRoundNoKey(x0); x1 = temp
	VMOVDQU (CX), Y6
	// First lane pair (0-1):
	VMOVDQA Y0, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y2, Y4, Y4
	VAESENCLAST Y15, Y0, Y0
	VMOVDQA Y4, Y2
	// Second lane pair (2-3):
	VMOVDQA Y1, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y3, Y5, Y5
	VAESENCLAST Y15, Y1, Y1
	VMOVDQA Y5, Y3

	// ===== Round 1 (odd)
	VMOVDQU 64(CX), Y6
	VMOVDQA Y2, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y0, Y4, Y4
	VAESENCLAST Y15, Y2, Y2
	VMOVDQA Y4, Y0
	VMOVDQA Y3, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y1, Y5, Y5
	VAESENCLAST Y15, Y3, Y3
	VMOVDQA Y5, Y1

	// ===== Round 2 (even)
	VMOVDQU 128(CX), Y6
	VMOVDQA Y0, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y2, Y4, Y4
	VAESENCLAST Y15, Y0, Y0
	VMOVDQA Y4, Y2
	VMOVDQA Y1, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y3, Y5, Y5
	VAESENCLAST Y15, Y1, Y1
	VMOVDQA Y5, Y3

	// ===== Round 3 (odd)
	VMOVDQU 192(CX), Y6
	VMOVDQA Y2, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y0, Y4, Y4
	VAESENCLAST Y15, Y2, Y2
	VMOVDQA Y4, Y0
	VMOVDQA Y3, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y1, Y5, Y5
	VAESENCLAST Y15, Y3, Y3
	VMOVDQA Y5, Y1

	// ===== Round 4 (even)
	VMOVDQU 256(CX), Y6
	VMOVDQA Y0, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y2, Y4, Y4
	VAESENCLAST Y15, Y0, Y0
	VMOVDQA Y4, Y2
	VMOVDQA Y1, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y3, Y5, Y5
	VAESENCLAST Y15, Y1, Y1
	VMOVDQA Y5, Y3

	// ===== Round 5 (odd)
	VMOVDQU 320(CX), Y6
	VMOVDQA Y2, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y0, Y4, Y4
	VAESENCLAST Y15, Y2, Y2
	VMOVDQA Y4, Y0
	VMOVDQA Y3, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y1, Y5, Y5
	VAESENCLAST Y15, Y3, Y3
	VMOVDQA Y5, Y1

	// ===== Round 6 (even)
	VMOVDQU 384(CX), Y6
	VMOVDQA Y0, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y2, Y4, Y4
	VAESENCLAST Y15, Y0, Y0
	VMOVDQA Y4, Y2
	VMOVDQA Y1, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y3, Y5, Y5
	VAESENCLAST Y15, Y1, Y1
	VMOVDQA Y5, Y3

	// ===== Round 7 (odd)
	VMOVDQU 448(CX), Y6
	VMOVDQA Y2, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y0, Y4, Y4
	VAESENCLAST Y15, Y2, Y2
	VMOVDQA Y4, Y0
	VMOVDQA Y3, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y1, Y5, Y5
	VAESENCLAST Y15, Y3, Y3
	VMOVDQA Y5, Y1

	// ===== Round 8 (even)
	VMOVDQU 512(CX), Y6
	VMOVDQA Y0, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y2, Y4, Y4
	VAESENCLAST Y15, Y0, Y0
	VMOVDQA Y4, Y2
	VMOVDQA Y1, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y3, Y5, Y5
	VAESENCLAST Y15, Y1, Y1
	VMOVDQA Y5, Y3

	// ===== Round 9 (odd)
	VMOVDQU 576(CX), Y6
	VMOVDQA Y2, Y4
	VAESENC Y6, Y4, Y4
	VAESENC Y0, Y4, Y4
	VAESENCLAST Y15, Y2, Y2
	VMOVDQA Y4, Y0
	VMOVDQA Y3, Y5
	VAESENC Y6, Y5, Y5
	VAESENC Y1, Y5, Y5
	VAESENCLAST Y15, Y3, Y3
	VMOVDQA Y5, Y1

	VMOVDQU Y0, (AX)
	VMOVDQU Y1, 32(AX)
	VMOVDQU Y2, (BX)
	VMOVDQU Y3, 32(BX)

	VZEROUPPER
	RET

// func Areion512Permutex4Avx2(x0, x1, x2, x3 *aes.Block4)
//
// State layout in YMM (AVX2 / VEX encoding restricts to Y0..Y15):
//   Y0  = x0 lanes 0-1
//   Y1  = x0 lanes 2-3
//   Y2  = x1 lanes 0-1
//   Y3  = x1 lanes 2-3
//   Y4  = x2 lanes 0-1
//   Y5  = x2 lanes 2-3
//   Y6  = x3 lanes 0-1
//   Y7  = x3 lanes 2-3
//   Y8, Y9   = temp1 pair (a-side, lanes 0-1 and 2-3)
//   Y10, Y11 = temp2 pair (c-side)
//   Y12 = current round constant (loaded fresh per round)
//   Y15 = zero (FinalRoundNoKey / RoundNoKey)
//   CX  = AreionRC4x base pointer
//
// Round body mirrors the AVX-512 path's areion512Round helper twice
// (once per lane pair). The (a, b, c, d) state binding rotates by one
// position per round modulo 4, identical to the serial Areion512
// reference and the AVX-512 implementation.
TEXT ·Areion512Permutex4Avx2(SB), NOSPLIT, $0-32
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX
	MOVQ x2+16(FP), DX
	MOVQ x3+24(FP), SI

	VMOVDQU (AX), Y0
	VMOVDQU 32(AX), Y1
	VMOVDQU (BX), Y2
	VMOVDQU 32(BX), Y3
	VMOVDQU (DX), Y4
	VMOVDQU 32(DX), Y5
	VMOVDQU (SI), Y6
	VMOVDQU 32(SI), Y7

	VPXOR Y15, Y15, Y15
	LEAQ ·AreionRC4x(SB), CX

	// ===== Round 0 (i%4=0): a=Y0/Y1, b=Y2/Y3, c=Y4/Y5, d=Y6/Y7
	VMOVDQU (CX), Y12
	// Lanes 0-1:
	VMOVDQA Y0, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y2, Y2
	VMOVDQA Y4, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y6, Y6
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y12, Y4, Y4
	VAESENC Y15, Y4, Y4
	// Lanes 2-3:
	VMOVDQA Y1, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y3, Y3
	VMOVDQA Y5, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y7, Y7
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y5, Y5

	// ===== Round 1 (i%4=1): a=Y2/Y3, b=Y4/Y5, c=Y6/Y7, d=Y0/Y1
	VMOVDQU 64(CX), Y12
	VMOVDQA Y2, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y4, Y4
	VMOVDQA Y6, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y0, Y0
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y12, Y6, Y6
	VAESENC Y15, Y6, Y6
	VMOVDQA Y3, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y5, Y5
	VMOVDQA Y7, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y1, Y1
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y7, Y7

	// ===== Round 2 (i%4=2): a=Y4/Y5, b=Y6/Y7, c=Y0/Y1, d=Y2/Y3
	VMOVDQU 128(CX), Y12
	VMOVDQA Y4, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y6, Y6
	VMOVDQA Y0, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y2, Y2
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y12, Y0, Y0
	VAESENC Y15, Y0, Y0
	VMOVDQA Y5, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y7, Y7
	VMOVDQA Y1, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y3, Y3
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y1, Y1

	// ===== Round 3 (i%4=3): a=Y6/Y7, b=Y0/Y1, c=Y2/Y3, d=Y4/Y5
	VMOVDQU 192(CX), Y12
	VMOVDQA Y6, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y0, Y0
	VMOVDQA Y2, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y4, Y4
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y12, Y2, Y2
	VAESENC Y15, Y2, Y2
	VMOVDQA Y7, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y1, Y1
	VMOVDQA Y3, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y5, Y5
	VAESENCLAST Y15, Y7, Y7
	VAESENCLAST Y12, Y3, Y3
	VAESENC Y15, Y3, Y3

	// ===== Round 4 (i%4=0)
	VMOVDQU 256(CX), Y12
	VMOVDQA Y0, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y2, Y2
	VMOVDQA Y4, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y6, Y6
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y12, Y4, Y4
	VAESENC Y15, Y4, Y4
	VMOVDQA Y1, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y3, Y3
	VMOVDQA Y5, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y7, Y7
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y5, Y5

	// ===== Round 5 (i%4=1)
	VMOVDQU 320(CX), Y12
	VMOVDQA Y2, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y4, Y4
	VMOVDQA Y6, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y0, Y0
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y12, Y6, Y6
	VAESENC Y15, Y6, Y6
	VMOVDQA Y3, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y5, Y5
	VMOVDQA Y7, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y1, Y1
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y7, Y7

	// ===== Round 6 (i%4=2)
	VMOVDQU 384(CX), Y12
	VMOVDQA Y4, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y6, Y6
	VMOVDQA Y0, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y2, Y2
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y12, Y0, Y0
	VAESENC Y15, Y0, Y0
	VMOVDQA Y5, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y7, Y7
	VMOVDQA Y1, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y3, Y3
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y1, Y1

	// ===== Round 7 (i%4=3)
	VMOVDQU 448(CX), Y12
	VMOVDQA Y6, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y0, Y0
	VMOVDQA Y2, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y4, Y4
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y12, Y2, Y2
	VAESENC Y15, Y2, Y2
	VMOVDQA Y7, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y1, Y1
	VMOVDQA Y3, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y5, Y5
	VAESENCLAST Y15, Y7, Y7
	VAESENCLAST Y12, Y3, Y3
	VAESENC Y15, Y3, Y3

	// ===== Round 8 (i%4=0)
	VMOVDQU 512(CX), Y12
	VMOVDQA Y0, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y2, Y2
	VMOVDQA Y4, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y6, Y6
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y12, Y4, Y4
	VAESENC Y15, Y4, Y4
	VMOVDQA Y1, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y3, Y3
	VMOVDQA Y5, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y7, Y7
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y5, Y5

	// ===== Round 9 (i%4=1)
	VMOVDQU 576(CX), Y12
	VMOVDQA Y2, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y4, Y4
	VMOVDQA Y6, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y0, Y0
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y12, Y6, Y6
	VAESENC Y15, Y6, Y6
	VMOVDQA Y3, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y5, Y5
	VMOVDQA Y7, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y1, Y1
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y7, Y7

	// ===== Round 10 (i%4=2)
	VMOVDQU 640(CX), Y12
	VMOVDQA Y4, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y6, Y6
	VMOVDQA Y0, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y2, Y2
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y12, Y0, Y0
	VAESENC Y15, Y0, Y0
	VMOVDQA Y5, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y7, Y7
	VMOVDQA Y1, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y3, Y3
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y1, Y1

	// ===== Round 11 (i%4=3)
	VMOVDQU 704(CX), Y12
	VMOVDQA Y6, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y0, Y0
	VMOVDQA Y2, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y4, Y4
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y12, Y2, Y2
	VAESENC Y15, Y2, Y2
	VMOVDQA Y7, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y1, Y1
	VMOVDQA Y3, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y5, Y5
	VAESENCLAST Y15, Y7, Y7
	VAESENCLAST Y12, Y3, Y3
	VAESENC Y15, Y3, Y3

	// ===== Final 3 rounds (i=12,13,14: i%4 = 0, 1, 2)
	// ===== Round 12 (i%4=0)
	VMOVDQU 768(CX), Y12
	VMOVDQA Y0, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y2, Y2
	VMOVDQA Y4, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y6, Y6
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y12, Y4, Y4
	VAESENC Y15, Y4, Y4
	VMOVDQA Y1, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y3, Y3
	VMOVDQA Y5, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y7, Y7
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y5, Y5

	// ===== Round 13 (i%4=1)
	VMOVDQU 832(CX), Y12
	VMOVDQA Y2, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y4, Y4
	VMOVDQA Y6, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y0, Y0
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y12, Y6, Y6
	VAESENC Y15, Y6, Y6
	VMOVDQA Y3, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y5, Y5
	VMOVDQA Y7, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y1, Y1
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y7, Y7

	// ===== Round 14 (i%4=2)
	VMOVDQU 896(CX), Y12
	VMOVDQA Y4, Y8
	VAESENC Y15, Y8, Y8
	VPXOR Y8, Y6, Y6
	VMOVDQA Y0, Y10
	VAESENC Y15, Y10, Y10
	VPXOR Y10, Y2, Y2
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y12, Y0, Y0
	VAESENC Y15, Y0, Y0
	VMOVDQA Y5, Y9
	VAESENC Y15, Y9, Y9
	VPXOR Y9, Y7, Y7
	VMOVDQA Y1, Y11
	VAESENC Y15, Y11, Y11
	VPXOR Y11, Y3, Y3
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y1, Y1

	// Final cyclic rotation: temp=x0; x0=x3; x3=x2; x2=x1; x1=temp
	// Effect: new (x0,x1,x2,x3) = old (x3,x0,x1,x2)
	// In YMM pairs: (Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7) → (Y6,Y7,Y0,Y1,Y2,Y3,Y4,Y5)
	// Save x0 lanes pair to Y8/Y9 (free now post-rounds), then chain.
	VMOVDQA Y0, Y8
	VMOVDQA Y1, Y9
	VMOVDQA Y6, Y0
	VMOVDQA Y7, Y1
	VMOVDQA Y4, Y6
	VMOVDQA Y5, Y7
	VMOVDQA Y2, Y4
	VMOVDQA Y3, Y5
	VMOVDQA Y8, Y2
	VMOVDQA Y9, Y3

	VMOVDQU Y0, (AX)
	VMOVDQU Y1, 32(AX)
	VMOVDQU Y2, (BX)
	VMOVDQU Y3, 32(BX)
	VMOVDQU Y4, (DX)
	VMOVDQU Y5, 32(DX)
	VMOVDQU Y6, (SI)
	VMOVDQU Y7, 32(SI)

	VZEROUPPER
	RET
