//go:build amd64 && !purego && !noitbasm

// AVX-512 + VAES assembly path for 4-way batched Areion permutations.
//
// Each function processes four independent Areion states in parallel
// using `VAESENC` / `VAESENCLAST` on 512-bit ZMM registers. Per round
// the work pattern matches the serial reference in
// `github.com/everanium/areion` (`areion256PermuteSoftwareRC` /
// `areion512PermuteSoftwareRC`) exactly; the only difference is each AES
// operation runs on four lanes simultaneously via VAES instead of
// per-lane AES-NI.
//
// Every kernel takes the round-constant table to run under as its last
// argument: `·AreionRC4x` (the P1 permutation) or `·AreionRC4x2` (the
// P2 permutation of SoEM22), both populated by `areionasm_amd64.go`'s
// `init()` and pre-broadcast to four 128-bit copies per ZMM register.
//
// The optimization fusing `RoundNoKey + XOR(rc)` into a single
// `VAESENC RC, state, state` instruction (because `AESENC(s, k) =
// MixColumns(ShiftRows(SubBytes(s))) XOR k` and `RoundNoKey + XOR(k)`
// produces the same result) follows the single-block
// `areion256PermuteRCAsm` in `github.com/everanium/areion`.

#include "textflag.h"

// func areion256Permutex4RC(x0, x1 *areion.Block4, rc *[15 * 64]byte)
//
// Applies the 10-round Areion256 permutation under the constant table
// rc to four lanes packed in SoA layout: `*x0` holds the four lanes'
// first-half AES blocks (Block4 = 64 bytes), `*x1` holds the
// second-half AES blocks. The caller (Go side) is responsible for the
// AoS → SoA pack and the matching unpack on return.
//
// Per round (10 rounds total, alternating x0/x1 roles):
//   even r:  ta = VAESENC(x0, rc[r])                // RoundNoKey(x0) XOR rc[r]
//            x0 = FinalRoundNoKey(x0)               // VAESENCLAST 0, x0, x0
//            x1 = VAESENC(ta, x1)                   // RoundNoKey(ta) XOR x1
//   odd r:   symmetric with x0/x1 roles swapped
TEXT ·areion256Permutex4RC(SB), NOSPLIT, $0-24
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX
	MOVQ rc+16(FP), CX
	VMOVDQU64 (AX), Z0
	VMOVDQU64 (BX), Z1
	VPXORD Z3, Z3, Z3
	VAESENC 0(CX), Z0, Z2
	VAESENCLAST Z3, Z0, Z0
	VAESENC Z1, Z2, Z1
	VAESENC 64(CX), Z1, Z2
	VAESENCLAST Z3, Z1, Z1
	VAESENC Z0, Z2, Z0
	VAESENC 128(CX), Z0, Z2
	VAESENCLAST Z3, Z0, Z0
	VAESENC Z1, Z2, Z1
	VAESENC 192(CX), Z1, Z2
	VAESENCLAST Z3, Z1, Z1
	VAESENC Z0, Z2, Z0
	VAESENC 256(CX), Z0, Z2
	VAESENCLAST Z3, Z0, Z0
	VAESENC Z1, Z2, Z1
	VAESENC 320(CX), Z1, Z2
	VAESENCLAST Z3, Z1, Z1
	VAESENC Z0, Z2, Z0
	VAESENC 384(CX), Z0, Z2
	VAESENCLAST Z3, Z0, Z0
	VAESENC Z1, Z2, Z1
	VAESENC 448(CX), Z1, Z2
	VAESENCLAST Z3, Z1, Z1
	VAESENC Z0, Z2, Z0
	VAESENC 512(CX), Z0, Z2
	VAESENCLAST Z3, Z0, Z0
	VAESENC Z1, Z2, Z1
	VAESENC 576(CX), Z1, Z2
	VAESENCLAST Z3, Z1, Z1
	VAESENC Z0, Z2, Z0
	VMOVDQU64 Z0, (AX)
	VMOVDQU64 Z1, (BX)
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VZEROUPPER
	RET

// func areion512Permutex4RC(x0, x1, x2, x3 *areion.Block4, rc *[15 * 64]byte)
//
// Applies the 15-round Areion512 permutation to four lanes packed in
// SoA layout: each `*xN` holds the four lanes' N-th 16-byte AES block
// contiguously (Block4 = 64 bytes).
//
// Per round (12 main + 3 final = 15 total, four-way state rotation
// `(a,b,c,d) = (x_{i%4}, x_{(i+1)%4}, x_{(i+2)%4}, x_{(i+3)%4})`):
//   b = VAESENC(a, b)               // RoundNoKey(a) XOR b
//   d = VAESENC(c, d)               // RoundNoKey(c) XOR d
//   a = FinalRoundNoKey(a)
//   c = FinalRoundNoKey(c) XOR rc; c = RoundNoKey(c)
//
// The `FinalRoundNoKey(c) XOR rc` step fuses into a single
// `VAESENCLAST rc, c, c` because `AESENCLAST(c, k) = ShiftRows(SubBytes(c)) XOR k`
// and the no-key final round is exactly `ShiftRows(SubBytes(c))`.
//
// After 15 rounds: cyclic state rotation `(x0, x1, x2, x3) →
// (x3, x0, x1, x2)`.
TEXT ·areion512Permutex4RC(SB), NOSPLIT, $0-40
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX
	MOVQ x2+16(FP), CX
	MOVQ x3+24(FP), DX
	MOVQ rc+32(FP), SI
	VMOVDQU64 (AX), Z0
	VMOVDQU64 (BX), Z1
	VMOVDQU64 (CX), Z2
	VMOVDQU64 (DX), Z3
	VPXORD Z15, Z15, Z15
	VAESENC Z1, Z0, Z1
	VAESENC Z3, Z2, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST 0(SI), Z2, Z2
	VAESENC Z15, Z2, Z2
	VAESENC Z2, Z1, Z2
	VAESENC Z0, Z3, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST 64(SI), Z3, Z3
	VAESENC Z15, Z3, Z3
	VAESENC Z3, Z2, Z3
	VAESENC Z1, Z0, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST 128(SI), Z0, Z0
	VAESENC Z15, Z0, Z0
	VAESENC Z0, Z3, Z0
	VAESENC Z2, Z1, Z2
	VAESENCLAST Z15, Z3, Z3
	VAESENCLAST 192(SI), Z1, Z1
	VAESENC Z15, Z1, Z1
	VAESENC Z1, Z0, Z1
	VAESENC Z3, Z2, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST 256(SI), Z2, Z2
	VAESENC Z15, Z2, Z2
	VAESENC Z2, Z1, Z2
	VAESENC Z0, Z3, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST 320(SI), Z3, Z3
	VAESENC Z15, Z3, Z3
	VAESENC Z3, Z2, Z3
	VAESENC Z1, Z0, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST 384(SI), Z0, Z0
	VAESENC Z15, Z0, Z0
	VAESENC Z0, Z3, Z0
	VAESENC Z2, Z1, Z2
	VAESENCLAST Z15, Z3, Z3
	VAESENCLAST 448(SI), Z1, Z1
	VAESENC Z15, Z1, Z1
	VAESENC Z1, Z0, Z1
	VAESENC Z3, Z2, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST 512(SI), Z2, Z2
	VAESENC Z15, Z2, Z2
	VAESENC Z2, Z1, Z2
	VAESENC Z0, Z3, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST 576(SI), Z3, Z3
	VAESENC Z15, Z3, Z3
	VAESENC Z3, Z2, Z3
	VAESENC Z1, Z0, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST 640(SI), Z0, Z0
	VAESENC Z15, Z0, Z0
	VAESENC Z0, Z3, Z0
	VAESENC Z2, Z1, Z2
	VAESENCLAST Z15, Z3, Z3
	VAESENCLAST 704(SI), Z1, Z1
	VAESENC Z15, Z1, Z1
	VAESENC Z1, Z0, Z1
	VAESENC Z3, Z2, Z3
	VAESENCLAST Z15, Z0, Z0
	VAESENCLAST 768(SI), Z2, Z2
	VAESENC Z15, Z2, Z2
	VAESENC Z2, Z1, Z2
	VAESENC Z0, Z3, Z0
	VAESENCLAST Z15, Z1, Z1
	VAESENCLAST 832(SI), Z3, Z3
	VAESENC Z15, Z3, Z3
	VAESENC Z3, Z2, Z3
	VAESENC Z1, Z0, Z1
	VAESENCLAST Z15, Z2, Z2
	VAESENCLAST 896(SI), Z0, Z0
	VAESENC Z15, Z0, Z0
	VMOVDQU64 Z3, (AX)
	VMOVDQU64 Z0, (BX)
	VMOVDQU64 Z1, (CX)
	VMOVDQU64 Z2, (DX)
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X3, X3, X3
	VZEROUPPER
	RET

// ─── AVX2 + VAES path (YMM, 256-bit registers, 2 AES blocks per VAES) ────
//
// Drop-in alternative to the AVX-512 functions above for x86-64 CPUs that
// have VAES but no AVX-512 (e.g. Intel Alder Lake E-cores when isolated,
// some AMD Zen 3 SKUs). The same 4-way batched API; instead of packing
// all four lanes into one ZMM, the four lanes are split into two pairs
// and each pair occupies a YMM register. Each VAESENC operates on 2 AES
// blocks per instruction (two lanes' worth of one Areion block); per
// round body the work pattern from the AVX-512 version is replicated
// twice — once for lanes 0-1 and once for lanes 2-3.
//
// Round constants come from the 64-byte-stride broadcast table passed
// as the rc argument (AreionRC4x for P1, AreionRC4x2 for P2): a 32-byte
// VMOVDQU load from offset r*64 picks up the first two of the four
// broadcast copies, which is exactly the 2-copy form a YMM register
// wants.
//
// Bit-exact parity invariant identical to the AVX-512 path; verified
// via Test*Avx2*Parity in areion_test.go on every test run.

// func areion256Permutex4Avx2RC(x0, x1 *areion.Block4, rc *[15 * 64]byte)
//
// State layout in YMM (AVX2 / VEX encoding restricts to Y0..Y15):
//   Y0 = x0 lanes 0-1 (32 bytes)
//   Y1 = x0 lanes 2-3
//   Y2 = x1 lanes 0-1
//   Y3 = x1 lanes 2-3
//   Y4, Y5 = temp pair (lanes 0-1 and lanes 2-3 respectively)
//   Y6     = current round constant (loaded fresh per round)
//   Y15    = zero (FinalRoundNoKey)
//   CX     = round-constant table base pointer (rc argument)
TEXT ·areion256Permutex4Avx2RC(SB), NOSPLIT, $0-24
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX
	MOVQ rc+16(FP), CX
	VMOVDQU 0(AX), Y0
	VMOVDQU 32(AX), Y1
	VMOVDQU 0(BX), Y2
	VMOVDQU 32(BX), Y3
	VPXOR Y15, Y15, Y15
	VMOVDQU 0(CX), Y6
	VAESENC Y6, Y0, Y4
	VAESENC Y6, Y1, Y5
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENC Y2, Y4, Y2
	VAESENC Y3, Y5, Y3
	VMOVDQU 64(CX), Y6
	VAESENC Y6, Y2, Y4
	VAESENC Y6, Y3, Y5
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENC Y0, Y4, Y0
	VAESENC Y1, Y5, Y1
	VMOVDQU 128(CX), Y6
	VAESENC Y6, Y0, Y4
	VAESENC Y6, Y1, Y5
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENC Y2, Y4, Y2
	VAESENC Y3, Y5, Y3
	VMOVDQU 192(CX), Y6
	VAESENC Y6, Y2, Y4
	VAESENC Y6, Y3, Y5
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENC Y0, Y4, Y0
	VAESENC Y1, Y5, Y1
	VMOVDQU 256(CX), Y6
	VAESENC Y6, Y0, Y4
	VAESENC Y6, Y1, Y5
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENC Y2, Y4, Y2
	VAESENC Y3, Y5, Y3
	VMOVDQU 320(CX), Y6
	VAESENC Y6, Y2, Y4
	VAESENC Y6, Y3, Y5
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENC Y0, Y4, Y0
	VAESENC Y1, Y5, Y1
	VMOVDQU 384(CX), Y6
	VAESENC Y6, Y0, Y4
	VAESENC Y6, Y1, Y5
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENC Y2, Y4, Y2
	VAESENC Y3, Y5, Y3
	VMOVDQU 448(CX), Y6
	VAESENC Y6, Y2, Y4
	VAESENC Y6, Y3, Y5
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENC Y0, Y4, Y0
	VAESENC Y1, Y5, Y1
	VMOVDQU 512(CX), Y6
	VAESENC Y6, Y0, Y4
	VAESENC Y6, Y1, Y5
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENC Y2, Y4, Y2
	VAESENC Y3, Y5, Y3
	VMOVDQU 576(CX), Y6
	VAESENC Y6, Y2, Y4
	VAESENC Y6, Y3, Y5
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENC Y0, Y4, Y0
	VAESENC Y1, Y5, Y1
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
	VZEROUPPER
	RET

// func areion512Permutex4Avx2RC(x0, x1, x2, x3 *areion.Block4, rc *[15 * 64]byte)
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
//   Y12 = current round constant (loaded fresh per round)
//   Y15 = zero (FinalRoundNoKey / RoundNoKey)
//   CX  = round-constant table base pointer (rc argument)
TEXT ·areion512Permutex4Avx2RC(SB), NOSPLIT, $0-40
	MOVQ x0+0(FP), AX
	MOVQ x1+8(FP), BX
	MOVQ x2+16(FP), DX
	MOVQ x3+24(FP), SI
	MOVQ rc+32(FP), CX
	VMOVDQU 0(AX), Y0
	VMOVDQU 32(AX), Y1
	VMOVDQU 0(BX), Y2
	VMOVDQU 32(BX), Y3
	VMOVDQU 0(DX), Y4
	VMOVDQU 32(DX), Y5
	VMOVDQU 0(SI), Y6
	VMOVDQU 32(SI), Y7
	VPXOR Y15, Y15, Y15
	VMOVDQU 0(CX), Y12
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y4, Y4
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y4, Y4
	VAESENC Y15, Y5, Y5
	VMOVDQU 64(CX), Y12
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y6, Y6
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y6, Y6
	VAESENC Y15, Y7, Y7
	VMOVDQU 128(CX), Y12
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y0, Y0
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y0, Y0
	VAESENC Y15, Y1, Y1
	VMOVDQU 192(CX), Y12
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENCLAST Y12, Y2, Y2
	VAESENCLAST Y12, Y3, Y3
	VAESENC Y15, Y2, Y2
	VAESENC Y15, Y3, Y3
	VMOVDQU 256(CX), Y12
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y4, Y4
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y4, Y4
	VAESENC Y15, Y5, Y5
	VMOVDQU 320(CX), Y12
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y6, Y6
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y6, Y6
	VAESENC Y15, Y7, Y7
	VMOVDQU 384(CX), Y12
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y0, Y0
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y0, Y0
	VAESENC Y15, Y1, Y1
	VMOVDQU 448(CX), Y12
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENCLAST Y12, Y2, Y2
	VAESENCLAST Y12, Y3, Y3
	VAESENC Y15, Y2, Y2
	VAESENC Y15, Y3, Y3
	VMOVDQU 512(CX), Y12
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y4, Y4
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y4, Y4
	VAESENC Y15, Y5, Y5
	VMOVDQU 576(CX), Y12
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y6, Y6
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y6, Y6
	VAESENC Y15, Y7, Y7
	VMOVDQU 640(CX), Y12
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y0, Y0
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y0, Y0
	VAESENC Y15, Y1, Y1
	VMOVDQU 704(CX), Y12
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENCLAST Y15, Y6, Y6
	VAESENCLAST Y15, Y7, Y7
	VAESENCLAST Y12, Y2, Y2
	VAESENCLAST Y12, Y3, Y3
	VAESENC Y15, Y2, Y2
	VAESENC Y15, Y3, Y3
	VMOVDQU 768(CX), Y12
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENCLAST Y15, Y0, Y0
	VAESENCLAST Y15, Y1, Y1
	VAESENCLAST Y12, Y4, Y4
	VAESENCLAST Y12, Y5, Y5
	VAESENC Y15, Y4, Y4
	VAESENC Y15, Y5, Y5
	VMOVDQU 832(CX), Y12
	VAESENC Y4, Y2, Y4
	VAESENC Y5, Y3, Y5
	VAESENC Y0, Y6, Y0
	VAESENC Y1, Y7, Y1
	VAESENCLAST Y15, Y2, Y2
	VAESENCLAST Y15, Y3, Y3
	VAESENCLAST Y12, Y6, Y6
	VAESENCLAST Y12, Y7, Y7
	VAESENC Y15, Y6, Y6
	VAESENC Y15, Y7, Y7
	VMOVDQU 896(CX), Y12
	VAESENC Y6, Y4, Y6
	VAESENC Y7, Y5, Y7
	VAESENC Y2, Y0, Y2
	VAESENC Y3, Y1, Y3
	VAESENCLAST Y15, Y4, Y4
	VAESENCLAST Y15, Y5, Y5
	VAESENCLAST Y12, Y0, Y0
	VAESENCLAST Y12, Y1, Y1
	VAESENC Y15, Y0, Y0
	VAESENC Y15, Y1, Y1
	VMOVDQU Y6, 0(AX)
	VMOVDQU Y7, 32(AX)
	VMOVDQU Y0, 0(BX)
	VMOVDQU Y1, 32(BX)
	VMOVDQU Y2, 0(DX)
	VMOVDQU Y3, 32(DX)
	VMOVDQU Y4, 0(SI)
	VMOVDQU Y5, 32(SI)
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X3, X3, X3
	VPXORD X4, X4, X4
	VPXORD X5, X5, X5
	VPXORD X6, X6, X6
	VPXORD X7, X7, X7
	VPXORD X12, X12, X12
	VZEROUPPER
	RET
