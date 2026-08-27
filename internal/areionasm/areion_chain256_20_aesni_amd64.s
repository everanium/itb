//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-256
// with 20-byte per-lane data input (the ITB Config.NonceBits=128 buf
// shape — the default config). AES-NI-only fallback for hosts that
// expose AESENC on XMM but lack the VAES ZMM / YMM paths (Cascade Lake
// Xeon Gold, AMD Zen 3, every AVX2-no-VAES cloud VM). Bit-exact with
// the VAES kernel Areion256ChainAbsorb20x4 and the Go single closure.
//
// 20 bytes ≤ 24-byte chunkSize, so the absorb is one SoEM round.
//
// Lane strategy (playbook §2 natural active-width / §8 ILP restore):
// the 4 pixel lanes are processed in two passes of 2 lanes each. Within
// a pass, both lanes' SoEM state1 and state2 permutations run
// interleaved = 4 independent 128-bit AES dependency chains, enough to
// hide the ~4-cycle AESENC latency on a single AES issue port. A ZMM
// 4-lane layout is unavailable without VAES; two lanes × two SoEM
// halves is the natural 4-chain grouping for XMM AESENC.
//
// Per-lane data layout (matches the VAES kernel / Go closure):
//   state[0..8]   = lengthTag (= 20)
//   state[8..28]  = data[0..20]
//   state[28..32] = 0
//
// Register allocation (per pass):
//   X0,X1  state1 (a,b)     X8..X11  round temps (t = RoundNoKey(a))
//   X2,X3  state2 (a,b)     X12      zero (FinalRoundNoKey / VAESENCLAST)
//   X4,X5  state1 (a,b) 2nd lane     X13  round constant (reloaded/round)
//   X6,X7  state2 (a,b) 2nd lane     X14,X15  fixedKey b0,b1 (setup only)
//
// Stack frame: 128 bytes SoA staging (b0 of all 4 lanes at SP+0/16/32/48,
// b1 at SP+64/80/96/112) built once at entry, then loaded per pass.

#include "textflag.h"

// AR256_ROUND — one Areion256 round across four independent AES chains
// (two lanes × state1 / state2). (pa,pb) / (qa,qb) / (ra,rb) / (sa,sb)
// are the (a,b) block pair of each chain; rcoff is the byte offset of
// the round constant in ·AreionRC4x. Maps the software round:
//   t = RoundNoKey(a) ⊕ rc; t = RoundNoKey(t) ⊕ b;
//   a = FinalRoundNoKey(a); b = t
// via AESENC rc,t (= RoundNoKey(a)⊕rc), AESENC b,t (= RoundNoKey(t)⊕b),
// AESENCLAST zero,a (= FinalRoundNoKey(a)). Caller swaps (a,b) argument
// order across odd/even rounds to encode the Areion (x0,x1) rotation.
#define AR256_ROUND(pa, pb, qa, qb, ra, rb, sa, sb, rcoff) \
	MOVOU ·AreionRC4x+rcoff(SB), X13; \
	MOVOU pa, X8;   MOVOU qa, X9;   MOVOU ra, X10;  MOVOU sa, X11; \
	AESENC X13, X8; AESENC X13, X9; AESENC X13, X10; AESENC X13, X11; \
	AESENC pb, X8;  AESENC qb, X9;  AESENC rb, X10;  AESENC sb, X11; \
	AESENCLAST X12, pa; AESENCLAST X12, qa; AESENCLAST X12, ra; AESENCLAST X12, sa; \
	MOVOU X8, pb;   MOVOU X9, qb;   MOVOU X10, rb;  MOVOU X11, sb

// func Areion256ChainAbsorb20x4AesNi(
//     fixedKey *[32]byte,
//     seeds *[4][4]uint64,
//     dataPtrs *[4]*byte,        // each ptr to ≥20 bytes
//     out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb20x4AesNi(SB), NOSPLIT, $128-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== SoA staging: lengthTag(20) + data[0..20] + zero pad =====
	//   SP+0/16/32/48    = b0 of lane 0/1/2/3: [len(8) | data[0..8]]
	//   SP+64/80/96/112  = b1 of lane 0/1/2/3: [data[8..16] | data[16..20] | 0]
	MOVQ $20, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 8(R8),  R12
	MOVQ R12, 64(SP)
	MOVL 16(R8), R12
	MOVL R12, 72(SP)
	MOVL $0, 76(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 80(SP)
	MOVL 16(R9), R12
	MOVL R12, 88(SP)
	MOVL $0, 92(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 96(SP)
	MOVL 16(R10), R12
	MOVL R12, 104(SP)
	MOVL $0, 108(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVL 16(R11), R12
	MOVL R12, 120(SP)
	MOVL $0, 124(SP)

	// ============================ PASS A: lanes 0,1 ============================
	// fixedKey b0,b1 into X14,X15; domainSep into X13 (setup only).
	MOVOU 0(AX),  X14
	MOVOU 16(AX), X15
	MOVOU ·AreionSoEMDomainSep256(SB), X13

	// Lane 0 SoEM setup → state1 (X0,X1), state2 (X2,X3).
	MOVOU 0(SP),  X8              // sb0
	MOVOU 64(SP), X9             // sb1
	MOVOU X8, X0
	PXOR X14, X0                 // s1.a = sb0 ⊕ fk0
	MOVOU X9, X1
	PXOR X15, X1                 // s1.b = sb1 ⊕ fk1
	MOVOU 0(BX),  X10            // seed0
	MOVOU 16(BX), X11           // seed1
	MOVOU X8, X2
	PXOR X10, X2
	PXOR X13, X2                 // s2.a = sb0 ⊕ seed0 ⊕ dom
	MOVOU X9, X3
	PXOR X11, X3                 // s2.b = sb1 ⊕ seed1

	// Lane 1 SoEM setup → state1 (X4,X5), state2 (X6,X7).
	MOVOU 16(SP), X8
	MOVOU 80(SP), X9
	MOVOU X8, X4
	PXOR X14, X4
	MOVOU X9, X5
	PXOR X15, X5
	MOVOU 32(BX), X10
	MOVOU 48(BX), X11
	MOVOU X8, X6
	PXOR X10, X6
	PXOR X13, X6
	MOVOU X9, X7
	PXOR X11, X7

	// zero for FinalRoundNoKey.
	PXOR X12, X12

	// 10-round Areion256 permutation (even/odd swap of a,b per round).
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 0)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 64)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 128)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 192)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 256)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 320)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 384)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 448)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 512)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 576)

	// SoEM output = state1' ⊕ state2'; write lanes 0,1.
	MOVOU X0, X8
	PXOR X2, X8
	MOVOU X8, 0(DX)
	MOVOU X1, X9
	PXOR X3, X9
	MOVOU X9, 16(DX)
	MOVOU X4, X8
	PXOR X6, X8
	MOVOU X8, 32(DX)
	MOVOU X5, X9
	PXOR X7, X9
	MOVOU X9, 48(DX)

	// ============================ PASS B: lanes 2,3 ============================
	MOVOU 0(AX),  X14
	MOVOU 16(AX), X15
	MOVOU ·AreionSoEMDomainSep256(SB), X13

	// Lane 2 SoEM setup → state1 (X0,X1), state2 (X2,X3).
	MOVOU 32(SP), X8
	MOVOU 96(SP), X9
	MOVOU X8, X0
	PXOR X14, X0
	MOVOU X9, X1
	PXOR X15, X1
	MOVOU 64(BX), X10
	MOVOU 80(BX), X11
	MOVOU X8, X2
	PXOR X10, X2
	PXOR X13, X2
	MOVOU X9, X3
	PXOR X11, X3

	// Lane 3 SoEM setup → state1 (X4,X5), state2 (X6,X7).
	MOVOU 48(SP),  X8
	MOVOU 112(SP), X9
	MOVOU X8, X4
	PXOR X14, X4
	MOVOU X9, X5
	PXOR X15, X5
	MOVOU 96(BX),  X10
	MOVOU 112(BX), X11
	MOVOU X8, X6
	PXOR X10, X6
	PXOR X13, X6
	MOVOU X9, X7
	PXOR X11, X7

	PXOR X12, X12

	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 0)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 64)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 128)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 192)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 256)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 320)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 384)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 448)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 512)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 576)

	MOVOU X0, X8
	PXOR X2, X8
	MOVOU X8, 64(DX)
	MOVOU X1, X9
	PXOR X3, X9
	MOVOU X9, 80(DX)
	MOVOU X4, X8
	PXOR X6, X8
	MOVOU X8, 96(DX)
	MOVOU X5, X9
	PXOR X7, X9
	MOVOU X9, 112(DX)

	RET
