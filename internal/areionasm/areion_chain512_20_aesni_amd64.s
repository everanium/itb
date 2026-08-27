//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-512
// with 20-byte per-lane data input (the ITB Config.NonceBits=128 buf
// shape — default config). 20 ≤ 56-byte chunkSize, so the absorb is a
// single SoEM-512 round. AES-NI-only fallback for hosts lacking the
// VAES ZMM / YMM paths (Cascade Lake Xeon Gold, AMD Zen 3, every
// AVX2-no-VAES cloud VM). Bit-exact with the VAES kernel
// Areion512ChainAbsorb20x4 and the Go single closure.
//
// Lane strategy (playbook §2 / §8): the four pixel lanes are processed
// one lane per pass (four passes). Areion-SoEM-512 already exposes four
// independent 128-bit AES chains within a single lane — the SoEM
// state1 / state2 permutations, each with the Areion512 round's
// a-block and c-block sub-chains — which is enough to hide the AESENC
// latency on a single AES issue port. A ZMM/YMM lane-packed layout is
// unavailable without VAES; the four intra-lane chains are the natural
// grouping for XMM AESENC.
//
// Per-lane 64-byte state (matches VAES kernel / Go closure):
//   b0: [lengthTag(20) | data[0..8]]
//   b1: [data[8..16] | data[16..20] | 0]
//   b2, b3: 0
//
// Register allocation (per lane):
//   X0..X3   state1 (a,b,c,d)      X4,X5,X12,X13  round temps
//   X8..X11  state2 (a,b,c,d)      X6   zero (RoundNoKey / FinalRoundNoKey)
//   X7       domainSep (setup)     X14  round constant (reloaded/round)
//
// Stack frame: 64 bytes for per-lane state staging.

#include "textflag.h"

// AR512_ROUND — one Areion512 round on both SoEM halves of a lane
// (state1 a,b,c,d and state2 ap,bp,cp,dp). Maps the software round:
//   b ^= RoundNoKey(a);  d ^= RoundNoKey(c);
//   a = FinalRoundNoKey(a);  c = RoundNoKey(FinalRoundNoKey(c) ⊕ rc)
// AESENC X6(zero),x = RoundNoKey(x); AESENCLAST X6,x = FinalRoundNoKey(x);
// AESENCLAST rc,x = FinalRoundNoKey(x) ⊕ rc. The four RoundNoKey ops
// (a, ap, c, cp) issue as four independent chains for ILP.
#define AR512_ROUND(a, b, c, d, ap, bp, cp, dp, rcoff) \
	MOVOU ·AreionRC4x+rcoff(SB), X14; \
	MOVOU a, X4;    MOVOU ap, X12; \
	AESENC X6, X4;  AESENC X6, X12; \
	PXOR X4, b;     PXOR X12, bp; \
	MOVOU c, X5;    MOVOU cp, X13; \
	AESENC X6, X5;  AESENC X6, X13; \
	PXOR X5, d;     PXOR X13, dp; \
	AESENCLAST X6, a;   AESENCLAST X6, ap; \
	AESENCLAST X14, c;  AESENCLAST X14, cp; \
	AESENC X6, c;   AESENC X6, cp

// AR512_PERM15 — the 15-round Areion512 permutation on state1
// (X0..X3) and state2 (X8..X11), with the (a,b,c,d) role rotation per
// round matching the software reference / VAES kernel.
#define AR512_PERM15 \
	AR512_ROUND(X0,X1,X2,X3, X8,X9,X10,X11, 0) \
	AR512_ROUND(X1,X2,X3,X0, X9,X10,X11,X8, 64) \
	AR512_ROUND(X2,X3,X0,X1, X10,X11,X8,X9, 128) \
	AR512_ROUND(X3,X0,X1,X2, X11,X8,X9,X10, 192) \
	AR512_ROUND(X0,X1,X2,X3, X8,X9,X10,X11, 256) \
	AR512_ROUND(X1,X2,X3,X0, X9,X10,X11,X8, 320) \
	AR512_ROUND(X2,X3,X0,X1, X10,X11,X8,X9, 384) \
	AR512_ROUND(X3,X0,X1,X2, X11,X8,X9,X10, 448) \
	AR512_ROUND(X0,X1,X2,X3, X8,X9,X10,X11, 512) \
	AR512_ROUND(X1,X2,X3,X0, X9,X10,X11,X8, 576) \
	AR512_ROUND(X2,X3,X0,X1, X10,X11,X8,X9, 640) \
	AR512_ROUND(X3,X0,X1,X2, X11,X8,X9,X10, 704) \
	AR512_ROUND(X0,X1,X2,X3, X8,X9,X10,X11, 768) \
	AR512_ROUND(X1,X2,X3,X0, X9,X10,X11,X8, 832) \
	AR512_ROUND(X2,X3,X0,X1, X10,X11,X8,X9, 896)

// AR512_SETUP builds state1 (X0..X3) and state2 (X8..X11) from the
// 64-byte lane state staged at SP+0..64. s0..s3 are the lane's seed
// block offsets in BX. domainSep in X7. fixedKey read from AX. Uses
// X4,X5 scratch.
#define AR512_SETUP(s0, s1o, s2o, s3o) \
	MOVOU 0(SP), X4;   MOVOU 0(AX), X5; \
	MOVOU X4, X0;  PXOR X5, X0; \
	MOVOU s0(BX), X5;  MOVOU X4, X8;  PXOR X5, X8;  PXOR X7, X8; \
	MOVOU 16(SP), X4;  MOVOU 16(AX), X5; \
	MOVOU X4, X1;  PXOR X5, X1; \
	MOVOU s1o(BX), X5; MOVOU X4, X9;  PXOR X5, X9; \
	MOVOU 32(SP), X4;  MOVOU 32(AX), X5; \
	MOVOU X4, X2;  PXOR X5, X2; \
	MOVOU s2o(BX), X5; MOVOU X4, X10; PXOR X5, X10; \
	MOVOU 48(SP), X4;  MOVOU 48(AX), X5; \
	MOVOU X4, X3;  PXOR X5, X3; \
	MOVOU s3o(BX), X5; MOVOU X4, X11; PXOR X5, X11

// AR512_WRITE stores the SoEM-512 output (state1' ⊕ state2', with the
// final cyclic rotation folded in — matches the VAES kernel):
//   out b0 = X3⊕X11, b1 = X0⊕X8, b2 = X1⊕X9, b3 = X2⊕X10
// o0..o3 are the lane's output block offsets in DX.
#define AR512_WRITE(o0, o1, o2, o3) \
	MOVOU X3, X4; PXOR X11, X4; MOVOU X4, o0(DX); \
	MOVOU X0, X4; PXOR X8,  X4; MOVOU X4, o1(DX); \
	MOVOU X1, X4; PXOR X9,  X4; MOVOU X4, o2(DX); \
	MOVOU X2, X4; PXOR X10, X4; MOVOU X4, o3(DX)

// STAGE20 stages the 20-byte lane state (data ptr in reg dp) into
// SP+0..64.
#define STAGE20(dp) \
	MOVQ $20, R12;   MOVQ R12, 0(SP); \
	MOVQ 0(dp), R12; MOVQ R12, 8(SP); \
	MOVQ 8(dp), R12; MOVQ R12, 16(SP); \
	MOVL 16(dp), R12; MOVL R12, 24(SP); MOVL $0, 28(SP); \
	MOVQ $0, 32(SP); MOVQ $0, 40(SP); \
	MOVQ $0, 48(SP); MOVQ $0, 56(SP)

// func Areion512ChainAbsorb20x4AesNi(
//     fixedKey *[64]byte, seeds *[4][8]uint64,
//     dataPtrs *[4]*byte, out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb20x4AesNi(SB), NOSPLIT, $64-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	MOVOU ·AreionSoEMDomainSep256(SB), X7

	// ---- Lane 0 ----
	STAGE20(R8)
	AR512_SETUP(0, 16, 32, 48)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(0, 16, 32, 48)

	// ---- Lane 1 ----
	STAGE20(R9)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_SETUP(64, 80, 96, 112)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(64, 80, 96, 112)

	// ---- Lane 2 ----
	STAGE20(R10)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_SETUP(128, 144, 160, 176)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(128, 144, 160, 176)

	// ---- Lane 3 ----
	STAGE20(R11)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_SETUP(192, 208, 224, 240)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(192, 208, 224, 240)

	RET
