//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-512
// with 68-byte per-lane data input (the ITB Config.NonceBits=512 buf
// shape). 68 > 56-byte chunkSize, so the absorb runs as 2 SoEM-512
// rounds. AES-NI-only fallback; one lane per pass (four passes), same
// intra-lane 4-chain structure as the 20-byte kernel
// (areion_chain512_20_aesni_amd64.s). Bit-exact with the VAES kernel
// Areion512ChainAbsorb68x4.
//
// Per-lane data layout consumed across two rounds (matches VAES):
//   Round 0: state[0..8]  = lengthTag (= 68); state[8..64] = data[0..56]
//   Round 1: state[8..16] ⊕= data[56..64]; state[16..20] ⊕= data[64..68]
//
// The round-1 absorb is folded directly into the stack-resident
// intermediate state via XORQ/XORL reg→mem, avoiding a register shuffle
// before the second SETUP.

#include "textflag.h"

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

#define AR512_WRITE(o0, o1, o2, o3) \
	MOVOU X3, X4; PXOR X11, X4; MOVOU X4, o0(DX); \
	MOVOU X0, X4; PXOR X8,  X4; MOVOU X4, o1(DX); \
	MOVOU X1, X4; PXOR X9,  X4; MOVOU X4, o2(DX); \
	MOVOU X2, X4; PXOR X10, X4; MOVOU X4, o3(DX)

// AR512_LANE68 runs the full 2-round absorb for one lane. dp = data
// pointer register; s* = seed block offsets in BX; o* = output block
// offsets in DX. Requires domainSep in X7 (survives both permutes).
#define AR512_LANE68(dp, s0, s1o, s2o, s3o, o0, o1, o2, o3) \
	MOVQ $68, R12;    MOVQ R12, 0(SP); \
	MOVQ 0(dp), R12;  MOVQ R12, 8(SP); \
	MOVQ 8(dp), R12;  MOVQ R12, 16(SP); \
	MOVQ 16(dp), R12; MOVQ R12, 24(SP); \
	MOVQ 24(dp), R12; MOVQ R12, 32(SP); \
	MOVQ 32(dp), R12; MOVQ R12, 40(SP); \
	MOVQ 40(dp), R12; MOVQ R12, 48(SP); \
	MOVQ 48(dp), R12; MOVQ R12, 56(SP); \
	AR512_SETUP(s0, s1o, s2o, s3o); \
	PXOR X6, X6; \
	AR512_PERM15; \
	MOVOU X3, X4; PXOR X11, X4; MOVOU X4, 0(SP); \
	MOVOU X0, X4; PXOR X8,  X4; MOVOU X4, 16(SP); \
	MOVOU X1, X4; PXOR X9,  X4; MOVOU X4, 32(SP); \
	MOVOU X2, X4; PXOR X10, X4; MOVOU X4, 48(SP); \
	MOVQ 56(dp), R13; XORQ R13, 8(SP); \
	MOVL 64(dp), R13; XORL R13, 16(SP); \
	AR512_SETUP(s0, s1o, s2o, s3o); \
	PXOR X6, X6; \
	AR512_PERM15; \
	AR512_WRITE(o0, o1, o2, o3)

// func Areion512ChainAbsorb68x4AesNi(
//     fixedKey *[64]byte, seeds *[4][8]uint64,
//     dataPtrs *[4]*byte, out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb68x4AesNi(SB), NOSPLIT, $64-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	MOVOU ·AreionSoEMDomainSep256(SB), X7

	AR512_LANE68(R8,  0,   16,  32,  48,  0,   16,  32,  48)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_LANE68(R9,  64,  80,  96,  112, 64,  80,  96,  112)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_LANE68(R10, 128, 144, 160, 176, 128, 144, 160, 176)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_LANE68(R11, 192, 208, 224, 240, 192, 208, 224, 240)

	RET
