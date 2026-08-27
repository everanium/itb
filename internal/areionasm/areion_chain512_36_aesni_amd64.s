//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-512
// with 36-byte per-lane data input (the ITB Config.NonceBits=256 buf
// shape). 36 ≤ 56-byte chunkSize, so the absorb is a single SoEM-512
// round. AES-NI-only fallback; identical to the 20-byte kernel
// (areion_chain512_20_aesni_amd64.s) except the state staging spans the
// 36 data bytes across b0/b1/b2.
//
// Per-lane 64-byte state:
//   b0: [lengthTag(36) | data[0..8]]
//   b1: [data[8..24]]
//   b2: [data[24..36] | 0]
//   b3: 0

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

// STAGE36 stages the 36-byte lane state (data ptr in reg dp) into SP.
#define STAGE36(dp) \
	MOVQ $36, R12;    MOVQ R12, 0(SP); \
	MOVQ 0(dp), R12;  MOVQ R12, 8(SP); \
	MOVQ 8(dp), R12;  MOVQ R12, 16(SP); \
	MOVQ 16(dp), R12; MOVQ R12, 24(SP); \
	MOVQ 24(dp), R12; MOVQ R12, 32(SP); \
	MOVL 32(dp), R12; MOVL R12, 40(SP); MOVL $0, 44(SP); \
	MOVQ $0, 48(SP);  MOVQ $0, 56(SP)

// func Areion512ChainAbsorb36x4AesNi(
//     fixedKey *[64]byte, seeds *[4][8]uint64,
//     dataPtrs *[4]*byte, out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb36x4AesNi(SB), NOSPLIT, $64-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	MOVOU ·AreionSoEMDomainSep256(SB), X7

	STAGE36(R8)
	AR512_SETUP(0, 16, 32, 48)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(0, 16, 32, 48)

	STAGE36(R9)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_SETUP(64, 80, 96, 112)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(64, 80, 96, 112)

	STAGE36(R10)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_SETUP(128, 144, 160, 176)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(128, 144, 160, 176)

	STAGE36(R11)
	MOVOU ·AreionSoEMDomainSep256(SB), X7
	AR512_SETUP(192, 208, 224, 240)
	PXOR X6, X6
	AR512_PERM15
	AR512_WRITE(192, 208, 224, 240)

	RET
