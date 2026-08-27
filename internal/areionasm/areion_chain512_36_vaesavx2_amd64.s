//go:build amd64 && !purego && !noitbasm

// YMM VAES (no AVX-512) fused chained-absorb kernel for Areion-SoEM-512
// with 36-byte per-lane data input (the ITB Config.NonceBits=256 buf
// shape). 36 bytes <= 56-byte chunkSize, so still a single SoEM-512
// round — only the initial-state data layout differs from the 20-byte
// case (more bytes in b1, partial fill in b2). Bit-exact with the ZMM
// Areion512ChainAbsorb36x4, the XMM AES-NI Areion512ChainAbsorb36x4AesNi,
// and the Go single closure. See areion_chain512_20_vaesavx2_amd64.s for
// the canonical 2-lane-pass description and macro contracts.
//
// Per-lane 64-byte state:
//   b0: [lengthTag(36) | data[0..8]]
//   b1: [data[8..24]]
//   b2: [data[24..36](12) | 0(4)]
//   b3: 0

#include "textflag.h"

#define AR512_YROUND(s1a, s1b, s1c, s1d, s2a, s2b, s2c, s2d, rcoff) \
	VBROADCASTI128 ·AreionRC4x+rcoff(SB), Y7; \
	VAESENC Y6, s1a, Y4; \
	VAESENC Y6, s2a, Y12; \
	VPXOR Y4, s1b, s1b; \
	VPXOR Y12, s2b, s2b; \
	VAESENC Y6, s1c, Y5; \
	VAESENC Y6, s2c, Y13; \
	VPXOR Y5, s1d, s1d; \
	VPXOR Y13, s2d, s2d; \
	VAESENCLAST Y6, s1a, s1a; \
	VAESENCLAST Y6, s2a, s2a; \
	VAESENCLAST Y7, s1c, s1c; \
	VAESENCLAST Y7, s2c, s2c; \
	VAESENC Y6, s1c, s1c; \
	VAESENC Y6, s2c, s2c

#define AR512_YPERM15 \
	AR512_YROUND(Y0, Y1, Y2, Y3, Y8,  Y9,  Y10, Y11, 0) \
	AR512_YROUND(Y1, Y2, Y3, Y0, Y9,  Y10, Y11, Y8,  64) \
	AR512_YROUND(Y2, Y3, Y0, Y1, Y10, Y11, Y8,  Y9,  128) \
	AR512_YROUND(Y3, Y0, Y1, Y2, Y11, Y8,  Y9,  Y10, 192) \
	AR512_YROUND(Y0, Y1, Y2, Y3, Y8,  Y9,  Y10, Y11, 256) \
	AR512_YROUND(Y1, Y2, Y3, Y0, Y9,  Y10, Y11, Y8,  320) \
	AR512_YROUND(Y2, Y3, Y0, Y1, Y10, Y11, Y8,  Y9,  384) \
	AR512_YROUND(Y3, Y0, Y1, Y2, Y11, Y8,  Y9,  Y10, 448) \
	AR512_YROUND(Y0, Y1, Y2, Y3, Y8,  Y9,  Y10, Y11, 512) \
	AR512_YROUND(Y1, Y2, Y3, Y0, Y9,  Y10, Y11, Y8,  576) \
	AR512_YROUND(Y2, Y3, Y0, Y1, Y10, Y11, Y8,  Y9,  640) \
	AR512_YROUND(Y3, Y0, Y1, Y2, Y11, Y8,  Y9,  Y10, 704) \
	AR512_YROUND(Y0, Y1, Y2, Y3, Y8,  Y9,  Y10, Y11, 768) \
	AR512_YROUND(Y1, Y2, Y3, Y0, Y9,  Y10, Y11, Y8,  832) \
	AR512_YROUND(Y2, Y3, Y0, Y1, Y10, Y11, Y8,  Y9,  896)

#define SETUP512(rb0, rb1, rb2, rb3, sb0lo, sb0hi, sb1lo, sb1hi, sb2lo, sb2hi, sb3lo, sb3hi) \
	VMOVDQU rb0(SP), Y14; \
	VBROADCASTI128 0(AX), Y15; \
	VPXOR Y15, Y14, Y0; \
	VMOVDQU sb0lo(BX), X15; \
	VINSERTI128 $1, sb0hi(BX), Y15, Y15; \
	VPXOR Y15, Y14, Y8; \
	VMOVDQU ·AreionSoEMDomainSep256(SB), Y15; \
	VPXOR Y15, Y8, Y8; \
	VMOVDQU rb1(SP), Y14; \
	VBROADCASTI128 16(AX), Y15; \
	VPXOR Y15, Y14, Y1; \
	VMOVDQU sb1lo(BX), X15; \
	VINSERTI128 $1, sb1hi(BX), Y15, Y15; \
	VPXOR Y15, Y14, Y9; \
	VMOVDQU rb2(SP), Y14; \
	VBROADCASTI128 32(AX), Y15; \
	VPXOR Y15, Y14, Y2; \
	VMOVDQU sb2lo(BX), X15; \
	VINSERTI128 $1, sb2hi(BX), Y15, Y15; \
	VPXOR Y15, Y14, Y10; \
	VMOVDQU rb3(SP), Y14; \
	VBROADCASTI128 48(AX), Y15; \
	VPXOR Y15, Y14, Y3; \
	VMOVDQU sb3lo(BX), X15; \
	VINSERTI128 $1, sb3hi(BX), Y15, Y15; \
	VPXOR Y15, Y14, Y11

#define WRITE512(l0, l1, l2, l3, h0, h1, h2, h3) \
	VPXOR Y11, Y3, Y3; \
	VPXOR Y8,  Y0, Y0; \
	VPXOR Y9,  Y1, Y1; \
	VPXOR Y10, Y2, Y2; \
	VEXTRACTI128 $0, Y3, l0(DX); \
	VEXTRACTI128 $0, Y0, l1(DX); \
	VEXTRACTI128 $0, Y1, l2(DX); \
	VEXTRACTI128 $0, Y2, l3(DX); \
	VEXTRACTI128 $1, Y3, h0(DX); \
	VEXTRACTI128 $1, Y0, h1(DX); \
	VEXTRACTI128 $1, Y1, h2(DX); \
	VEXTRACTI128 $1, Y2, h3(DX)

// func Areion512ChainAbsorb36x4VaesAvx2(
//     fixedKey *[64]byte,
//     seeds *[4][8]uint64,
//     dataPtrs *[4]*byte,        // each ptr to >=36 bytes
//     out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb36x4VaesAvx2(SB), NOSPLIT, $256-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXOR Y6, Y6, Y6

	// ===== SoA staging: lengthTag(36) + data[0..36] + zero pad =====
	//   b0: [len(8) | data[0..8]]        SP+0/16/32/48
	//   b1: [data[8..24]]                SP+64/80/96/112
	//   b2: [data[24..36](12) | 0(4)]    SP+128/144/160/176
	//   b3: 0                            SP+192/208/224/240
	MOVQ $36, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)

	// b1: data[8..24] (16 bytes).
	MOVQ 8(R8),  R12
	MOVQ R12, 64(SP)
	MOVQ 16(R8), R12
	MOVQ R12, 72(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 80(SP)
	MOVQ 16(R9), R12
	MOVQ R12, 88(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 96(SP)
	MOVQ 16(R10), R12
	MOVQ R12, 104(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVQ 16(R11), R12
	MOVQ R12, 120(SP)

	// b2: data[24..36] (12 bytes) + 4-byte zero pad.
	MOVQ 24(R8), R12
	MOVQ R12, 128(SP)
	MOVL 32(R8), R12
	MOVL R12, 136(SP)
	MOVL $0, 140(SP)
	MOVQ 24(R9), R12
	MOVQ R12, 144(SP)
	MOVL 32(R9), R12
	MOVL R12, 152(SP)
	MOVL $0, 156(SP)
	MOVQ 24(R10), R12
	MOVQ R12, 160(SP)
	MOVL 32(R10), R12
	MOVL R12, 168(SP)
	MOVL $0, 172(SP)
	MOVQ 24(R11), R12
	MOVQ R12, 176(SP)
	MOVL 32(R11), R12
	MOVL R12, 184(SP)
	MOVL $0, 188(SP)

	// b3 = 0.
	VPXOR Y0, Y0, Y0
	VMOVDQU Y0, 192(SP)
	VMOVDQU Y0, 224(SP)

	// ============================ PASS A: lanes 0,1 ============================
	SETUP512(0, 64, 128, 192, 0, 64, 16, 80, 32, 96, 48, 112)
	AR512_YPERM15
	WRITE512(0, 16, 32, 48, 64, 80, 96, 112)

	// ============================ PASS B: lanes 2,3 ============================
	SETUP512(32, 96, 160, 224, 128, 192, 144, 208, 160, 224, 176, 240)
	AR512_YPERM15
	WRITE512(128, 144, 160, 176, 192, 208, 224, 240)

	VZEROUPPER
	RET
