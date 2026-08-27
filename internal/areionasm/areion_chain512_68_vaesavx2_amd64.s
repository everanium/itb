//go:build amd64 && !purego && !noitbasm

// YMM VAES (no AVX-512) fused chained-absorb kernel for Areion-SoEM-512
// with 68-byte per-lane data input (the ITB Config.NonceBits=512 buf
// shape). 68 bytes > 56-byte chunkSize, so the absorb runs as 2 SoEM
// rounds. Bit-exact with the ZMM Areion512ChainAbsorb68x4, the XMM
// AES-NI Areion512ChainAbsorb68x4AesNi, and the Go single closure. See
// areion_chain512_20_vaesavx2_amd64.s for the canonical 2-lane-pass
// description and macro contracts.
//
// Per-lane data layout consumed across two rounds:
//   Round 0: b0=[len(68)|data[0..8]], b1=data[8..24], b2=data[24..40],
//            b3=data[40..56]                                (full chunk)
//   Round 1: state[8..16]  ⊕= data[56..64]   (8 bytes — b0 high half)
//            state[16..20] ⊕= data[64..68]   (4 bytes — b1 low quarter)
//
// The running 64-byte state is carried between the two rounds through a
// per-pass 128-byte stack scratch region (SP+256..384), holding the four
// SoEM output blocks for the pass's two lanes. The round-0 SoA staging
// (SP+0..256) survives both passes.
//
// Stack frame: 256 (round-0 staging) + 128 (round-1 carried state) = 384.

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

// ROTFOLD512 — final cyclic rotation + SoEM XOR into (Y3,Y0,Y1,Y2) as
// the new running state blocks (b0,b1,b2,b3): b0=Y3⊕Y11, b1=Y0⊕Y8,
// b2=Y1⊕Y9, b3=Y2⊕Y10.
#define ROTFOLD512 \
	VPXOR Y11, Y3, Y3; \
	VPXOR Y8,  Y0, Y0; \
	VPXOR Y9,  Y1, Y1; \
	VPXOR Y10, Y2, Y2

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

// func Areion512ChainAbsorb68x4VaesAvx2(
//     fixedKey *[64]byte,
//     seeds *[4][8]uint64,
//     dataPtrs *[4]*byte,        // each ptr to >=68 bytes
//     out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb68x4VaesAvx2(SB), NOSPLIT, $384-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXOR Y6, Y6, Y6

	// ===== Round-0 SoA staging: lengthTag(68) + data[0..56] =====
	//   b0: [len(8) | data[0..8]]   SP+0/16/32/48
	//   b1: [data[8..24]]           SP+64/80/96/112
	//   b2: [data[24..40]]          SP+128/144/160/176
	//   b3: [data[40..56]]          SP+192/208/224/240
	MOVQ $68, R12
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

	// b1: data[8..24].
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

	// b2: data[24..40].
	MOVQ 24(R8), R12
	MOVQ R12, 128(SP)
	MOVQ 32(R8), R12
	MOVQ R12, 136(SP)
	MOVQ 24(R9), R12
	MOVQ R12, 144(SP)
	MOVQ 32(R9), R12
	MOVQ R12, 152(SP)
	MOVQ 24(R10), R12
	MOVQ R12, 160(SP)
	MOVQ 32(R10), R12
	MOVQ R12, 168(SP)
	MOVQ 24(R11), R12
	MOVQ R12, 176(SP)
	MOVQ 32(R11), R12
	MOVQ R12, 184(SP)

	// b3: data[40..56].
	MOVQ 40(R8), R12
	MOVQ R12, 192(SP)
	MOVQ 48(R8), R12
	MOVQ R12, 200(SP)
	MOVQ 40(R9), R12
	MOVQ R12, 208(SP)
	MOVQ 48(R9), R12
	MOVQ R12, 216(SP)
	MOVQ 40(R10), R12
	MOVQ R12, 224(SP)
	MOVQ 48(R10), R12
	MOVQ R12, 232(SP)
	MOVQ 40(R11), R12
	MOVQ R12, 240(SP)
	MOVQ 48(R11), R12
	MOVQ R12, 248(SP)

	// ============================ PASS A: lanes 0,1 ============================
	// Round 0.
	SETUP512(0, 64, 128, 192, 0, 64, 16, 80, 32, 96, 48, 112)
	AR512_YPERM15
	ROTFOLD512                     // new state: Y3=b0, Y0=b1, Y1=b2, Y2=b3

	// Round-1 data XOR pattern (lanes 0,1) staged at SP+256 (xb0),
	// SP+288 (xb1):
	//   xb0 lane [0..8]=0, [8..16]=data[56..64]
	//   xb1 lane [0..4]=data[64..68], [4..16]=0
	XORQ R12, R12
	MOVQ R12, 256(SP)
	MOVQ 56(R8), R13
	MOVQ R13, 264(SP)
	MOVQ R12, 272(SP)
	MOVQ 56(R9), R13
	MOVQ R13, 280(SP)
	MOVL 64(R8), R13
	MOVL R13, 288(SP)
	MOVL R12, 292(SP)
	MOVQ R12, 296(SP)
	MOVL 64(R9), R13
	MOVL R13, 304(SP)
	MOVL R12, 308(SP)
	MOVQ R12, 312(SP)
	VMOVDQU 256(SP), Y14
	VPXOR Y14, Y3, Y3              // new b0 ⊕= xb0
	VMOVDQU 288(SP), Y14
	VPXOR Y14, Y0, Y0             // new b1 ⊕= xb1

	// Store the running state to the carried region for the round-1
	// SETUP512 (order matters: loads above already consumed SP+256/288).
	VMOVDQU Y3, 256(SP)
	VMOVDQU Y0, 288(SP)
	VMOVDQU Y1, 320(SP)
	VMOVDQU Y2, 352(SP)

	// Round 1.
	SETUP512(256, 288, 320, 352, 0, 64, 16, 80, 32, 96, 48, 112)
	AR512_YPERM15
	WRITE512(0, 16, 32, 48, 64, 80, 96, 112)

	// ============================ PASS B: lanes 2,3 ============================
	SETUP512(32, 96, 160, 224, 128, 192, 144, 208, 160, 224, 176, 240)
	AR512_YPERM15
	ROTFOLD512

	XORQ R12, R12
	MOVQ R12, 256(SP)
	MOVQ 56(R10), R13
	MOVQ R13, 264(SP)
	MOVQ R12, 272(SP)
	MOVQ 56(R11), R13
	MOVQ R13, 280(SP)
	MOVL 64(R10), R13
	MOVL R13, 288(SP)
	MOVL R12, 292(SP)
	MOVQ R12, 296(SP)
	MOVL 64(R11), R13
	MOVL R13, 304(SP)
	MOVL R12, 308(SP)
	MOVQ R12, 312(SP)
	VMOVDQU 256(SP), Y14
	VPXOR Y14, Y3, Y3
	VMOVDQU 288(SP), Y14
	VPXOR Y14, Y0, Y0

	VMOVDQU Y3, 256(SP)
	VMOVDQU Y0, 288(SP)
	VMOVDQU Y1, 320(SP)
	VMOVDQU Y2, 352(SP)

	SETUP512(256, 288, 320, 352, 128, 192, 144, 208, 160, 224, 176, 240)
	AR512_YPERM15
	WRITE512(128, 144, 160, 176, 192, 208, 224, 240)

	VZEROUPPER
	RET
