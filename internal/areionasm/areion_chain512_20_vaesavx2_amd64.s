//go:build amd64 && !purego && !noitbasm

// YMM VAES (no AVX-512) fused chained-absorb kernel for Areion-SoEM-512
// with 20-byte per-lane data input (the ITB Config.NonceBits=128 buf
// shape — the default config). Batched path for hosts that expose VAES
// on YMM but lack AVX-512 (Alder Lake+ E-cores, P-cores with BIOS-
// disabled AVX-512, some enterprise SKUs). Bit-exact with the ZMM
// Areion512ChainAbsorb20x4, the XMM AES-NI Areion512ChainAbsorb20x4AesNi,
// and the Go single closure.
//
// 20 bytes <= 56-byte chunkSize, so the absorb is a single SoEM-512
// round; the kernel runs the 15-round Areion512 permutation interleaved
// on state1 and state2 and writes the 64-byte digest per lane, with the
// final cyclic rotation folded into the SoEM output XOR.
//
// Lane strategy (playbook §2 / §8): the 4 pixel lanes are processed in
// two passes of 2 lanes each; each YMM holds two lanes' 16-byte AES
// block. Areion-SoEM-512 exposes four independent VAES chains within a
// pass — the SoEM state1 / state2 permutations, each with the Areion512
// round's a-block and c-block sub-chains — enough to saturate a single
// VAES issue port. Direct ZMM 4-lane -> YMM 2-lane narrowing.
//
// Per-lane 64-byte state (matches the ZMM kernel / Go closure):
//   b0: [lengthTag(20) | data[0..8]]
//   b1: [data[8..16] | data[16..20] | 0]
//   b2, b3: 0
//
// Register allocation (per pass, 2 lanes):
//   Y0,Y1,Y2,Y3    state1 (a,b,c,d)     Y4,Y5    state1 a/c temps
//   Y8,Y9,Y10,Y11  state2 (a,b,c,d)     Y12,Y13  state2 a/c temps
//   Y6             zero                 Y7       round constant
//   Y14,Y15        setup scratch (fixedKey / seed / raw block)
//
// Stack frame: 256 bytes SoA staging (b0..b3 of all 4 lanes, stride 16),
// built once at entry, loaded 2 lanes/pass.

#include "textflag.h"

// AR512_YROUND — one Areion512 round on the 2-lane pass's state1
// (a,b,c,d) and state2 (a,b,c,d). Maps the software round (identical to
// the ZMM kernel's AREION512_FUSED_ROUND, narrowed to YMM):
//   b ^= RoundNoKey(a);  d ^= RoundNoKey(c);
//   a = FinalRoundNoKey(a);  c = RoundNoKey(FinalRoundNoKey(c) ⊕ rc)
// VAESENC Y6(zero),x = RoundNoKey(x); VAESENCLAST Y6,x = FinalRoundNoKey(x);
// VAESENCLAST rc,x = FinalRoundNoKey(x) ⊕ rc. rcoff reads the low 16
// bytes of ·AreionRC4x, broadcast to both YMM halves.
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

// AR512_YPERM15 — the 15-round Areion512 permutation on state1 (Y0..Y3)
// and state2 (Y8..Y11), (a,b,c,d) role rotation per round.
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

// SETUP512 — SoEM-512 state setup: builds state1 (Y0..Y3) and state2
// (Y8..Y11) from the four running-state blocks staged at rb0..rb3(SP)
// and the fixedKey (AX) / per-lane seed blocks (BX offsets). domainSep
// is XOR'd into state2's b0 word. Y14/Y15 scratch.
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

// WRITE512 — SoEM-512 output (state1' ⊕ state2', final cyclic rotation
// folded, matching the ZMM kernel): out b0 = Y3⊕Y11, b1 = Y0⊕Y8,
// b2 = Y1⊕Y9, b3 = Y2⊕Y10. lN is the low lane's output block-N offset in
// DX; hN is the high lane's (lN + 64).
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

// func Areion512ChainAbsorb20x4VaesAvx2(
//     fixedKey *[64]byte,
//     seeds *[4][8]uint64,
//     dataPtrs *[4]*byte,        // each ptr to >=20 bytes
//     out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb20x4VaesAvx2(SB), NOSPLIT, $256-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXOR Y6, Y6, Y6

	// ===== SoA staging: lengthTag(20) + data[0..20] + zero pad =====
	//   SP+0..64    b0: [len(8) | data[0..8]]
	//   SP+64..128  b1: [data[8..16] | data[16..20] | 0]
	//   SP+128..192 b2: 0
	//   SP+192..256 b3: 0
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

	// b2, b3 = 0.
	VPXOR Y0, Y0, Y0
	VMOVDQU Y0, 128(SP)
	VMOVDQU Y0, 160(SP)
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
