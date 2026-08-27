//go:build amd64 && !purego && !noitbasm

// YMM VAES (no AVX-512) fused chained-absorb kernel for Areion-SoEM-256
// with 36-byte per-lane data input (the ITB Config.NonceBits=256 buf
// shape). 36 bytes > 24-byte chunkSize, so the absorb runs as 2 SoEM
// rounds; the 2-lane pass carries its running 32-byte state in (Y8,Y9)
// across both rounds. Bit-exact with the ZMM Areion256ChainAbsorb36x4,
// the XMM AES-NI Areion256ChainAbsorb36x4AesNi, and the Go single
// closure. See areion_chain256_20_vaesavx2_amd64.s for the canonical
// 2-lane-pass description.
//
// Per-lane data layout (36 bytes total) is consumed across two rounds:
//   Round 0:  state[0..8]  = lengthTag (= 36)
//             state[8..32] = data[0..24]  (chunkSize = 24 bytes)
//   Round 1:  state[8..16]  ⊕= data[24..32]   (8 bytes — high half b0)
//             state[16..20] ⊕= data[32..36]  (4 bytes — low quarter b1)
//
// Register allocation (per pass, 2 lanes):
//   Y0,Y1  state1 (a,b)          Y8,Y9  carried running state (b0,b1)
//   Y2,Y3  state2 (a,b)          Y10,Y11 fixedKey/seed/xor scratch
//   Y4,Y5  round temps           Y12    domain separation
//   Y6     zero                  Y7     round constant
//
// Stack frame: 128 bytes SoA staging for the 4-lane round-0 state
// (SP+0..128, survives both passes) + 64 bytes round-1 XOR-pattern
// staging (SP+128..192, rebuilt per pass).

#include "textflag.h"

// AR256_YROUND — see areion_chain256_20_vaesavx2_amd64.s.
#define AR256_YROUND(s1a, s1b, s2a, s2b, rcoff) \
	VBROADCASTI128 ·AreionRC4x+rcoff(SB), Y7; \
	VAESENC Y7, s1a, Y4; \
	VAESENC Y7, s2a, Y5; \
	VAESENC s1b, Y4, Y4; \
	VAESENC s2b, Y5, Y5; \
	VAESENCLAST Y6, s1a, s1a; \
	VAESENCLAST Y6, s2a, s2a; \
	VMOVDQA Y4, s1b; \
	VMOVDQA Y5, s2b

#define AR256_YPERM10 \
	AR256_YROUND(Y0, Y1, Y2, Y3, 0) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 64) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 128) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 192) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 256) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 320) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 384) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 448) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 512) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 576)

// SETUP256 — SoEM state setup from the carried running state (Y8,Y9)
// into state1 (Y0,Y1) and state2 (Y2,Y3). sb0lo/sb0hi/sb1lo/sb1hi are
// the byte offsets in BX of the two lanes' seed b0/b1 fragments.
#define SETUP256(sb0lo, sb0hi, sb1lo, sb1hi) \
	VBROADCASTI128 0(AX),  Y10; \
	VPXOR Y10, Y8, Y0; \
	VBROADCASTI128 16(AX), Y11; \
	VPXOR Y11, Y9, Y1; \
	VMOVDQU sb0lo(BX), X10; \
	VINSERTI128 $1, sb0hi(BX), Y10, Y10; \
	VPXOR Y10, Y8, Y2; \
	VPXOR Y12, Y2, Y2; \
	VMOVDQU sb1lo(BX), X11; \
	VINSERTI128 $1, sb1hi(BX), Y11, Y11; \
	VPXOR Y11, Y9, Y3

// func Areion256ChainAbsorb36x4VaesAvx2(
//     fixedKey *[32]byte,
//     seeds *[4][4]uint64,
//     dataPtrs *[4]*byte,        // each ptr to >=36 bytes
//     out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb36x4VaesAvx2(SB), NOSPLIT, $192-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXOR Y6, Y6, Y6
	VMOVDQU ·AreionSoEMDomainSep256(SB), Y12

	// ===== Round-0 SoA staging: lengthTag(36) + data[0..24] =====
	//   SP+0/16/32/48    = b0 of lane 0/1/2/3: [len(8) | data[0..8]]
	//   SP+64/80/96/112  = b1 of lane 0/1/2/3: [data[8..24]]
	MOVQ $36, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 8(R8),  R12
	MOVQ R12, 64(SP)
	MOVQ 16(R8), R12
	MOVQ R12, 72(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 80(SP)
	MOVQ 16(R9), R12
	MOVQ R12, 88(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 96(SP)
	MOVQ 16(R10), R12
	MOVQ R12, 104(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVQ 16(R11), R12
	MOVQ R12, 120(SP)

	// ============================ PASS A: lanes 0,1 ============================
	VMOVDQU 0(SP),  Y8            // carried b0 (lanes 0,1)
	VMOVDQU 64(SP), Y9           // carried b1 (lanes 0,1)

	// Round 0.
	SETUP256(0, 32, 16, 48)
	AR256_YPERM10
	VPXOR Y2, Y0, Y8             // carried b0 = round-0 SoEM output
	VPXOR Y3, Y1, Y9            // carried b1

	// Round 1: XOR data[24..36] into state[8..20], lanes 0,1.
	//   b0_xor lane [0..8]=0, [8..16]=data[24..32]  at SP+128 (lane0), SP+144 (lane1)
	//   b1_xor lane [0..4]=data[32..36], [4..16]=0   at SP+160 (lane0), SP+176 (lane1)
	XORQ R12, R12
	MOVQ R12, 128(SP)
	MOVQ 24(R8), R13
	MOVQ R13, 136(SP)
	MOVQ R12, 144(SP)
	MOVQ 24(R9), R13
	MOVQ R13, 152(SP)
	MOVL 32(R8), R13
	MOVL R13, 160(SP)
	MOVL R12, 164(SP)
	MOVQ R12, 168(SP)
	MOVL 32(R9), R13
	MOVL R13, 176(SP)
	MOVL R12, 180(SP)
	MOVQ R12, 184(SP)
	VMOVDQU 128(SP), Y10
	VPXOR Y10, Y8, Y8
	VMOVDQU 160(SP), Y11
	VPXOR Y11, Y9, Y9

	SETUP256(0, 32, 16, 48)
	AR256_YPERM10
	VPXOR Y2, Y0, Y0
	VPXOR Y3, Y1, Y1
	VEXTRACTI128 $0, Y0, 0(DX)
	VEXTRACTI128 $0, Y1, 16(DX)
	VEXTRACTI128 $1, Y0, 32(DX)
	VEXTRACTI128 $1, Y1, 48(DX)

	// ============================ PASS B: lanes 2,3 ============================
	VMOVDQU 32(SP), Y8           // carried b0 (lanes 2,3)
	VMOVDQU 96(SP), Y9          // carried b1 (lanes 2,3)

	SETUP256(64, 96, 80, 112)
	AR256_YPERM10
	VPXOR Y2, Y0, Y8
	VPXOR Y3, Y1, Y9

	XORQ R12, R12
	MOVQ R12, 128(SP)
	MOVQ 24(R10), R13
	MOVQ R13, 136(SP)
	MOVQ R12, 144(SP)
	MOVQ 24(R11), R13
	MOVQ R13, 152(SP)
	MOVL 32(R10), R13
	MOVL R13, 160(SP)
	MOVL R12, 164(SP)
	MOVQ R12, 168(SP)
	MOVL 32(R11), R13
	MOVL R13, 176(SP)
	MOVL R12, 180(SP)
	MOVQ R12, 184(SP)
	VMOVDQU 128(SP), Y10
	VPXOR Y10, Y8, Y8
	VMOVDQU 160(SP), Y11
	VPXOR Y11, Y9, Y9

	SETUP256(64, 96, 80, 112)
	AR256_YPERM10
	VPXOR Y2, Y0, Y0
	VPXOR Y3, Y1, Y1
	VEXTRACTI128 $0, Y0, 64(DX)
	VEXTRACTI128 $0, Y1, 80(DX)
	VEXTRACTI128 $1, Y0, 96(DX)
	VEXTRACTI128 $1, Y1, 112(DX)

	VZEROUPPER
	RET
