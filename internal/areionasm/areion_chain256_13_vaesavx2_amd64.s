//go:build amd64 && !purego && !noitbasm

// YMM VAES (no AVX-512) fused chained-absorb kernel for Areion-SoEM-256
// with 13-byte per-lane data input — the Interlocked Barrier PRF fill
// message shape (0x03 || uint64-LE(groupIdx) || 4 reserved). 13 bytes <=
// 24-byte chunkSize, so the absorb is a single SoEM round. Bit-exact
// with the ZMM Areion256ChainAbsorb13x4, the XMM AES-NI
// Areion256ChainAbsorb13x4AesNi, and the Go single closure. See
// areion_chain256_20_vaesavx2_amd64.s for the canonical description of
// the 2-lane-pass lane strategy and register allocation.
//
// Identical to the 20-byte kernel except lengthTag = 13 and the b1
// staging loads exactly data[8..13] (5 bytes) via MOVL + MOVBLZX rather
// than MOVQ 8(Rx) + MOVL 16(Rx). The lane data pointers reference
// exactly-13-byte scratch buffers packed adjacently ([4][13]byte); a
// full MOVQ at offset 8 would read three bytes past the live buffer, so
// the load width is capped at the 13 live bytes.
//
//   state[0..8]   = lengthTag (= 13)
//   state[8..21]  = data[0..13]
//   state[21..32] = 0

#include "textflag.h"

// AR256_YROUND — see areion_chain256_20_vaesavx2_amd64.s for the
// canonical description.
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

// func Areion256ChainAbsorb13x4VaesAvx2(
//     fixedKey *[32]byte,
//     seeds *[4][4]uint64,
//     dataPtrs *[4]*byte,        // each ptr to >=13 bytes
//     out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb13x4VaesAvx2(SB), NOSPLIT, $128-32
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

	// ===== SoA staging: lengthTag(13) + data[0..13] + zero pad =====
	//   SP+0/16/32/48    = b0 of lane 0/1/2/3: [len(8) | data[0..8]]
	//   SP+64/80/96/112  = b1 of lane 0/1/2/3: [data[8..12] | data[12] | 0]
	MOVQ $13, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ $0, 64(SP)
	MOVQ $0, 72(SP)
	MOVL 8(R8),  R12
	MOVL R12, 64(SP)
	MOVBLZX 12(R8), R12
	MOVB R12, 68(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ $0, 80(SP)
	MOVQ $0, 88(SP)
	MOVL 8(R9),  R12
	MOVL R12, 80(SP)
	MOVBLZX 12(R9), R12
	MOVB R12, 84(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ $0, 96(SP)
	MOVQ $0, 104(SP)
	MOVL 8(R10), R12
	MOVL R12, 96(SP)
	MOVBLZX 12(R10), R12
	MOVB R12, 100(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ $0, 112(SP)
	MOVQ $0, 120(SP)
	MOVL 8(R11), R12
	MOVL R12, 112(SP)
	MOVBLZX 12(R11), R12
	MOVB R12, 116(SP)

	// ============================ PASS A: lanes 0,1 ============================
	VMOVDQU 0(SP),  Y8
	VMOVDQU 64(SP), Y9
	VBROADCASTI128 0(AX),  Y10
	VPXOR Y10, Y8, Y0
	VBROADCASTI128 16(AX), Y11
	VPXOR Y11, Y9, Y1
	VMOVDQU 0(BX), X10
	VINSERTI128 $1, 32(BX), Y10, Y10
	VPXOR Y10, Y8, Y2
	VPXOR Y12, Y2, Y2
	VMOVDQU 16(BX), X11
	VINSERTI128 $1, 48(BX), Y11, Y11
	VPXOR Y11, Y9, Y3

	AR256_YPERM10

	VPXOR Y2, Y0, Y0
	VPXOR Y3, Y1, Y1
	VEXTRACTI128 $0, Y0, 0(DX)
	VEXTRACTI128 $0, Y1, 16(DX)
	VEXTRACTI128 $1, Y0, 32(DX)
	VEXTRACTI128 $1, Y1, 48(DX)

	// ============================ PASS B: lanes 2,3 ============================
	VMOVDQU 32(SP), Y8
	VMOVDQU 96(SP), Y9
	VBROADCASTI128 0(AX),  Y10
	VPXOR Y10, Y8, Y0
	VBROADCASTI128 16(AX), Y11
	VPXOR Y11, Y9, Y1
	VMOVDQU 64(BX), X10
	VINSERTI128 $1, 96(BX), Y10, Y10
	VPXOR Y10, Y8, Y2
	VPXOR Y12, Y2, Y2
	VMOVDQU 80(BX), X11
	VINSERTI128 $1, 112(BX), Y11, Y11
	VPXOR Y11, Y9, Y3

	AR256_YPERM10

	VPXOR Y2, Y0, Y0
	VPXOR Y3, Y1, Y1
	VEXTRACTI128 $0, Y0, 64(DX)
	VEXTRACTI128 $0, Y1, 80(DX)
	VEXTRACTI128 $1, Y0, 96(DX)
	VEXTRACTI128 $1, Y1, 112(DX)

	VZEROUPPER
	RET
