//go:build amd64 && !purego && !noitbasm

// Fused chained-absorb VAES kernel for Areion-SoEM-256 with 13-byte
// per-lane data input — the Interlocked Barrier PRF fill message shape
// (0x03 || uint64-LE(groupIdx) || 4 reserved). 13 bytes ≤ 24-byte
// chunkSize, so the absorb is a single SoEM round.
//
// Identical to the 20-byte kernel (areion_chain256_20_amd64.s) except
// lengthTag = 13 and the b1 staging loads exactly
// data[8..13] (5 bytes) via MOVL + MOVBLZX rather than the 20-byte
// kernel's MOVQ 8(Rx) + MOVL 16(Rx). The lane data pointers reference
// exactly-13-byte scratch buffers packed adjacently ([4][13]byte); a
// full MOVQ at offset 8 would read three bytes past the live buffer
// into the next lane's staging, so the load width is capped at the 13
// live bytes.
//
//   state[0..8]   = lengthTag (= 13)
//   state[8..21]  = data[0..13]
//   state[21..32] = 0  (zero padding to fill the 32-byte block)

#include "textflag.h"

// AREION256_FUSED_ROUND — see areion_chain256_36_amd64.s for the
// canonical description of this round-body macro.
#define AREION256_FUSED_ROUND(s1a, s1b, s2a, s2b, rc) \
	VMOVDQA64 s1a, Z2; \
	VMOVDQA64 s2a, Z6; \
	VAESENC rc, Z2, Z2; \
	VAESENC rc, Z6, Z6; \
	VAESENC s1b, Z2, Z2; \
	VAESENC s2b, Z6, Z6; \
	VAESENCLAST Z3, s1a, s1a; \
	VAESENCLAST Z3, s2a, s2a; \
	VMOVDQA64 Z2, s1b; \
	VMOVDQA64 Z6, s2b

// func Areion256ChainAbsorb13x4(
//     fixedKey *[32]byte,
//     seeds *[4][4]uint64,
//     dataPtrs *[4]*byte,        // each ptr to ≥13 bytes
//     out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb13x4(SB), NOSPLIT, $128-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXORD Z3, Z3, Z3

	VBROADCASTI32X4 0(AX),  Z8
	VBROADCASTI32X4 16(AX), Z9

	VMOVDQU 0(BX),  X10
	VINSERTI64X2 $1, 32(BX), Y10, Y10
	VINSERTI64X2 $2, 64(BX), Z10, Z10
	VINSERTI64X2 $3, 96(BX), Z10, Z10
	VMOVDQU 16(BX), X11
	VINSERTI64X2 $1, 48(BX), Y11, Y11
	VINSERTI64X2 $2, 80(BX), Z11, Z11
	VINSERTI64X2 $3, 112(BX), Z11, Z11

	VMOVDQU64 ·AreionSoEMDomainSep256(SB), Z12

	VMOVDQU64 ·AreionRC4x+0(SB),   Z16
	VMOVDQU64 ·AreionRC4x+64(SB),  Z17
	VMOVDQU64 ·AreionRC4x+128(SB), Z18
	VMOVDQU64 ·AreionRC4x+192(SB), Z19
	VMOVDQU64 ·AreionRC4x+256(SB), Z20
	VMOVDQU64 ·AreionRC4x+320(SB), Z21
	VMOVDQU64 ·AreionRC4x+384(SB), Z22
	VMOVDQU64 ·AreionRC4x+448(SB), Z23
	VMOVDQU64 ·AreionRC4x+512(SB), Z24
	VMOVDQU64 ·AreionRC4x+576(SB), Z25

	// ===== Build state from lengthTag(13) + data[0..13] + zero pad =====
	//
	// SoA staging (per lane stride 16, two contiguous 64-byte packs):
	//   SP+0..64   = Z14 staging (b0): per lane
	//                  [0..8]  = 13 (length tag)
	//                  [8..16] = data[0..8]
	//   SP+64..128 = Z15 staging (b1): per lane
	//                  [0..4]  = data[8..12]
	//                  [4..5]  = data[12]
	//                  [5..16] = 0
	MOVQ $13, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	// Lane 0.
	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ $0, 64(SP)
	MOVQ $0, 72(SP)
	MOVL 8(R8),  R12
	MOVL R12, 64(SP)
	MOVBLZX 12(R8), R12
	MOVB R12, 68(SP)
	// Lane 1.
	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ $0, 80(SP)
	MOVQ $0, 88(SP)
	MOVL 8(R9),  R12
	MOVL R12, 80(SP)
	MOVBLZX 12(R9), R12
	MOVB R12, 84(SP)
	// Lane 2.
	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ $0, 96(SP)
	MOVQ $0, 104(SP)
	MOVL 8(R10), R12
	MOVL R12, 96(SP)
	MOVBLZX 12(R10), R12
	MOVB R12, 100(SP)
	// Lane 3.
	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ $0, 112(SP)
	MOVQ $0, 120(SP)
	MOVL 8(R11), R12
	MOVL R12, 112(SP)
	MOVBLZX 12(R11), R12
	MOVB R12, 116(SP)

	// Pack staging → SoA Block4 in (Z14, Z15).
	VMOVDQU64 0(SP),  Z14
	VMOVDQU64 64(SP), Z15

	// SoEM state setup.
	VPXORD Z8,  Z14, Z0
	VPXORD Z9,  Z15, Z1
	VPXORD Z10, Z14, Z4
	VPXORD Z12, Z4,  Z4
	VPXORD Z11, Z15, Z5

	// Single-round 10-iteration interleaved permute.
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z16)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z17)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z18)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z19)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z20)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z21)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z22)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z23)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z24)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z25)

	// SoEM output: state1' ⊕ state2'.
	VPXORD Z4, Z0, Z14
	VPXORD Z5, Z1, Z15

	// Output write.
	VEXTRACTI64X2 $0, Z14, 0(DX)
	VEXTRACTI64X2 $0, Z15, 16(DX)
	VEXTRACTI64X2 $1, Z14, 32(DX)
	VEXTRACTI64X2 $1, Z15, 48(DX)
	VEXTRACTI64X2 $2, Z14, 64(DX)
	VEXTRACTI64X2 $2, Z15, 80(DX)
	VEXTRACTI64X2 $3, Z14, 96(DX)
	VEXTRACTI64X2 $3, Z15, 112(DX)

	VZEROUPPER
	RET
