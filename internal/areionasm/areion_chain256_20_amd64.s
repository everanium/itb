//go:build amd64 && !purego

// Fused chained-absorb VAES kernel for Areion-SoEM-256 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — the
// default config and most-frequently-hit path).
//
// 20 bytes ≤ 24-byte chunkSize, so the absorb runs as a single SoEM
// round. The kernel mirrors the structure of the 36-byte variant
// (`Areion256ChainAbsorb36x4`) but skips the second round and the
// inter-round data XOR. Per-lane data layout:
//
//   state[0..8]   = lengthTag (= 20, baked in)
//   state[8..28]  = data[0..20]
//   state[28..32] = 0  (zero padding to fill the 32-byte block)

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

// func Areion256ChainAbsorb20x4(
//     fixedKey *[32]byte,
//     seeds *[4][4]uint64,
//     dataPtrs *[4]*byte,        // each ptr to ≥20 bytes
//     out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb20x4(SB), NOSPLIT, $128-32
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

	// ===== Build state from lengthTag(20) + data[0..20] + zero pad =====
	//
	// Per lane stack[lane*32]:
	//   [0..8]   = 20 (length tag)
	//   [8..16]  = data[0..8]
	//   [16..28] = data[8..20]
	//   [28..32] = 0
	MOVQ $20, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 64(SP)
	MOVQ R12, 96(SP)

	// Lane 0.
	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 8(R8),  R12
	MOVQ R12, 16(SP)
	MOVL 16(R8), R12
	MOVL R12, 24(SP)
	MOVL $0, 28(SP)
	// Lane 1.
	MOVQ 0(R9),  R12
	MOVQ R12, 40(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 48(SP)
	MOVL 16(R9), R12
	MOVL R12, 56(SP)
	MOVL $0, 60(SP)
	// Lane 2.
	MOVQ 0(R10), R12
	MOVQ R12, 72(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 80(SP)
	MOVL 16(R10), R12
	MOVL R12, 88(SP)
	MOVL $0, 92(SP)
	// Lane 3.
	MOVQ 0(R11), R12
	MOVQ R12, 104(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVL 16(R11), R12
	MOVL R12, 120(SP)
	MOVL $0, 124(SP)

	// Pack stack AoS → SoA Block4 in (Z14, Z15).
	VMOVDQU 0(SP), X14
	VINSERTI64X2 $1, 32(SP), Y14, Y14
	VINSERTI64X2 $2, 64(SP), Z14, Z14
	VINSERTI64X2 $3, 96(SP), Z14, Z14
	VMOVDQU 16(SP), X15
	VINSERTI64X2 $1, 48(SP), Y15, Y15
	VINSERTI64X2 $2, 80(SP), Z15, Z15
	VINSERTI64X2 $3, 112(SP), Z15, Z15

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
