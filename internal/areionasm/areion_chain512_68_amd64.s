//go:build amd64 && !purego

// Fused chained-absorb VAES kernel for Areion-SoEM-512 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape).
//
// 68 bytes > 56-byte chunkSize so the absorb runs as 2 SoEM rounds
// with state held in (Z14, Z15, Z16, Z17) ZMM registers across both
// rounds. Per-lane data layout:
//
//   Round 0: state[0..8]   = lengthTag (= 68)
//            state[8..64]  = data[0..56]                (full chunk)
//   Round 1: state[8..16]  ⊕= data[56..64]              (8 bytes — high half b0)
//            state[16..20] ⊕= data[64..68]              (4 bytes — low quarter b1)
//            state[20..64]  unchanged

#include "textflag.h"

// AREION512_FUSED_ROUND — see areion_chain512_20_amd64.s for the
// canonical description of this round-body macro.
#define AREION512_FUSED_ROUND(s1a, s1b, s1c, s1d, s2a, s2b, s2c, s2d, rc) \
	VMOVDQA64 s1a, Z4; \
	VMOVDQA64 s2a, Z12; \
	VAESENC Z6, Z4, Z4; \
	VAESENC Z6, Z12, Z12; \
	VPXORD Z4, s1b, s1b; \
	VPXORD Z12, s2b, s2b; \
	VMOVDQA64 s1c, Z5; \
	VMOVDQA64 s2c, Z13; \
	VAESENC Z6, Z5, Z5; \
	VAESENC Z6, Z13, Z13; \
	VPXORD Z5, s1d, s1d; \
	VPXORD Z13, s2d, s2d; \
	VAESENCLAST Z6, s1a, s1a; \
	VAESENCLAST Z6, s2a, s2a; \
	VAESENCLAST rc, s1c, s1c; \
	VAESENCLAST rc, s2c, s2c; \
	VAESENC Z6, s1c, s1c; \
	VAESENC Z6, s2c, s2c

// Per-round permute body block — emits the 15-round Areion512
// permutation interleaved on (Z0..Z3) state1 and (Z8..Z11) state2.
// Folded into a #define-style block to avoid duplicating 15 round
// statements twice in the 2-round kernel below.
#define AREION512_PERMUTE15 \
	VMOVDQU64 ·AreionRC4x+0(SB), Z27; \
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27); \
	VMOVDQU64 ·AreionRC4x+64(SB), Z27; \
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27); \
	VMOVDQU64 ·AreionRC4x+128(SB), Z27; \
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27); \
	VMOVDQU64 ·AreionRC4x+192(SB), Z27; \
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z27); \
	VMOVDQU64 ·AreionRC4x+256(SB), Z27; \
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27); \
	VMOVDQU64 ·AreionRC4x+320(SB), Z27; \
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27); \
	VMOVDQU64 ·AreionRC4x+384(SB), Z27; \
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27); \
	VMOVDQU64 ·AreionRC4x+448(SB), Z27; \
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z27); \
	VMOVDQU64 ·AreionRC4x+512(SB), Z27; \
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27); \
	VMOVDQU64 ·AreionRC4x+576(SB), Z27; \
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27); \
	VMOVDQU64 ·AreionRC4x+640(SB), Z27; \
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27); \
	VMOVDQU64 ·AreionRC4x+704(SB), Z27; \
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z27); \
	VMOVDQU64 ·AreionRC4x+768(SB), Z27; \
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27); \
	VMOVDQU64 ·AreionRC4x+832(SB), Z27; \
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27); \
	VMOVDQU64 ·AreionRC4x+896(SB), Z27; \
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27)

// func Areion512ChainAbsorb68x4(
//     fixedKey *[64]byte,
//     seeds *[4][8]uint64,
//     dataPtrs *[4]*byte,        // each ptr to ≥68 bytes
//     out *[4][8]uint64)
TEXT ·Areion512ChainAbsorb68x4(SB), NOSPLIT, $256-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXORD Z6, Z6, Z6

	VBROADCASTI32X4 0(AX),  Z18
	VBROADCASTI32X4 16(AX), Z19
	VBROADCASTI32X4 32(AX), Z20
	VBROADCASTI32X4 48(AX), Z21

	VMOVDQU64 0(BX),   X22
	VINSERTI64X2 $1, 64(BX),  Y22, Y22
	VINSERTI64X2 $2, 128(BX), Z22, Z22
	VINSERTI64X2 $3, 192(BX), Z22, Z22
	VMOVDQU64 16(BX),  X23
	VINSERTI64X2 $1, 80(BX),  Y23, Y23
	VINSERTI64X2 $2, 144(BX), Z23, Z23
	VINSERTI64X2 $3, 208(BX), Z23, Z23
	VMOVDQU64 32(BX),  X24
	VINSERTI64X2 $1, 96(BX),  Y24, Y24
	VINSERTI64X2 $2, 160(BX), Z24, Z24
	VINSERTI64X2 $3, 224(BX), Z24, Z24
	VMOVDQU64 48(BX),  X25
	VINSERTI64X2 $1, 112(BX), Y25, Y25
	VINSERTI64X2 $2, 176(BX), Z25, Z25
	VINSERTI64X2 $3, 240(BX), Z25, Z25

	VMOVDQU64 ·AreionSoEMDomainSep256(SB), Z26

	// ===== Round 0: build state from lengthTag(68) + data[0..56] =====
	//
	// Stack layout (per lane stride 16, 4 lanes per buffer):
	//   SP+0..64    = Z14 staging (b0): lengthTag(8) + data[0..8](8)
	//   SP+64..128  = Z15 staging (b1): data[8..24](16)
	//   SP+128..192 = Z16 staging (b2): data[24..40](16)
	//   SP+192..256 = Z17 staging (b3): data[40..56](16)
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

	// b1 staging: data[8..24].
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

	// b2 staging: data[24..40].
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

	// b3 staging: data[40..56].
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

	// Pack staging → SoA Block4.
	VMOVDQU 0(SP), X14
	VINSERTI64X2 $1, 16(SP), Y14, Y14
	VINSERTI64X2 $2, 32(SP), Z14, Z14
	VINSERTI64X2 $3, 48(SP), Z14, Z14
	VMOVDQU 64(SP), X15
	VINSERTI64X2 $1, 80(SP), Y15, Y15
	VINSERTI64X2 $2, 96(SP), Z15, Z15
	VINSERTI64X2 $3, 112(SP), Z15, Z15
	VMOVDQU64 128(SP), X16
	VINSERTI64X2 $1, 144(SP), Y16, Y16
	VINSERTI64X2 $2, 160(SP), Z16, Z16
	VINSERTI64X2 $3, 176(SP), Z16, Z16
	VMOVDQU64 192(SP), X17
	VINSERTI64X2 $1, 208(SP), Y17, Y17
	VINSERTI64X2 $2, 224(SP), Z17, Z17
	VINSERTI64X2 $3, 240(SP), Z17, Z17

	// SoEM state setup for round 0.
	VPXORD Z18, Z14, Z0
	VPXORD Z19, Z15, Z1
	VPXORD Z20, Z16, Z2
	VPXORD Z21, Z17, Z3
	VPXORD Z22, Z14, Z8
	VPXORD Z26, Z8,  Z8
	VPXORD Z23, Z15, Z9
	VPXORD Z24, Z16, Z10
	VPXORD Z25, Z17, Z11

	// 15-round Areion512 permutation, round 0.
	AREION512_PERMUTE15

	// Round 0 SoEM output: state1' XOR state2' (with rotation already
	// folded — see fused per-half kernel for the same pattern).
	// Update state-held buffers (Z14..Z17).
	VPXORD Z11, Z3, Z14         // new b0 = state1.x3' ⊕ state2.x3' (rotated x0)
	VPXORD Z8,  Z0, Z15         // new b1 = state1.x0' ⊕ state2.x0' (rotated x1)
	VPXORD Z9,  Z1, Z16         // new b2 = state1.x1' ⊕ state2.x1' (rotated x2)
	VPXORD Z10, Z2, Z17         // new b3 = state1.x2' ⊕ state2.x2' (rotated x3)

	// ===== Round 1: XOR data[56..68] (12 bytes) into state[8..20] =====
	//
	// Stack reused for round-1 XOR-pattern staging (per lane stride 16):
	//   SP+0..64   = Z_xor_b0 staging
	//                  lane i [0..8]   = 0
	//                  lane i [8..16]  = data[i][56..64]
	//   SP+64..128 = Z_xor_b1 staging
	//                  lane i [0..4]   = data[i][64..68]
	//                  lane i [4..16]  = 0
	XORQ R12, R12
	// b0_xor staging: zero(8) + data[56..64](8).
	MOVQ R12, 0(SP)
	MOVQ 56(R8), R13
	MOVQ R13, 8(SP)
	MOVQ R12, 16(SP)
	MOVQ 56(R9), R13
	MOVQ R13, 24(SP)
	MOVQ R12, 32(SP)
	MOVQ 56(R10), R13
	MOVQ R13, 40(SP)
	MOVQ R12, 48(SP)
	MOVQ 56(R11), R13
	MOVQ R13, 56(SP)

	// b1_xor staging: data[64..68](4) + zero(12).
	MOVL 64(R8), R13
	MOVL R13, 64(SP)
	MOVL R12, 68(SP)
	MOVQ R12, 72(SP)
	MOVL 64(R9), R13
	MOVL R13, 80(SP)
	MOVL R12, 84(SP)
	MOVQ R12, 88(SP)
	MOVL 64(R10), R13
	MOVL R13, 96(SP)
	MOVL R12, 100(SP)
	MOVQ R12, 104(SP)
	MOVL 64(R11), R13
	MOVL R13, 112(SP)
	MOVL R12, 116(SP)
	MOVQ R12, 120(SP)

	// Pack to (Z2, Z6) — scratch (no permute in flight).
	VMOVDQU 0(SP), X2
	VINSERTI64X2 $1, 16(SP), Y2, Y2
	VINSERTI64X2 $2, 32(SP), Z2, Z2
	VINSERTI64X2 $3, 48(SP), Z2, Z2
	VMOVDQU 64(SP), X4
	VINSERTI64X2 $1, 80(SP), Y4, Y4
	VINSERTI64X2 $2, 96(SP), Z4, Z4
	VINSERTI64X2 $3, 112(SP), Z4, Z4

	// XOR data into state.
	VPXORD Z2, Z14, Z14
	VPXORD Z4, Z15, Z15

	// SoEM state setup for round 1.
	VPXORD Z18, Z14, Z0
	VPXORD Z19, Z15, Z1
	VPXORD Z20, Z16, Z2
	VPXORD Z21, Z17, Z3
	VPXORD Z22, Z14, Z8
	VPXORD Z26, Z8,  Z8
	VPXORD Z23, Z15, Z9
	VPXORD Z24, Z16, Z10
	VPXORD Z25, Z17, Z11

	// 15-round permute, round 1.
	AREION512_PERMUTE15

	// Final SoEM XOR + writeback (rotation folded).
	VPXORD Z11, Z3, Z3
	VPXORD Z8,  Z0, Z0
	VPXORD Z9,  Z1, Z1
	VPXORD Z10, Z2, Z2

	VEXTRACTI64X2 $0, Z3, 0(DX)
	VEXTRACTI64X2 $0, Z0, 16(DX)
	VEXTRACTI64X2 $0, Z1, 32(DX)
	VEXTRACTI64X2 $0, Z2, 48(DX)
	VEXTRACTI64X2 $1, Z3, 64(DX)
	VEXTRACTI64X2 $1, Z0, 80(DX)
	VEXTRACTI64X2 $1, Z1, 96(DX)
	VEXTRACTI64X2 $1, Z2, 112(DX)
	VEXTRACTI64X2 $2, Z3, 128(DX)
	VEXTRACTI64X2 $2, Z0, 144(DX)
	VEXTRACTI64X2 $2, Z1, 160(DX)
	VEXTRACTI64X2 $2, Z2, 176(DX)
	VEXTRACTI64X2 $3, Z3, 192(DX)
	VEXTRACTI64X2 $3, Z0, 208(DX)
	VEXTRACTI64X2 $3, Z1, 224(DX)
	VEXTRACTI64X2 $3, Z2, 240(DX)

	VZEROUPPER
	RET
