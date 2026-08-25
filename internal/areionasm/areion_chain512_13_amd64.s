//go:build amd64 && !purego && !noitbasm

// Fused chained-absorb VAES kernel for Areion-SoEM-512 with 13-byte
// per-lane data input — the Interlocked Barrier PRF fill message shape
// (0x03 || uint64-LE(groupIdx) || 4 reserved). 13 bytes ≤ 56-byte
// chunkSize, so the absorb is a single SoEM-512 round; the kernel runs
// the 15-round Areion512 permutation interleaved on state1 and state2
// (same ILP pattern as the 20-byte fused kernel) and writes the final
// 64-byte digest per lane.
//
// This is a mechanical copy of the 20-byte kernel
// (areion_chain512_20_amd64.s) with two adjustments:
//   - lengthTag 20 -> 13
//   - the b1 staging loads exactly data[8..13] (5 bytes) via MOVL +
//     MOVBLZX rather than the 20-byte kernel's MOVQ 8(Rx) + MOVL 16(Rx).
//     The 4 lane data pointers reference exactly-13-byte scratch buffers
//     packed adjacently ([4][13]byte); a full MOVQ 8(Rx) would read
//     bytes 8..16, three bytes past the 13-byte buffer into the next
//     lane's staging, so the load width is capped at the live 13 bytes.
//
// Per-lane data layout (13 bytes total, padded to 64-byte block):
//
//   state[0..8]   = lengthTag (= 13)
//   state[8..21]  = data[0..13]
//   state[21..64] = 0 (zero pad)
//
// In SoA Block4 layout (4 × 16-byte AES blocks per lane state):
//
//   b0 (Z14): per-lane [lengthTag(8) + data[0..8](8)]   — non-zero
//   b1 (Z15): per-lane [data[8..13](5) + zero(11)]        — non-zero
//   b2 (Z16): all zeros
//   b3 (Z17): all zeros

#include "textflag.h"

// AREION512_FUSED_ROUND — identical to the 20-byte kernel's round body.
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

// func Areion512ChainAbsorb13x4(
//     fixedKey *[64]byte,        // shared 64-byte fixed key (k1)
//     seeds *[4][8]uint64,       // per-lane seed components (k2 = 64 bytes per lane)
//     dataPtrs *[4]*byte,        // each ptr to ≥13 bytes
//     out *[4][8]uint64)         // output (4 lanes × 8 uint64 = 64 bytes per lane)
TEXT ·Areion512ChainAbsorb13x4(SB), NOSPLIT, $128-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// Z6 = zero (FinalRoundNoKey "round key" + RoundNoKey "round key").
	VPXORD Z6, Z6, Z6

	// Z18..Z21: fixedKey b0/b1/b2/b3 broadcast.
	VBROADCASTI32X4 0(AX),  Z18
	VBROADCASTI32X4 16(AX), Z19
	VBROADCASTI32X4 32(AX), Z20
	VBROADCASTI32X4 48(AX), Z21

	// Z22..Z25: seedKey b0/b1/b2/b3 SoA.
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

	// Z26: SoEM domain-separation constant.
	VMOVDQU64 ·AreionSoEMDomainSep256(SB), Z26

	// ===== Build state from lengthTag(13) + data[0..13] + zero pad =====
	//
	// Stack scratch:
	//   SP+0..64    = staging for Z14 (b0): per lane stride 16
	//                  lane i [0..8]  = lengthTag (13)
	//                  lane i [8..16] = data[i][0..8]
	//   SP+64..128  = staging for Z15 (b1): per lane stride 16
	//                  lane i [0..4]  = data[i][8..12]
	//                  lane i [4..5]  = data[i][12]
	//                  lane i [5..16] = 0
	//
	// Z16 (b2), Z17 (b3) are zero — built via VPXORD with self.
	MOVQ $13, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	// b0 high half = data[0..8] (MOVQ, 8 bytes; valid, 13 ≥ 8).
	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)

	// b1 staging: per lane data[8..13] (5 bytes) + 11-byte zero pad.
	// Zero the full 16-byte lane slot first, then write the 5 live bytes
	// via a 4-byte MOVL (data[8..12]) + 1-byte MOVBLZX (data[12]) — never
	// a MOVQ at offset 8, which would read past the 13-byte buffer.
	// Lane 0.
	MOVQ $0, 64(SP)
	MOVQ $0, 72(SP)
	MOVL 8(R8),  R12
	MOVL R12, 64(SP)
	MOVBLZX 12(R8), R12
	MOVB R12, 68(SP)
	// Lane 1.
	MOVQ $0, 80(SP)
	MOVQ $0, 88(SP)
	MOVL 8(R9),  R12
	MOVL R12, 80(SP)
	MOVBLZX 12(R9), R12
	MOVB R12, 84(SP)
	// Lane 2.
	MOVQ $0, 96(SP)
	MOVQ $0, 104(SP)
	MOVL 8(R10), R12
	MOVL R12, 96(SP)
	MOVBLZX 12(R10), R12
	MOVB R12, 100(SP)
	// Lane 3.
	MOVQ $0, 112(SP)
	MOVQ $0, 120(SP)
	MOVL 8(R11), R12
	MOVL R12, 112(SP)
	MOVBLZX 12(R11), R12
	MOVB R12, 116(SP)

	// Pack staging → SoA Block4 (Z14, Z15).
	VMOVDQU64 0(SP),  Z14
	VMOVDQU64 64(SP), Z15

	// b2, b3 = zero.
	VPXORD Z16, Z16, Z16
	VPXORD Z17, Z17, Z17

	// SoEM state setup:
	//   state1 = state ⊕ fixedKey
	//   state2 = state ⊕ seedKey ⊕ domainSep
	VPXORD Z18, Z14, Z0
	VPXORD Z19, Z15, Z1
	VPXORD Z20, Z16, Z2
	VPXORD Z21, Z17, Z3
	VPXORD Z22, Z14, Z8
	VPXORD Z26, Z8,  Z8
	VPXORD Z23, Z15, Z9
	VPXORD Z24, Z16, Z10
	VPXORD Z25, Z17, Z11

	// Z14..Z28: Areion512 round constants RC[0..14] (4-broadcast form).
	VMOVDQU64 ·AreionRC4x+0(SB),   Z14
	VMOVDQU64 ·AreionRC4x+64(SB),  Z15
	VMOVDQU64 ·AreionRC4x+128(SB), Z16
	VMOVDQU64 ·AreionRC4x+192(SB), Z17
	VMOVDQU64 ·AreionRC4x+256(SB), Z18
	VMOVDQU64 ·AreionRC4x+320(SB), Z19
	VMOVDQU64 ·AreionRC4x+384(SB), Z20
	VMOVDQU64 ·AreionRC4x+448(SB), Z21
	VMOVDQU64 ·AreionRC4x+512(SB), Z22
	VMOVDQU64 ·AreionRC4x+576(SB), Z23
	VMOVDQU64 ·AreionRC4x+640(SB), Z24
	VMOVDQU64 ·AreionRC4x+704(SB), Z25
	VMOVDQU64 ·AreionRC4x+768(SB), Z26
	VMOVDQU64 ·AreionRC4x+832(SB), Z27
	VMOVDQU64 ·AreionRC4x+896(SB), Z28

	// 15-round Areion512 permutation, interleaved on (Z0..Z3) and
	// (Z8..Z11).
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z14)
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z15)
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z16)
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z17)
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z18)
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z19)
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z20)
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z21)
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z22)
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z23)
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z24)
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z25)
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z26)
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27)
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z28)

	// ===== Final cyclic rotation + SoEM XOR + writeback =====
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
