//go:build amd64 && !purego && !noitbasm

// Fused chained-absorb VAES kernel for Areion-SoEM-512 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). 20 bytes ≤ 56-byte chunkSize, so the absorb is a single
// SoEM-512 round; the kernel runs the 15-round Areion512 permutation
// interleaved on state1 and state2 (same ILP pattern as the fused
// per-half kernel) and writes the final 64-byte digest per lane.
//
// Per-lane data layout (20 bytes total, padded to 64-byte block):
//
//   state[0..8]   = lengthTag (= 20)
//   state[8..28]  = data[0..20]
//   state[28..64] = 0 (zero pad)
//
// In SoA Block4 layout (4 × 16-byte AES blocks per lane state):
//
//   b0 (Z14): per-lane [lengthTag(8) + data[0..8](8)]   — non-zero
//   b1 (Z15): per-lane [data[8..20](12) + zero(4)]       — non-zero
//   b2 (Z16): all zeros (zeroed via VPXORD self,self)
//   b3 (Z17): all zeros
//
// Register pressure budget:
//
//   Z0..Z3  state1.a/b/c/d              Z18..Z21 fixedKey b0..b3 broadcast
//   Z4,Z5   state1 temps                 Z22..Z25 seedKey b0..b3 SoA
//   Z6      zero (FinalRoundNoKey)       Z26      domain separation
//   Z8..Z11 state2.a/b/c/d              Z27      current RC (loaded per round)
//   Z12,Z13 state2 temps                 Z14..Z17 state SoA (then b2/b3 zeroed
//                                                  for 20-byte; b0/b1 carry data)

#include "textflag.h"

// AREION512_FUSED_ROUND emits the per-round body of the Areion-SoEM-512
// fused permutation, interleaving state1 and state2 work on independent
// register groups for ILP. Same shape as the per-round body in the
// fused per-half kernel `Areion512SoEMPermutex4Interleaved`.
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

// func Areion512ChainAbsorb20x4(
//     fixedKey *[64]byte,        // shared 64-byte fixed key (k1)
//     seeds *[4][8]uint64,       // per-lane seed components (k2 = 64 bytes per lane)
//     dataPtrs *[4]*byte,        // each ptr to ≥20 bytes
//     out *[4][8]uint64)         // output (4 lanes × 8 uint64 = 64 bytes per lane)
TEXT ·Areion512ChainAbsorb20x4(SB), NOSPLIT, $128-32
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

	// Z18..Z21: fixedKey b0/b1/b2/b3 broadcast — 4 copies of each
	// 16-byte fragment of the 64-byte fixedKey, filling all 4 lanes.
	VBROADCASTI32X4 0(AX),  Z18
	VBROADCASTI32X4 16(AX), Z19
	VBROADCASTI32X4 32(AX), Z20
	VBROADCASTI32X4 48(AX), Z21

	// Z22..Z25: seedKey b0/b1/b2/b3 SoA — lane i's seeds[N*16..N*16+16]
	// in lane slot i of ZMM_N, gathered from per-lane stride 64 in the
	// seeds *[4][8]uint64 buffer.
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

	// ===== Build state from lengthTag(20) + data[0..20] + zero pad =====
	//
	// Stack scratch:
	//   SP+0..64    = staging for Z14 (b0): per lane stride 16
	//                  lane i [0..8]  = lengthTag (20)
	//                  lane i [8..16] = data[i][0..8]
	//   SP+64..128  = staging for Z15 (b1): per lane stride 16
	//                  lane i [0..8]  = data[i][8..16]
	//                  lane i [8..12] = data[i][16..20]
	//                  lane i [12..16]= 0
	//
	// Z16 (b2), Z17 (b3) are zero — built via VPXORD with self.
	MOVQ $20, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	// Lane 0 b0 high half = data[0..8].
	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	// Lane 1.
	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	// Lane 2.
	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	// Lane 3.
	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)

	// b1 staging: per lane data[8..20] + 4-byte zero pad.
	// Lane 0.
	MOVQ 8(R8),  R12
	MOVQ R12, 64(SP)
	MOVL 16(R8), R12
	MOVL R12, 72(SP)
	MOVL $0, 76(SP)
	// Lane 1.
	MOVQ 8(R9),  R12
	MOVQ R12, 80(SP)
	MOVL 16(R9), R12
	MOVL R12, 88(SP)
	MOVL $0, 92(SP)
	// Lane 2.
	MOVQ 8(R10), R12
	MOVQ R12, 96(SP)
	MOVL 16(R10), R12
	MOVL R12, 104(SP)
	MOVL $0, 108(SP)
	// Lane 3.
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVL 16(R11), R12
	MOVL R12, 120(SP)
	MOVL $0, 124(SP)

	// Pack staging → SoA Block4 (Z14, Z15).
	VMOVDQU 0(SP), X14
	VINSERTI64X2 $1, 16(SP), Y14, Y14
	VINSERTI64X2 $2, 32(SP), Z14, Z14
	VINSERTI64X2 $3, 48(SP), Z14, Z14
	VMOVDQU 64(SP), X15
	VINSERTI64X2 $1, 80(SP), Y15, Y15
	VINSERTI64X2 $2, 96(SP), Z15, Z15
	VINSERTI64X2 $3, 112(SP), Z15, Z15

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

	// 15-round Areion512 permutation, interleaved on (Z0..Z3) and
	// (Z8..Z11). RC loaded dynamically into Z27 before each round.
	// (a,b,c,d) rotates per round following i%4 (existing convention).
	//
	// === Round 0  (i%4=0): a=x0, b=x1, c=x2, d=x3
	VMOVDQU64 ·AreionRC4x+0(SB), Z27
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27)
	// === Round 1  (i%4=1): a=x1, b=x2, c=x3, d=x0
	VMOVDQU64 ·AreionRC4x+64(SB), Z27
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27)
	// === Round 2  (i%4=2): a=x2, b=x3, c=x0, d=x1
	VMOVDQU64 ·AreionRC4x+128(SB), Z27
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27)
	// === Round 3  (i%4=3): a=x3, b=x0, c=x1, d=x2
	VMOVDQU64 ·AreionRC4x+192(SB), Z27
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z27)
	// === Round 4
	VMOVDQU64 ·AreionRC4x+256(SB), Z27
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27)
	// === Round 5
	VMOVDQU64 ·AreionRC4x+320(SB), Z27
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27)
	// === Round 6
	VMOVDQU64 ·AreionRC4x+384(SB), Z27
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27)
	// === Round 7
	VMOVDQU64 ·AreionRC4x+448(SB), Z27
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z27)
	// === Round 8
	VMOVDQU64 ·AreionRC4x+512(SB), Z27
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27)
	// === Round 9
	VMOVDQU64 ·AreionRC4x+576(SB), Z27
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27)
	// === Round 10
	VMOVDQU64 ·AreionRC4x+640(SB), Z27
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27)
	// === Round 11
	VMOVDQU64 ·AreionRC4x+704(SB), Z27
	AREION512_FUSED_ROUND(Z3, Z0, Z1, Z2, Z11, Z8,  Z9,  Z10, Z27)
	// === Round 12 (first of final 3)
	VMOVDQU64 ·AreionRC4x+768(SB), Z27
	AREION512_FUSED_ROUND(Z0, Z1, Z2, Z3, Z8,  Z9,  Z10, Z11, Z27)
	// === Round 13
	VMOVDQU64 ·AreionRC4x+832(SB), Z27
	AREION512_FUSED_ROUND(Z1, Z2, Z3, Z0, Z9,  Z10, Z11, Z8,  Z27)
	// === Round 14
	VMOVDQU64 ·AreionRC4x+896(SB), Z27
	AREION512_FUSED_ROUND(Z2, Z3, Z0, Z1, Z10, Z11, Z8,  Z9,  Z27)

	// ===== Final cyclic rotation `(x0,x1,x2,x3) → (x3,x0,x1,x2)`
	// fused with SoEM XOR `state1' ⊕ state2'` and writeback. Same
	// pattern as the per-half fused kernel — rotation just renames
	// register roles, so the rotated XOR pattern uses register
	// contents directly.
	//
	//   *out[lane][0..16]  = rotated_x0 = state1.x3 ⊕ state2.x3 = Z3 ⊕ Z11
	//   *out[lane][16..32] = rotated_x1 = state1.x0 ⊕ state2.x0 = Z0 ⊕ Z8
	//   *out[lane][32..48] = rotated_x2 = state1.x1 ⊕ state2.x1 = Z1 ⊕ Z9
	//   *out[lane][48..64] = rotated_x3 = state1.x2 ⊕ state2.x2 = Z2 ⊕ Z10
	//
	// Output layout (per lane stride 64): SoA → AoS via VEXTRACTI64X2.
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
