//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for BLAKE2b-512 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape). Two
// 128-byte BLAKE2b compression blocks per lane, with state-residency
// in ZMM registers between the two compressions:
//
//	Block 1 (t=128, f=0):  buf[0:128]   = b2key + (data[0:64] ⊕ seed)
//	Block 2 (t=132, f=^0): buf[128:132] = data[64:68] (no seed XOR;
//	                                       the seed-injection region
//	                                       buf[64:128] lives entirely
//	                                       in block 1)
//
// Four pixels processed lane-parallel: 16 ZMM registers hold v[0..15]
// across both compressions (lanes 0..3 active, 4..7 padding); the
// remaining 16 ZMMs hold m[0..15] for the active block. Between the
// blocks, the post-block-1 chaining hash h_after_block1 is held in
// Z0..Z7 (= the v[0..7] init for block 2) and also saved to stack so
// the final block-2 fold can XOR it back in.
//
// Function signature (Go-side prototype in blake2basm_chain_amd64.go):
//
//	blake2b512ChainAbsorb68x4Asm(
//	    h0       *[8]uint64,        // param-XOR'd IV (broadcast to 4 lanes)
//	    b2key    *[64]byte,         // shared 64-byte fixed key
//	    seeds    *[4][8]uint64,     // per-lane 8 seed components
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥68 bytes
//	    out      *[4][8]uint64)     // output: 4 lanes × 8 uint64
//
// Stack frame: 512 bytes for h_after_block1 save (8 ZMMs × 64 bytes).

#include "textflag.h"

#define BLAKE2B_G(a, b, c, d, mx, my) \
	VPADDQ b,  a, a; \
	VPADDQ mx, a, a; \
	VPXORQ a,  d, d; \
	VPRORQ $32, d, d; \
	VPADDQ d,  c, c; \
	VPXORQ c,  b, b; \
	VPRORQ $24, b, b; \
	VPADDQ b,  a, a; \
	VPADDQ my, a, a; \
	VPXORQ a,  d, d; \
	VPRORQ $16, d, d; \
	VPADDQ d,  c, c; \
	VPXORQ c,  b, b; \
	VPRORQ $63, b, b

#define BLAKE2B_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
	BLAKE2B_G(Z0, Z4, Z8,  Z12, s0,  s1); \
	BLAKE2B_G(Z1, Z5, Z9,  Z13, s2,  s3); \
	BLAKE2B_G(Z2, Z6, Z10, Z14, s4,  s5); \
	BLAKE2B_G(Z3, Z7, Z11, Z15, s6,  s7); \
	BLAKE2B_G(Z0, Z5, Z10, Z15, s8,  s9); \
	BLAKE2B_G(Z1, Z6, Z11, Z12, s10, s11); \
	BLAKE2B_G(Z2, Z7, Z8,  Z13, s12, s13); \
	BLAKE2B_G(Z3, Z4, Z9,  Z14, s14, s15)

#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, y_dst) \
	VMOVQ l0, X16; \
	VPINSRQ $1, l1, X16, X16; \
	VMOVQ l2, X17; \
	VPINSRQ $1, l3, X17, X17; \
	VINSERTI64X2 $1, X17, Y16, y_dst

// Block-1 message-pack helpers — apply seed XOR over the data region
// (buf[64:128] = data[0:64] then XOR'd with seed[0..7]).
#define EMIT_M_FROM_DATAXSEED(data_off, seed_idx, y_dst) \
	MOVQ data_off(R8),  R12; \
	XORQ seed_idx*8 + 0*64(CX), R12; \
	MOVQ data_off(R9),  R13; \
	XORQ seed_idx*8 + 1*64(CX), R13; \
	MOVQ data_off(R10), R14; \
	XORQ seed_idx*8 + 2*64(CX), R14; \
	MOVQ data_off(R11), DI; \
	XORQ seed_idx*8 + 3*64(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

// Block-2 message-pack helper — m[0] = (data[64:68] || zero[0:4]).
// No seed XOR (seed only applies to block 1's data region). MOVL
// from data_off zero-extends the upper 32 bits.
#define EMIT_M_FROM_DATAEXT4(data_off, y_dst) \
	MOVL data_off(R8),  R12; \
	MOVL data_off(R9),  R13; \
	MOVL data_off(R10), R14; \
	MOVL data_off(R11), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

#define STORE_LANE_QW(z_src, off) \
	VEXTRACTI64X2 $0, z_src, X16; \
	VPEXTRQ $0, X16, off(R8); \
	VPEXTRQ $1, X16, off(R9); \
	VEXTRACTI64X2 $1, z_src, X17; \
	VPEXTRQ $0, X17, off(R10); \
	VPEXTRQ $1, X17, off(R11)

// func blake2b512ChainAbsorb68x4Asm(
//     h0       *[8]uint64,
//     b2key    *[64]byte,
//     seeds    *[4][8]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint64)
TEXT ·blake2b512ChainAbsorb68x4Asm(SB), NOSPLIT, $512-40
	MOVQ h0+0(FP),       AX
	MOVQ b2key+8(FP),    BX
	MOVQ seeds+16(FP),   CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP),     R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== Block 1 state init =====
	// v[0..7] = h0 broadcast (Blake2bIV512Param: paramBlock pre-XOR'd
	// into h0[0]).
	VPBROADCASTQ 0(AX),  Z0
	VPBROADCASTQ 8(AX),  Z1
	VPBROADCASTQ 16(AX), Z2
	VPBROADCASTQ 24(AX), Z3
	VPBROADCASTQ 32(AX), Z4
	VPBROADCASTQ 40(AX), Z5
	VPBROADCASTQ 48(AX), Z6
	VPBROADCASTQ 56(AX), Z7

	// v[8..15] = IV[0..7] broadcast.
	VPBROADCASTQ ·Blake2bIV+0(SB),  Z8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Z9
	VPBROADCASTQ ·Blake2bIV+16(SB), Z10
	VPBROADCASTQ ·Blake2bIV+24(SB), Z11
	VPBROADCASTQ ·Blake2bIV+32(SB), Z12
	VPBROADCASTQ ·Blake2bIV+40(SB), Z13
	VPBROADCASTQ ·Blake2bIV+48(SB), Z14
	VPBROADCASTQ ·Blake2bIV+56(SB), Z15

	// Block 1: t = 128 (cumulative byte count after this block).
	// f = 0 (NOT final — block 2 follows).
	MOVQ $128, R12
	VPBROADCASTQ R12, Z16
	VPXORQ Z16, Z12, Z12

	// ===== Block 1 message-word build (m[8..15] before m[0..7] to
	// avoid X16/X17 scratch clobbering Z16/Z17 message broadcasts).
	EMIT_M_FROM_DATAXSEED(0,  0, Y24)
	EMIT_M_FROM_DATAXSEED(8,  1, Y25)
	EMIT_M_FROM_DATAXSEED(16, 2, Y26)
	EMIT_M_FROM_DATAXSEED(24, 3, Y27)
	EMIT_M_FROM_DATAXSEED(32, 4, Y28)
	EMIT_M_FROM_DATAXSEED(40, 5, Y29)
	EMIT_M_FROM_DATAXSEED(48, 6, Y30)
	EMIT_M_FROM_DATAXSEED(56, 7, Y31)

	VPBROADCASTQ 0(BX),  Z16
	VPBROADCASTQ 8(BX),  Z17
	VPBROADCASTQ 16(BX), Z18
	VPBROADCASTQ 24(BX), Z19
	VPBROADCASTQ 32(BX), Z20
	VPBROADCASTQ 40(BX), Z21
	VPBROADCASTQ 48(BX), Z22
	VPBROADCASTQ 56(BX), Z23

	// ===== Block 1: 12 rounds =====
	BLAKE2B_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE2B_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)
	BLAKE2B_ROUND(Z27, Z24, Z28, Z16, Z21, Z18, Z31, Z29, Z26, Z30, Z19, Z22, Z23, Z17, Z25, Z20)
	BLAKE2B_ROUND(Z23, Z25, Z19, Z17, Z29, Z28, Z27, Z30, Z18, Z22, Z21, Z26, Z20, Z16, Z31, Z24)
	BLAKE2B_ROUND(Z25, Z16, Z21, Z23, Z18, Z20, Z26, Z31, Z30, Z17, Z27, Z28, Z22, Z24, Z19, Z29)
	BLAKE2B_ROUND(Z18, Z28, Z22, Z26, Z16, Z27, Z24, Z19, Z20, Z29, Z23, Z21, Z31, Z30, Z17, Z25)
	BLAKE2B_ROUND(Z28, Z21, Z17, Z31, Z30, Z29, Z20, Z26, Z16, Z23, Z22, Z19, Z25, Z18, Z24, Z27)
	BLAKE2B_ROUND(Z29, Z27, Z23, Z30, Z28, Z17, Z19, Z25, Z21, Z16, Z31, Z20, Z24, Z22, Z18, Z26)
	BLAKE2B_ROUND(Z22, Z31, Z30, Z25, Z27, Z19, Z16, Z24, Z28, Z18, Z29, Z23, Z17, Z20, Z26, Z21)
	BLAKE2B_ROUND(Z26, Z18, Z24, Z20, Z23, Z22, Z17, Z21, Z31, Z27, Z25, Z30, Z19, Z28, Z29, Z16)
	BLAKE2B_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE2B_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)

	// ===== Block 1 fold: h_after_block1[k] = h0[k] ⊕ v[k] ⊕ v[k+8]
	// for k in 0..7. Result lives in Z0..Z7 (= v[0..7] init for block 2).
	VPXORQ Z8,  Z0, Z0
	VPXORQ Z9,  Z1, Z1
	VPXORQ Z10, Z2, Z2
	VPXORQ Z11, Z3, Z3
	VPXORQ Z12, Z4, Z4
	VPXORQ Z13, Z5, Z5
	VPXORQ Z14, Z6, Z6
	VPXORQ Z15, Z7, Z7

	VPBROADCASTQ 0(AX),  Z16
	VPXORQ Z16, Z0, Z0
	VPBROADCASTQ 8(AX),  Z16
	VPXORQ Z16, Z1, Z1
	VPBROADCASTQ 16(AX), Z16
	VPXORQ Z16, Z2, Z2
	VPBROADCASTQ 24(AX), Z16
	VPXORQ Z16, Z3, Z3
	VPBROADCASTQ 32(AX), Z16
	VPXORQ Z16, Z4, Z4
	VPBROADCASTQ 40(AX), Z16
	VPXORQ Z16, Z5, Z5
	VPBROADCASTQ 48(AX), Z16
	VPXORQ Z16, Z6, Z6
	VPBROADCASTQ 56(AX), Z16
	VPXORQ Z16, Z7, Z7

	// Save h_after_block1 to stack so we can XOR it into the final
	// block-2 fold (Z0..Z7 will be mutated by the block-2 rounds).
	VMOVDQU64 Z0, 0(SP)
	VMOVDQU64 Z1, 64(SP)
	VMOVDQU64 Z2, 128(SP)
	VMOVDQU64 Z3, 192(SP)
	VMOVDQU64 Z4, 256(SP)
	VMOVDQU64 Z5, 320(SP)
	VMOVDQU64 Z6, 384(SP)
	VMOVDQU64 Z7, 448(SP)

	// ===== Block 2 state init =====
	// v[0..7] = h_after_block1 (already in Z0..Z7 from the block-1 fold).
	// v[8..15] = IV broadcast (re-init Z8..Z15).
	VPBROADCASTQ ·Blake2bIV+0(SB),  Z8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Z9
	VPBROADCASTQ ·Blake2bIV+16(SB), Z10
	VPBROADCASTQ ·Blake2bIV+24(SB), Z11
	VPBROADCASTQ ·Blake2bIV+32(SB), Z12
	VPBROADCASTQ ·Blake2bIV+40(SB), Z13
	VPBROADCASTQ ·Blake2bIV+48(SB), Z14
	VPBROADCASTQ ·Blake2bIV+56(SB), Z15

	// Block 2: t = 132 (= 128 + 4 trailing data bytes).
	MOVQ $132, R12
	VPBROADCASTQ R12, Z16
	VPXORQ Z16, Z12, Z12

	// f = ^0 (final block).
	VPTERNLOGQ $0xff, Z16, Z16, Z16
	VPXORQ Z16, Z14, Z14

	// ===== Block 2 message-word build =====
	// m[0] = (data[lane][64:68] || zero[0:4]). No seed XOR (seed only
	// covers buf[64:128] which is entirely in block 1).
	EMIT_M_FROM_DATAEXT4(64, Y16)
	// m[1..15] = 0. Block 2's payload region buf[128+8:256] is pure
	// zero pad.
	VPXORQ Z17, Z17, Z17
	VPXORQ Z18, Z18, Z18
	VPXORQ Z19, Z19, Z19
	VPXORQ Z20, Z20, Z20
	VPXORQ Z21, Z21, Z21
	VPXORQ Z22, Z22, Z22
	VPXORQ Z23, Z23, Z23
	VPXORQ Z24, Z24, Z24
	VPXORQ Z25, Z25, Z25
	VPXORQ Z26, Z26, Z26
	VPXORQ Z27, Z27, Z27
	VPXORQ Z28, Z28, Z28
	VPXORQ Z29, Z29, Z29
	VPXORQ Z30, Z30, Z30
	VPXORQ Z31, Z31, Z31

	// ===== Block 2: 12 rounds =====
	BLAKE2B_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE2B_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)
	BLAKE2B_ROUND(Z27, Z24, Z28, Z16, Z21, Z18, Z31, Z29, Z26, Z30, Z19, Z22, Z23, Z17, Z25, Z20)
	BLAKE2B_ROUND(Z23, Z25, Z19, Z17, Z29, Z28, Z27, Z30, Z18, Z22, Z21, Z26, Z20, Z16, Z31, Z24)
	BLAKE2B_ROUND(Z25, Z16, Z21, Z23, Z18, Z20, Z26, Z31, Z30, Z17, Z27, Z28, Z22, Z24, Z19, Z29)
	BLAKE2B_ROUND(Z18, Z28, Z22, Z26, Z16, Z27, Z24, Z19, Z20, Z29, Z23, Z21, Z31, Z30, Z17, Z25)
	BLAKE2B_ROUND(Z28, Z21, Z17, Z31, Z30, Z29, Z20, Z26, Z16, Z23, Z22, Z19, Z25, Z18, Z24, Z27)
	BLAKE2B_ROUND(Z29, Z27, Z23, Z30, Z28, Z17, Z19, Z25, Z21, Z16, Z31, Z20, Z24, Z22, Z18, Z26)
	BLAKE2B_ROUND(Z22, Z31, Z30, Z25, Z27, Z19, Z16, Z24, Z28, Z18, Z29, Z23, Z17, Z20, Z26, Z21)
	BLAKE2B_ROUND(Z26, Z18, Z24, Z20, Z23, Z22, Z17, Z21, Z31, Z27, Z25, Z30, Z19, Z28, Z29, Z16)
	BLAKE2B_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE2B_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)

	// ===== Block 2 final fold: out[k] = h_after_block1[k] ⊕ v[k] ⊕ v[k+8]
	// h_after_block1 reloaded from stack via memory-source VPXORQ.
	VPXORQ Z8,  Z0, Z0
	VPXORQ Z9,  Z1, Z1
	VPXORQ Z10, Z2, Z2
	VPXORQ Z11, Z3, Z3
	VPXORQ Z12, Z4, Z4
	VPXORQ Z13, Z5, Z5
	VPXORQ Z14, Z6, Z6
	VPXORQ Z15, Z7, Z7

	VPXORQ 0(SP),   Z0, Z0
	VPXORQ 64(SP),  Z1, Z1
	VPXORQ 128(SP), Z2, Z2
	VPXORQ 192(SP), Z3, Z3
	VPXORQ 256(SP), Z4, Z4
	VPXORQ 320(SP), Z5, Z5
	VPXORQ 384(SP), Z6, Z6
	VPXORQ 448(SP), Z7, Z7

	// ===== Writeback to out[4][8]uint64 =====
	MOVQ R15, R8
	LEAQ 64(R15), R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11

	STORE_LANE_QW(Z0, 0)
	STORE_LANE_QW(Z1, 8)
	STORE_LANE_QW(Z2, 16)
	STORE_LANE_QW(Z3, 24)
	STORE_LANE_QW(Z4, 32)
	STORE_LANE_QW(Z5, 40)
	STORE_LANE_QW(Z6, 48)
	STORE_LANE_QW(Z7, 56)

	VZEROUPPER
	RET
