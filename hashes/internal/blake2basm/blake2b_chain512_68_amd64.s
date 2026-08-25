//go:build amd64 && !purego && !noitbasm

// YMM-batched fused chain-absorb kernel for BLAKE2b-512 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape). Two
// 128-byte BLAKE2b compression blocks per lane, with state-residency
// in YMM registers between the two compressions (the 4 × 64-bit
// lane qwords fill one YMM register exactly):
//
//	Block 1 (t=128, f=0):  buf[0:128]   = b2key + (data[0:64] ⊕ seed)
//	Block 2 (t=132, f=^0): buf[128:132] = data[64:68] (no seed XOR;
//	                                       the seed-injection region
//	                                       buf[64:128] lives entirely
//	                                       in block 1)
//
// Four pixels processed lane-parallel: 16 YMM registers hold v[0..15]
// across both compressions; the remaining 16 YMMs hold m[0..15] for
// the active block. Between the blocks, the post-block-1 chaining
// hash h_after_block1 is held in Y0..Y7 (= the v[0..7] init for
// block 2) and also saved to stack so the final block-2 fold can
// XOR it back in.
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
// Stack frame: 256 bytes for h_after_block1 save (8 YMMs × 32 bytes).

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
	BLAKE2B_G(Y0, Y4, Y8,  Y12, s0,  s1); \
	BLAKE2B_G(Y1, Y5, Y9,  Y13, s2,  s3); \
	BLAKE2B_G(Y2, Y6, Y10, Y14, s4,  s5); \
	BLAKE2B_G(Y3, Y7, Y11, Y15, s6,  s7); \
	BLAKE2B_G(Y0, Y5, Y10, Y15, s8,  s9); \
	BLAKE2B_G(Y1, Y6, Y11, Y12, s10, s11); \
	BLAKE2B_G(Y2, Y7, Y8,  Y13, s12, s13); \
	BLAKE2B_G(Y3, Y4, Y9,  Y14, s14, s15)

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
TEXT ·blake2b512ChainAbsorb68x4Asm(SB), NOSPLIT, $256-40
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
	VPBROADCASTQ 0(AX),  Y0
	VPBROADCASTQ 8(AX),  Y1
	VPBROADCASTQ 16(AX), Y2
	VPBROADCASTQ 24(AX), Y3
	VPBROADCASTQ 32(AX), Y4
	VPBROADCASTQ 40(AX), Y5
	VPBROADCASTQ 48(AX), Y6
	VPBROADCASTQ 56(AX), Y7

	// v[8..15] = IV[0..7] broadcast.
	VPBROADCASTQ ·Blake2bIV+0(SB),  Y8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Y9
	VPBROADCASTQ ·Blake2bIV+16(SB), Y10
	VPBROADCASTQ ·Blake2bIV+24(SB), Y11
	VPBROADCASTQ ·Blake2bIV+32(SB), Y12
	VPBROADCASTQ ·Blake2bIV+40(SB), Y13
	VPBROADCASTQ ·Blake2bIV+48(SB), Y14
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15

	// Block 1: t = 128 (cumulative byte count after this block).
	// f = 0 (NOT final — block 2 follows).
	MOVQ $128, R12
	VPBROADCASTQ R12, Y16
	VPXORQ Y16, Y12, Y12

	// ===== Block 1 message-word build (m[8..15] before m[0..7] to
	// avoid X16/X17 scratch clobbering Y16/Y17 message broadcasts).
	EMIT_M_FROM_DATAXSEED(0,  0, Y24)
	EMIT_M_FROM_DATAXSEED(8,  1, Y25)
	EMIT_M_FROM_DATAXSEED(16, 2, Y26)
	EMIT_M_FROM_DATAXSEED(24, 3, Y27)
	EMIT_M_FROM_DATAXSEED(32, 4, Y28)
	EMIT_M_FROM_DATAXSEED(40, 5, Y29)
	EMIT_M_FROM_DATAXSEED(48, 6, Y30)
	EMIT_M_FROM_DATAXSEED(56, 7, Y31)

	VPBROADCASTQ 0(BX),  Y16
	VPBROADCASTQ 8(BX),  Y17
	VPBROADCASTQ 16(BX), Y18
	VPBROADCASTQ 24(BX), Y19
	VPBROADCASTQ 32(BX), Y20
	VPBROADCASTQ 40(BX), Y21
	VPBROADCASTQ 48(BX), Y22
	VPBROADCASTQ 56(BX), Y23

	// ===== Block 1: 12 rounds =====
	BLAKE2B_ROUND(Y16, Y17, Y18, Y19, Y20, Y21, Y22, Y23, Y24, Y25, Y26, Y27, Y28, Y29, Y30, Y31)
	BLAKE2B_ROUND(Y30, Y26, Y20, Y24, Y25, Y31, Y29, Y22, Y17, Y28, Y16, Y18, Y27, Y23, Y21, Y19)
	BLAKE2B_ROUND(Y27, Y24, Y28, Y16, Y21, Y18, Y31, Y29, Y26, Y30, Y19, Y22, Y23, Y17, Y25, Y20)
	BLAKE2B_ROUND(Y23, Y25, Y19, Y17, Y29, Y28, Y27, Y30, Y18, Y22, Y21, Y26, Y20, Y16, Y31, Y24)
	BLAKE2B_ROUND(Y25, Y16, Y21, Y23, Y18, Y20, Y26, Y31, Y30, Y17, Y27, Y28, Y22, Y24, Y19, Y29)
	BLAKE2B_ROUND(Y18, Y28, Y22, Y26, Y16, Y27, Y24, Y19, Y20, Y29, Y23, Y21, Y31, Y30, Y17, Y25)
	BLAKE2B_ROUND(Y28, Y21, Y17, Y31, Y30, Y29, Y20, Y26, Y16, Y23, Y22, Y19, Y25, Y18, Y24, Y27)
	BLAKE2B_ROUND(Y29, Y27, Y23, Y30, Y28, Y17, Y19, Y25, Y21, Y16, Y31, Y20, Y24, Y22, Y18, Y26)
	BLAKE2B_ROUND(Y22, Y31, Y30, Y25, Y27, Y19, Y16, Y24, Y28, Y18, Y29, Y23, Y17, Y20, Y26, Y21)
	BLAKE2B_ROUND(Y26, Y18, Y24, Y20, Y23, Y22, Y17, Y21, Y31, Y27, Y25, Y30, Y19, Y28, Y29, Y16)
	BLAKE2B_ROUND(Y16, Y17, Y18, Y19, Y20, Y21, Y22, Y23, Y24, Y25, Y26, Y27, Y28, Y29, Y30, Y31)
	BLAKE2B_ROUND(Y30, Y26, Y20, Y24, Y25, Y31, Y29, Y22, Y17, Y28, Y16, Y18, Y27, Y23, Y21, Y19)

	// ===== Block 1 fold: h_after_block1[k] = h0[k] ⊕ v[k] ⊕ v[k+8]
	// for k in 0..7. Result lives in Y0..Y7 (= v[0..7] init for block 2).
	// Single VPTERNLOGQ per word with truth table 0x96 (three-way XOR),
	// h0[k] re-read from (AX) via the embedded-broadcast memory operand.
	VPTERNLOGQ.BCST $0x96, 0(AX),  Y8,  Y0
	VPTERNLOGQ.BCST $0x96, 8(AX),  Y9,  Y1
	VPTERNLOGQ.BCST $0x96, 16(AX), Y10, Y2
	VPTERNLOGQ.BCST $0x96, 24(AX), Y11, Y3
	VPTERNLOGQ.BCST $0x96, 32(AX), Y12, Y4
	VPTERNLOGQ.BCST $0x96, 40(AX), Y13, Y5
	VPTERNLOGQ.BCST $0x96, 48(AX), Y14, Y6
	VPTERNLOGQ.BCST $0x96, 56(AX), Y15, Y7

	// Save h_after_block1 to stack so we can XOR it into the final
	// block-2 fold (Y0..Y7 will be mutated by the block-2 rounds).
	VMOVDQU64 Y0, 0(SP)
	VMOVDQU64 Y1, 32(SP)
	VMOVDQU64 Y2, 64(SP)
	VMOVDQU64 Y3, 96(SP)
	VMOVDQU64 Y4, 128(SP)
	VMOVDQU64 Y5, 160(SP)
	VMOVDQU64 Y6, 192(SP)
	VMOVDQU64 Y7, 224(SP)

	// ===== Block 2 state init =====
	// v[0..7] = h_after_block1 (already in Y0..Y7 from the block-1 fold).
	// v[8..15] = IV broadcast (re-init Y8..Y15).
	VPBROADCASTQ ·Blake2bIV+0(SB),  Y8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Y9
	VPBROADCASTQ ·Blake2bIV+16(SB), Y10
	VPBROADCASTQ ·Blake2bIV+24(SB), Y11
	VPBROADCASTQ ·Blake2bIV+32(SB), Y12
	VPBROADCASTQ ·Blake2bIV+40(SB), Y13
	VPBROADCASTQ ·Blake2bIV+48(SB), Y14
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15

	// Block 2: t = 132 (= 128 + 4 trailing data bytes).
	MOVQ $132, R12
	VPBROADCASTQ R12, Y16
	VPXORQ Y16, Y12, Y12

	// f = ^0 (final block).
	VPTERNLOGQ $0xff, Y16, Y16, Y16
	VPXORQ Y16, Y14, Y14

	// ===== Block 2 message-word build =====
	// m[0] = (data[lane][64:68] || zero[0:4]). No seed XOR (seed only
	// covers buf[64:128] which is entirely in block 1).
	EMIT_M_FROM_DATAEXT4(64, Y16)
	// m[1..15] = 0. Block 2's payload region buf[128+8:256] is pure
	// zero pad.
	VPXORQ Y17, Y17, Y17
	VPXORQ Y18, Y18, Y18
	VPXORQ Y19, Y19, Y19
	VPXORQ Y20, Y20, Y20
	VPXORQ Y21, Y21, Y21
	VPXORQ Y22, Y22, Y22
	VPXORQ Y23, Y23, Y23
	VPXORQ Y24, Y24, Y24
	VPXORQ Y25, Y25, Y25
	VPXORQ Y26, Y26, Y26
	VPXORQ Y27, Y27, Y27
	VPXORQ Y28, Y28, Y28
	VPXORQ Y29, Y29, Y29
	VPXORQ Y30, Y30, Y30
	VPXORQ Y31, Y31, Y31

	// ===== Block 2: 12 rounds =====
	BLAKE2B_ROUND(Y16, Y17, Y18, Y19, Y20, Y21, Y22, Y23, Y24, Y25, Y26, Y27, Y28, Y29, Y30, Y31)
	BLAKE2B_ROUND(Y30, Y26, Y20, Y24, Y25, Y31, Y29, Y22, Y17, Y28, Y16, Y18, Y27, Y23, Y21, Y19)
	BLAKE2B_ROUND(Y27, Y24, Y28, Y16, Y21, Y18, Y31, Y29, Y26, Y30, Y19, Y22, Y23, Y17, Y25, Y20)
	BLAKE2B_ROUND(Y23, Y25, Y19, Y17, Y29, Y28, Y27, Y30, Y18, Y22, Y21, Y26, Y20, Y16, Y31, Y24)
	BLAKE2B_ROUND(Y25, Y16, Y21, Y23, Y18, Y20, Y26, Y31, Y30, Y17, Y27, Y28, Y22, Y24, Y19, Y29)
	BLAKE2B_ROUND(Y18, Y28, Y22, Y26, Y16, Y27, Y24, Y19, Y20, Y29, Y23, Y21, Y31, Y30, Y17, Y25)
	BLAKE2B_ROUND(Y28, Y21, Y17, Y31, Y30, Y29, Y20, Y26, Y16, Y23, Y22, Y19, Y25, Y18, Y24, Y27)
	BLAKE2B_ROUND(Y29, Y27, Y23, Y30, Y28, Y17, Y19, Y25, Y21, Y16, Y31, Y20, Y24, Y22, Y18, Y26)
	BLAKE2B_ROUND(Y22, Y31, Y30, Y25, Y27, Y19, Y16, Y24, Y28, Y18, Y29, Y23, Y17, Y20, Y26, Y21)
	BLAKE2B_ROUND(Y26, Y18, Y24, Y20, Y23, Y22, Y17, Y21, Y31, Y27, Y25, Y30, Y19, Y28, Y29, Y16)
	BLAKE2B_ROUND(Y16, Y17, Y18, Y19, Y20, Y21, Y22, Y23, Y24, Y25, Y26, Y27, Y28, Y29, Y30, Y31)
	BLAKE2B_ROUND(Y30, Y26, Y20, Y24, Y25, Y31, Y29, Y22, Y17, Y28, Y16, Y18, Y27, Y23, Y21, Y19)

	// ===== Block 2 final fold: out[k] = h_after_block1[k] ⊕ v[k] ⊕ v[k+8]
	// Single VPTERNLOGQ per word with truth table 0x96 (three-way XOR);
	// h_after_block1 reloaded from stack via the full-width memory operand.
	VPTERNLOGQ $0x96, 0(SP),   Y8,  Y0
	VPTERNLOGQ $0x96, 32(SP),  Y9,  Y1
	VPTERNLOGQ $0x96, 64(SP), Y10, Y2
	VPTERNLOGQ $0x96, 96(SP), Y11, Y3
	VPTERNLOGQ $0x96, 128(SP), Y12, Y4
	VPTERNLOGQ $0x96, 160(SP), Y13, Y5
	VPTERNLOGQ $0x96, 192(SP), Y14, Y6
	VPTERNLOGQ $0x96, 224(SP), Y15, Y7

	// ===== Writeback to out[4][8]uint64 =====
	MOVQ R15, R8
	LEAQ 64(R15), R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11

	STORE_LANE_QW(Y0, 0)
	STORE_LANE_QW(Y1, 8)
	STORE_LANE_QW(Y2, 16)
	STORE_LANE_QW(Y3, 24)
	STORE_LANE_QW(Y4, 32)
	STORE_LANE_QW(Y5, 40)
	STORE_LANE_QW(Y6, 48)
	STORE_LANE_QW(Y7, 56)

	VZEROUPPER
	RET
