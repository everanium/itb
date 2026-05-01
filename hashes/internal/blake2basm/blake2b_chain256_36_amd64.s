//go:build amd64 && !purego

// ZMM-batched fused chain-absorb kernel for BLAKE2b-256 with 36-byte
// per-lane data input (the ITB SetNonceBits(256) buf shape).
//
// Per-lane buffer construction (matches the public hashes.BLAKE2b256
// closure bit-exactly):
//
//	buf[0:32]   = b2key                (shared across all 4 lanes)
//	buf[32:68]  = data[lane]           (per-lane, 36 bytes)
//	then for i in 0..3:
//	  buf[32+i*8 : 40+i*8] ^= seeds[lane][i]   (LE)
//
// The 68-byte buf is zero-padded to a 128-byte block by blake2b
// internally; one compression with t=68 (= 32 key + 36 data), f=^0.
//
//	blake2b256ChainAbsorb36x4Asm(
//	    h0       *[8]uint64,        // Blake2bIV256Param (paramBlock 0x01010020)
//	    b2key    *[32]byte,         // shared 32-byte fixed key
//	    seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥36 bytes
//	    out      *[4][8]uint64)     // output: only out[lane][0..4] meaningful

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

// 256-bit seed-XOR macro: per-lane stride is 32 bytes (4 × uint64),
// vs the 512-bit kernel's 64-byte stride.
#define EMIT_M_FROM_DATAXSEED(data_off, seed_idx, y_dst) \
	MOVQ data_off(R8),  R12; \
	XORQ seed_idx*8 + 0*32(CX), R12; \
	MOVQ data_off(R9),  R13; \
	XORQ seed_idx*8 + 1*32(CX), R13; \
	MOVQ data_off(R10), R14; \
	XORQ seed_idx*8 + 2*32(CX), R14; \
	MOVQ data_off(R11), DI; \
	XORQ seed_idx*8 + 3*32(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

#define EMIT_M_FROM_DATAEXT4XSEED(data_off, seed_idx, y_dst) \
	MOVL data_off(R8),  R12; \
	XORQ seed_idx*8 + 0*32(CX), R12; \
	MOVL data_off(R9),  R13; \
	XORQ seed_idx*8 + 1*32(CX), R13; \
	MOVL data_off(R10), R14; \
	XORQ seed_idx*8 + 2*32(CX), R14; \
	MOVL data_off(R11), DI; \
	XORQ seed_idx*8 + 3*32(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

#define EMIT_M_FROM_SEED(seed_idx, y_dst) \
	MOVQ seed_idx*8 + 0*32(CX), R12; \
	MOVQ seed_idx*8 + 1*32(CX), R13; \
	MOVQ seed_idx*8 + 2*32(CX), R14; \
	MOVQ seed_idx*8 + 3*32(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

// EMIT_M_FROM_DATAEXT4_NOSEED — 4-byte zero-extended data load with
// no seed XOR. Used for m positions where the data region overlaps
// the buf payload past the seed-injection [32:64] range.
#define EMIT_M_FROM_DATAEXT4_NOSEED(data_off, y_dst) \
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

// func blake2b256ChainAbsorb36x4Asm(...)
TEXT ·blake2b256ChainAbsorb36x4Asm(SB), NOSPLIT, $0-40
	MOVQ h0+0(FP),       AX
	MOVQ b2key+8(FP),    BX
	MOVQ seeds+16(FP),   CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP),     R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== State init =====
	VPBROADCASTQ 0(AX),  Z0
	VPBROADCASTQ 8(AX),  Z1
	VPBROADCASTQ 16(AX), Z2
	VPBROADCASTQ 24(AX), Z3
	VPBROADCASTQ 32(AX), Z4
	VPBROADCASTQ 40(AX), Z5
	VPBROADCASTQ 48(AX), Z6
	VPBROADCASTQ 56(AX), Z7

	VPBROADCASTQ ·Blake2bIV+0(SB),  Z8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Z9
	VPBROADCASTQ ·Blake2bIV+16(SB), Z10
	VPBROADCASTQ ·Blake2bIV+24(SB), Z11
	VPBROADCASTQ ·Blake2bIV+32(SB), Z12
	VPBROADCASTQ ·Blake2bIV+40(SB), Z13
	VPBROADCASTQ ·Blake2bIV+48(SB), Z14
	VPBROADCASTQ ·Blake2bIV+56(SB), Z15

	// t = 68 = key_len(32) + data_len(36).
	MOVQ $68, R12
	VPBROADCASTQ R12, Z16
	VPXORQ Z16, Z12, Z12

	// f = ^0 (final block).
	VPTERNLOGQ $0xff, Z16, Z16, Z16
	VPXORQ Z16, Z14, Z14

	// ===== Build message words m[0..15] =====
	// m[4..8] first (uses X16/X17 scratch — m[0..3] come last).
	//
	// m[4] = data[lane][0:8]   ⊕ seeds[lane][0]
	EMIT_M_FROM_DATAXSEED(0, 0, Y20)
	// m[5] = data[lane][8:16]  ⊕ seeds[lane][1]
	EMIT_M_FROM_DATAXSEED(8, 1, Y21)
	// m[6] = data[lane][16:24] ⊕ seeds[lane][2]
	EMIT_M_FROM_DATAXSEED(16, 2, Y22)
	// m[7] = data[lane][24:32] ⊕ seeds[lane][3]
	EMIT_M_FROM_DATAXSEED(24, 3, Y23)
	// m[8] = (data[lane][32:36] || zero[0:4]). No seed XOR
	// (seed-injection region [32:64] of buf only covers m[4..7]).
	EMIT_M_FROM_DATAEXT4_NOSEED(32, Y24)

	// m[0..3] from b2key (32-byte key prefix → 4 uint64).
	VPBROADCASTQ 0(BX),  Z16
	VPBROADCASTQ 8(BX),  Z17
	VPBROADCASTQ 16(BX), Z18
	VPBROADCASTQ 24(BX), Z19

	// m[9..15] = 0 (zero pad region of the 128-byte block after byte 68).
	VPXORQ Z25, Z25, Z25
	VPXORQ Z26, Z26, Z26
	VPXORQ Z27, Z27, Z27
	VPXORQ Z28, Z28, Z28
	VPXORQ Z29, Z29, Z29
	VPXORQ Z30, Z30, Z30
	VPXORQ Z31, Z31, Z31

	// ===== 12 mixing rounds =====
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

	// ===== Output XOR fold (only Z0..Z3 needed for 32-byte digest) =====
	VPBROADCASTQ 0(AX),  Z16
	VPXORQ Z16, Z0, Z0
	VPBROADCASTQ 8(AX),  Z16
	VPXORQ Z16, Z1, Z1
	VPBROADCASTQ 16(AX), Z16
	VPXORQ Z16, Z2, Z2
	VPBROADCASTQ 24(AX), Z16
	VPXORQ Z16, Z3, Z3

	VPXORQ Z8,  Z0, Z0
	VPXORQ Z9,  Z1, Z1
	VPXORQ Z10, Z2, Z2
	VPXORQ Z11, Z3, Z3

	// ===== Writeback (only out[lane][0..4] = 32 bytes) =====
	// out is *[4][8]uint64; per-lane stride still 64 bytes since the
	// output array layout is uniform with the 512-bit case (callers
	// just truncate to out[0..4] after the call).
	MOVQ R15, R8
	LEAQ 64(R15), R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11

	STORE_LANE_QW(Z0, 0)
	STORE_LANE_QW(Z1, 8)
	STORE_LANE_QW(Z2, 16)
	STORE_LANE_QW(Z3, 24)

	VZEROUPPER
	RET
