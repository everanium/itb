//go:build amd64 && !purego && !noitbasm

// YMM-batched fused chain-absorb kernel for BLAKE2b-256 with 13-byte
// per-lane data input — the Interlocked Barrier PRF fill message shape
// (0x03 || uint64-LE(groupIdx) || 4 reserved). Mechanical copy of the
// 20-byte kernel; only the two data-carrying message words at the tail
// of the seed-injection region differ.
//
// Per-lane buffer construction (matches hashes.BLAKE2b256 bit-exactly):
//
//	buf[0:32]   = b2key                (shared across all 4 lanes)
//	buf[32:45]  = data[lane]           (per-lane, 13 bytes)
//	buf[45:64]  = zero pad
//	then for i in 0..3:
//	  buf[32+i*8 : 40+i*8] ^= seeds[lane][i]   (LE)
//
// max(data_len, 32) = 32, so t = 64 (32 key + 32) exactly as the
// 20-byte kernel; one final-block compression. Message words:
//
//	m[0..3] = b2key
//	m[4]    = data[0:8]                       ⊕ seed[0]
//	m[5]    = (data[8:13] || zero[0:3])       ⊕ seed[1]   ← 5 data bytes
//	m[6]    = seed[2]                                       (data exhausted)
//	m[7]    = seed[3]
//
// data is read at offset 0 (MOVQ, 8 bytes) and offset 8 (MOVL 4 bytes +
// MOVBLZX 1 byte) = exactly 13 bytes; a MOVQ at offset 8 would read
// past the 13-byte scratch buffer into the adjacent lane.

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

// EMIT_M_FROM_DATA5XSEED — assemble the 5-byte little-endian value
// data[off:off+5] (4-byte MOVL at off + 1 byte MOVBLZX at off+4 shifted
// into byte position 4), zero-extended to 64 bits, XOR
// seeds[lane][seed_idx]. DX is a free scratch after the data pointers
// were loaded from it into R8..R11.
#define EMIT_M_FROM_DATA5XSEED(data_off, seed_idx, y_dst) \
	MOVL data_off(R8),  R12; MOVBLZX data_off+4(R8),  DX; SHLQ $32, DX; ORQ DX, R12; XORQ seed_idx*8 + 0*32(CX), R12; \
	MOVL data_off(R9),  R13; MOVBLZX data_off+4(R9),  DX; SHLQ $32, DX; ORQ DX, R13; XORQ seed_idx*8 + 1*32(CX), R13; \
	MOVL data_off(R10), R14; MOVBLZX data_off+4(R10), DX; SHLQ $32, DX; ORQ DX, R14; XORQ seed_idx*8 + 2*32(CX), R14; \
	MOVL data_off(R11), DI;  MOVBLZX data_off+4(R11), DX; SHLQ $32, DX; ORQ DX, DI;  XORQ seed_idx*8 + 3*32(CX), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

#define EMIT_M_FROM_SEED(seed_idx, y_dst) \
	MOVQ seed_idx*8 + 0*32(CX), R12; \
	MOVQ seed_idx*8 + 1*32(CX), R13; \
	MOVQ seed_idx*8 + 2*32(CX), R14; \
	MOVQ seed_idx*8 + 3*32(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

#define STORE_LANE_QW(z_src, off) \
	VEXTRACTI64X2 $0, z_src, X16; \
	VPEXTRQ $0, X16, off(R8); \
	VPEXTRQ $1, X16, off(R9); \
	VEXTRACTI64X2 $1, z_src, X17; \
	VPEXTRQ $0, X17, off(R10); \
	VPEXTRQ $1, X17, off(R11)

// func blake2b256ChainAbsorb13x4Asm(
//     h0       *[8]uint64,
//     b2key    *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint64)
TEXT ·blake2b256ChainAbsorb13x4Asm(SB), NOSPLIT, $0-40
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
	VPBROADCASTQ 0(AX),  Y0
	VPBROADCASTQ 8(AX),  Y1
	VPBROADCASTQ 16(AX), Y2
	VPBROADCASTQ 24(AX), Y3
	VPBROADCASTQ 32(AX), Y4
	VPBROADCASTQ 40(AX), Y5
	VPBROADCASTQ 48(AX), Y6
	VPBROADCASTQ 56(AX), Y7

	VPBROADCASTQ ·Blake2bIV+0(SB),  Y8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Y9
	VPBROADCASTQ ·Blake2bIV+16(SB), Y10
	VPBROADCASTQ ·Blake2bIV+24(SB), Y11
	VPBROADCASTQ ·Blake2bIV+32(SB), Y12
	VPBROADCASTQ ·Blake2bIV+40(SB), Y13
	VPBROADCASTQ ·Blake2bIV+48(SB), Y14
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15

	// t = 64 = key_len(32) + max(data_len, 32) = 32 + 32.
	MOVQ $64, R12
	VPBROADCASTQ R12, Y16
	VPXORQ Y16, Y12, Y12

	// f = ^0 (final block).
	VPTERNLOGQ $0xff, Y16, Y16, Y16
	VPXORQ Y16, Y14, Y14

	// ===== Build message words m[0..15] =====
	// m[4] = data[0:8] ⊕ seed[0]
	EMIT_M_FROM_DATAXSEED(0, 0, Y20)
	// m[5] = (data[8:13] || zero) ⊕ seed[1]
	EMIT_M_FROM_DATA5XSEED(8, 1, Y21)
	// m[6] = seed[2] (data exhausted at byte 13)
	EMIT_M_FROM_SEED(2, Y22)
	// m[7] = seed[3]
	EMIT_M_FROM_SEED(3, Y23)

	// m[0..3] from b2key (32-byte key prefix → 4 uint64).
	VPBROADCASTQ 0(BX),  Y16
	VPBROADCASTQ 8(BX),  Y17
	VPBROADCASTQ 16(BX), Y18
	VPBROADCASTQ 24(BX), Y19

	// m[8..15] = 0.
	VPXORQ Y24, Y24, Y24
	VPXORQ Y25, Y25, Y25
	VPXORQ Y26, Y26, Y26
	VPXORQ Y27, Y27, Y27
	VPXORQ Y28, Y28, Y28
	VPXORQ Y29, Y29, Y29
	VPXORQ Y30, Y30, Y30
	VPXORQ Y31, Y31, Y31

	// ===== 12 mixing rounds =====
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

	// ===== Output XOR fold (only Y0..Y3 needed for 32-byte digest) =====
	VPTERNLOGQ.BCST $0x96, 0(AX),  Y8,  Y0
	VPTERNLOGQ.BCST $0x96, 8(AX),  Y9,  Y1
	VPTERNLOGQ.BCST $0x96, 16(AX), Y10, Y2
	VPTERNLOGQ.BCST $0x96, 24(AX), Y11, Y3

	// ===== Writeback (only out[lane][0..4] = 32 bytes) =====
	MOVQ R15, R8
	LEAQ 64(R15), R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11

	STORE_LANE_QW(Y0, 0)
	STORE_LANE_QW(Y1, 8)
	STORE_LANE_QW(Y2, 16)
	STORE_LANE_QW(Y3, 24)

	VZEROUPPER
	RET
