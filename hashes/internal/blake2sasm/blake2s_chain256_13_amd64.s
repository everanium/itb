//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for BLAKE2s-256 with 13-byte
// per-lane data input — the Interlocked Barrier PRF fill message shape
// (0x03 || uint64-LE(groupIdx) || 4 reserved). Mechanical copy of the
// 20-byte kernel; only the two data-carrying message words at the tail
// of the seed-injection region differ.
//
// Per-lane buffer construction (matches hashes.BLAKE2s256 bit-exactly):
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
//	m[0..7]  = b2key
//	m[8]     = data[0:4]                ⊕ seed[0]_lo
//	m[9]     = data[4:8]                ⊕ seed[0]_hi
//	m[10]    = data[8:12]               ⊕ seed[1]_lo
//	m[11]    = (0x000000 || data[12])   ⊕ seed[1]_hi   ← one data byte
//	m[12]    = seed[2]_lo                                (data exhausted)
//	m[13]    = seed[2]_hi
//	m[14]    = seed[3]_lo
//	m[15]    = seed[3]_hi
//
// data is read at offsets 0, 4, 8 (MOVL) + offset 12 (MOVBLZX) =
// exactly 13 bytes; a MOVL at offset 12 would read past the 13-byte
// scratch buffer into the adjacent lane.

#include "textflag.h"

#define BLAKE2S_G(a, b, c, d, mx, my) \
	VPADDD b,  a, a; \
	VPADDD mx, a, a; \
	VPXORD a,  d, d; \
	VPRORD $16, d, d; \
	VPADDD d,  c, c; \
	VPXORD c,  b, b; \
	VPRORD $12, b, b; \
	VPADDD b,  a, a; \
	VPADDD my, a, a; \
	VPXORD a,  d, d; \
	VPRORD $8,  d, d; \
	VPADDD d,  c, c; \
	VPXORD c,  b, b; \
	VPRORD $7,  b, b

#define BLAKE2S_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
	BLAKE2S_G(X0, X4, X8,  X12, s0,  s1); \
	BLAKE2S_G(X1, X5, X9,  X13, s2,  s3); \
	BLAKE2S_G(X2, X6, X10, X14, s4,  s5); \
	BLAKE2S_G(X3, X7, X11, X15, s6,  s7); \
	BLAKE2S_G(X0, X5, X10, X15, s8,  s9); \
	BLAKE2S_G(X1, X6, X11, X12, s10, s11); \
	BLAKE2S_G(X2, X7, X8,  X13, s12, s13); \
	BLAKE2S_G(X3, X4, X9,  X14, s14, s15)

#define PACK_M_LANES(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

#define EMIT_M_FROM_DATAXSEEDLO(data_off, seed_idx, x_dst) \
	MOVL data_off(R8),  R12; \
	XORL seed_idx*8 + 0*32 + 0(CX), R12; \
	MOVL data_off(R9),  R13; \
	XORL seed_idx*8 + 1*32 + 0(CX), R13; \
	MOVL data_off(R10), R14; \
	XORL seed_idx*8 + 2*32 + 0(CX), R14; \
	MOVL data_off(R11), DI; \
	XORL seed_idx*8 + 3*32 + 0(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

#define EMIT_M_FROM_DATAXSEEDHI(data_off, seed_idx, x_dst) \
	MOVL data_off(R8),  R12; \
	XORL seed_idx*8 + 0*32 + 4(CX), R12; \
	MOVL data_off(R9),  R13; \
	XORL seed_idx*8 + 1*32 + 4(CX), R13; \
	MOVL data_off(R10), R14; \
	XORL seed_idx*8 + 2*32 + 4(CX), R14; \
	MOVL data_off(R11), DI; \
	XORL seed_idx*8 + 3*32 + 4(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

// EMIT_M_FROM_DATABYTEXSEEDHI — one data byte (zero-extended to the
// low byte of the 32-bit word) XOR seeds[lane][seed_idx]_hi32.
#define EMIT_M_FROM_DATABYTEXSEEDHI(data_off, seed_idx, x_dst) \
	MOVBLZX data_off(R8),  R12; \
	XORL seed_idx*8 + 0*32 + 4(CX), R12; \
	MOVBLZX data_off(R9),  R13; \
	XORL seed_idx*8 + 1*32 + 4(CX), R13; \
	MOVBLZX data_off(R10), R14; \
	XORL seed_idx*8 + 2*32 + 4(CX), R14; \
	MOVBLZX data_off(R11), DI; \
	XORL seed_idx*8 + 3*32 + 4(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

#define EMIT_M_FROM_SEEDLO(seed_idx, x_dst) \
	MOVL seed_idx*8 + 0*32 + 0(CX), R12; \
	MOVL seed_idx*8 + 1*32 + 0(CX), R13; \
	MOVL seed_idx*8 + 2*32 + 0(CX), R14; \
	MOVL seed_idx*8 + 3*32 + 0(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

#define EMIT_M_FROM_SEEDHI(seed_idx, x_dst) \
	MOVL seed_idx*8 + 0*32 + 4(CX), R12; \
	MOVL seed_idx*8 + 1*32 + 4(CX), R13; \
	MOVL seed_idx*8 + 2*32 + 4(CX), R14; \
	MOVL seed_idx*8 + 3*32 + 4(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

// func blake2s256ChainAbsorb13x4Asm(
//     h0       *[8]uint32,
//     b2key    *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint32)
TEXT ·blake2s256ChainAbsorb13x4Asm(SB), NOSPLIT, $0-40
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
	VPBROADCASTD 0(AX),  X0
	VPBROADCASTD 4(AX),  X1
	VPBROADCASTD 8(AX),  X2
	VPBROADCASTD 12(AX), X3
	VPBROADCASTD 16(AX), X4
	VPBROADCASTD 20(AX), X5
	VPBROADCASTD 24(AX), X6
	VPBROADCASTD 28(AX), X7

	VPBROADCASTD ·Blake2sIV+0(SB),  X8
	VPBROADCASTD ·Blake2sIV+4(SB),  X9
	VPBROADCASTD ·Blake2sIV+8(SB),  X10
	VPBROADCASTD ·Blake2sIV+12(SB), X11
	VPBROADCASTD ·Blake2sIV+16(SB), X12
	VPBROADCASTD ·Blake2sIV+20(SB), X13
	VPBROADCASTD ·Blake2sIV+24(SB), X14
	VPBROADCASTD ·Blake2sIV+28(SB), X15

	// t_lo = 64.
	MOVL $64, R12
	VPBROADCASTD R12, X16
	VPXORD X16, X12, X12
	// t_hi = 0 — X13 unchanged.

	// f0 = ^0 (final block), into v[14]. f1 = 0 — X15 unchanged.
	VPTERNLOGD $0xff, X16, X16, X16
	VPXORD X16, X14, X14

	// ===== Build message words m[0..15] =====
	// m[8]  = data[0:4]   ⊕ seed[0]_lo
	EMIT_M_FROM_DATAXSEEDLO( 0, 0, X24)
	// m[9]  = data[4:8]   ⊕ seed[0]_hi
	EMIT_M_FROM_DATAXSEEDHI( 4, 0, X25)
	// m[10] = data[8:12]  ⊕ seed[1]_lo
	EMIT_M_FROM_DATAXSEEDLO( 8, 1, X26)
	// m[11] = data[12] ⊕ seed[1]_hi  (one data byte)
	EMIT_M_FROM_DATABYTEXSEEDHI(12, 1, X27)
	// m[12] = seed[2]_lo  (data exhausted)
	EMIT_M_FROM_SEEDLO(2, X28)
	// m[13] = seed[2]_hi
	EMIT_M_FROM_SEEDHI(2, X29)
	// m[14] = seed[3]_lo
	EMIT_M_FROM_SEEDLO(3, X30)
	// m[15] = seed[3]_hi
	EMIT_M_FROM_SEEDHI(3, X31)

	// m[0..7] = b2key dwords, broadcast to all 4 lanes.
	VPBROADCASTD 0(BX),  X16
	VPBROADCASTD 4(BX),  X17
	VPBROADCASTD 8(BX),  X18
	VPBROADCASTD 12(BX), X19
	VPBROADCASTD 16(BX), X20
	VPBROADCASTD 20(BX), X21
	VPBROADCASTD 24(BX), X22
	VPBROADCASTD 28(BX), X23

	// ===== 10 mixing rounds (BLAKE2s uses sigma[0..9] only) =====
	BLAKE2S_ROUND(X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, X31)
	BLAKE2S_ROUND(X30, X26, X20, X24, X25, X31, X29, X22, X17, X28, X16, X18, X27, X23, X21, X19)
	BLAKE2S_ROUND(X27, X24, X28, X16, X21, X18, X31, X29, X26, X30, X19, X22, X23, X17, X25, X20)
	BLAKE2S_ROUND(X23, X25, X19, X17, X29, X28, X27, X30, X18, X22, X21, X26, X20, X16, X31, X24)
	BLAKE2S_ROUND(X25, X16, X21, X23, X18, X20, X26, X31, X30, X17, X27, X28, X22, X24, X19, X29)
	BLAKE2S_ROUND(X18, X28, X22, X26, X16, X27, X24, X19, X20, X29, X23, X21, X31, X30, X17, X25)
	BLAKE2S_ROUND(X28, X21, X17, X31, X30, X29, X20, X26, X16, X23, X22, X19, X25, X18, X24, X27)
	BLAKE2S_ROUND(X29, X27, X23, X30, X28, X17, X19, X25, X21, X16, X31, X20, X24, X22, X18, X26)
	BLAKE2S_ROUND(X22, X31, X30, X25, X27, X19, X16, X24, X28, X18, X29, X23, X17, X20, X26, X21)
	BLAKE2S_ROUND(X26, X18, X24, X20, X23, X22, X17, X21, X31, X27, X25, X30, X19, X28, X29, X16)

	// ===== Output XOR fold =====
	VPTERNLOGD.BCST $0x96, 0(AX),  X8,  X0
	VPTERNLOGD.BCST $0x96, 4(AX),  X9,  X1
	VPTERNLOGD.BCST $0x96, 8(AX),  X10, X2
	VPTERNLOGD.BCST $0x96, 12(AX), X11, X3
	VPTERNLOGD.BCST $0x96, 16(AX), X12, X4
	VPTERNLOGD.BCST $0x96, 20(AX), X13, X5
	VPTERNLOGD.BCST $0x96, 24(AX), X14, X6
	VPTERNLOGD.BCST $0x96, 28(AX), X15, X7

	// ===== Writeback =====
	MOVQ R15, R8
	LEAQ 32(R15),  R9
	LEAQ 64(R15),  R10
	LEAQ 96(R15),  R11

	STORE_LANE_DW(X0, 0)
	STORE_LANE_DW(X1, 4)
	STORE_LANE_DW(X2, 8)
	STORE_LANE_DW(X3, 12)
	STORE_LANE_DW(X4, 16)
	STORE_LANE_DW(X5, 20)
	STORE_LANE_DW(X6, 24)
	STORE_LANE_DW(X7, 28)

	VZEROUPPER
	RET
