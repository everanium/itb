//go:build amd64 && !purego

// ZMM-batched fused chain-absorb kernel for BLAKE2s-256 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Lane-parallel layout across 4 pixels: 16 ZMM registers
// hold v[0..15] across all rounds, 16 more hold m[0..15]. No
// DIAG/UNDIAG permutations — column G uses Z[0,4,8,12], diagonal G
// uses Z[0,5,10,15]. BLAKE2s differs from BLAKE2b in word size
// (u32 vs u64), block size (64 vs 128), round count (10 vs 12), and
// G rotates (16, 12, 8, 7 vs 32, 24, 16, 63).
//
// Per-lane buffer construction (matches the public hashes.BLAKE2s256
// closure bit-exactly):
//
//	buf[0:32]   = b2key                (shared across all 4 lanes)
//	buf[32:52]  = data[lane]           (per-lane, 20 bytes)
//	buf[52:64]  = zero pad
//	then for i in 0..3:
//	  buf[32+i*8 : 40+i*8] ^= seeds[lane][i]   (LE uint64; straddles
//	                                             two BLAKE2s message
//	                                             words m[2i+8], m[2i+9])
//
// One BLAKE2s compression with t=64 (= 32 key + 32 max(data, 32)),
// f=^0 (final block). The 64-byte buf fits in exactly one BLAKE2s
// 64-byte block — no inter-block fold required (single-block kernel).
//
//	blake2s256ChainAbsorb20x4Asm(
//	    h0       *[8]uint32,        // Blake2sIV256Param (paramBlock 0x01010020)
//	    b2key    *[32]byte,         // shared 32-byte fixed key
//	    seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥20 bytes
//	    out      *[4][8]uint32)     // output: 32 bytes per lane

#include "textflag.h"

// BLAKE2S_G — full BLAKE2s G-function, lane-parallel on 4 pixels.
// Spec rotates: 16, 12, 8, 7. All in-place.
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
	BLAKE2S_G(Z0, Z4, Z8,  Z12, s0,  s1); \
	BLAKE2S_G(Z1, Z5, Z9,  Z13, s2,  s3); \
	BLAKE2S_G(Z2, Z6, Z10, Z14, s4,  s5); \
	BLAKE2S_G(Z3, Z7, Z11, Z15, s6,  s7); \
	BLAKE2S_G(Z0, Z5, Z10, Z15, s8,  s9); \
	BLAKE2S_G(Z1, Z6, Z11, Z12, s10, s11); \
	BLAKE2S_G(Z2, Z7, Z8,  Z13, s12, s13); \
	BLAKE2S_G(Z3, Z4, Z9,  Z14, s14, s15)

// PACK_M_LANES — pack 4 × 32-bit values (one per lane) into dwords
// 0..3 of x_dst. EVEX VMOVD zeros upper ZMM lanes automatically, so
// the resulting Z(x_dst) has dwords 0..3 = (l0, l1, l2, l3) and
// dwords 4..15 = 0. Unlike the BLAKE2b counterpart, no X16/X17
// scratch is required (4 dwords fit in a single XMM).
#define PACK_M_LANES(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

// EMIT_M_FROM_DATAXSEEDLO — load 32-bit data dword at offset, XOR
// with the LOW half of seeds[lane][seed_idx] (uint64 lo32). Per-lane
// stride 32 bytes for seeds *[4][4]uint64.
//
// MOVL into a 64-bit GPR zero-extends the upper 32 bits (x86-64
// rule); the subsequent VMOVD/VPINSRD reads only the low 32 bits.
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

// EMIT_M_FROM_DATAXSEEDHI — same as above but XORs with the HIGH
// half (uint64 hi32 at offset +4). Used for the odd-indexed message
// word (m[2*seed_idx + 9]) that pairs with seed_idx within a uint64.
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

// EMIT_M_FROM_SEEDLO — only seed_lo, no data (data exhausted in this
// dword position). Used for m[2*seed_idx + 8] when data ended before
// reaching this offset.
#define EMIT_M_FROM_SEEDLO(seed_idx, x_dst) \
	MOVL seed_idx*8 + 0*32 + 0(CX), R12; \
	MOVL seed_idx*8 + 1*32 + 0(CX), R13; \
	MOVL seed_idx*8 + 2*32 + 0(CX), R14; \
	MOVL seed_idx*8 + 3*32 + 0(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

// EMIT_M_FROM_SEEDHI — only seed_hi, no data.
#define EMIT_M_FROM_SEEDHI(seed_idx, x_dst) \
	MOVL seed_idx*8 + 0*32 + 4(CX), R12; \
	MOVL seed_idx*8 + 1*32 + 4(CX), R13; \
	MOVL seed_idx*8 + 2*32 + 4(CX), R14; \
	MOVL seed_idx*8 + 3*32 + 4(CX), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

// STORE_LANE_DW — extract one dword per lane from Z_src and store at
// out[lane]+off. Per-lane stride 32 bytes (out is *[4][8]uint32).
#define STORE_LANE_DW(z_src, off) \
	VEXTRACTI32X4 $0, z_src, X16; \
	VPEXTRD $0, X16, off(R8); \
	VPEXTRD $1, X16, off(R9); \
	VPEXTRD $2, X16, off(R10); \
	VPEXTRD $3, X16, off(R11)

// func blake2s256ChainAbsorb20x4Asm(...)
TEXT ·blake2s256ChainAbsorb20x4Asm(SB), NOSPLIT, $0-40
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
	// v[0..7] = h0 (paramBlock-XOR'd IV), broadcast to 4 dword lanes.
	VPBROADCASTD 0(AX),  Z0
	VPBROADCASTD 4(AX),  Z1
	VPBROADCASTD 8(AX),  Z2
	VPBROADCASTD 12(AX), Z3
	VPBROADCASTD 16(AX), Z4
	VPBROADCASTD 20(AX), Z5
	VPBROADCASTD 24(AX), Z6
	VPBROADCASTD 28(AX), Z7

	// v[8..15] = Blake2sIV
	VPBROADCASTD ·Blake2sIV+0(SB),  Z8
	VPBROADCASTD ·Blake2sIV+4(SB),  Z9
	VPBROADCASTD ·Blake2sIV+8(SB),  Z10
	VPBROADCASTD ·Blake2sIV+12(SB), Z11
	VPBROADCASTD ·Blake2sIV+16(SB), Z12
	VPBROADCASTD ·Blake2sIV+20(SB), Z13
	VPBROADCASTD ·Blake2sIV+24(SB), Z14
	VPBROADCASTD ·Blake2sIV+28(SB), Z15

	// t_lo = 64 (low 32 bits of the BLAKE2s 64-bit counter).
	MOVL $64, R12
	VPBROADCASTD R12, Z16
	VPXORD Z16, Z12, Z12
	// t_hi = 0 — Z13 unchanged.

	// f0 = ^0 (final block flag), into v[14]. f1 = 0 — Z15 unchanged.
	VPTERNLOGD $0xff, Z16, Z16, Z16
	VPXORD Z16, Z14, Z14

	// ===== Build message words m[0..15] =====
	// Per-lane m[8..15] FIRST (PACK_M_LANES writes only into x_dst,
	// no X16/X17 scratch involved — but the discipline of "pack
	// per-lane before key broadcast" is preserved verbatim from the
	// BLAKE2b counterpart for habit and safety).

	// m[8]  = data[0:4]   ⊕ seed[0]_lo
	EMIT_M_FROM_DATAXSEEDLO( 0, 0, X24)
	// m[9]  = data[4:8]   ⊕ seed[0]_hi
	EMIT_M_FROM_DATAXSEEDHI( 4, 0, X25)
	// m[10] = data[8:12]  ⊕ seed[1]_lo
	EMIT_M_FROM_DATAXSEEDLO( 8, 1, X26)
	// m[11] = data[12:16] ⊕ seed[1]_hi
	EMIT_M_FROM_DATAXSEEDHI(12, 1, X27)
	// m[12] = data[16:20] ⊕ seed[2]_lo  (last 4 bytes of data)
	EMIT_M_FROM_DATAXSEEDLO(16, 2, X28)
	// m[13] = seed[2]_hi  (data exhausted)
	EMIT_M_FROM_SEEDHI(2, X29)
	// m[14] = seed[3]_lo
	EMIT_M_FROM_SEEDLO(3, X30)
	// m[15] = seed[3]_hi
	EMIT_M_FROM_SEEDHI(3, X31)

	// m[0..7] = b2key dwords, broadcast to all 4 lanes.
	VPBROADCASTD 0(BX),  Z16
	VPBROADCASTD 4(BX),  Z17
	VPBROADCASTD 8(BX),  Z18
	VPBROADCASTD 12(BX), Z19
	VPBROADCASTD 16(BX), Z20
	VPBROADCASTD 20(BX), Z21
	VPBROADCASTD 24(BX), Z22
	VPBROADCASTD 28(BX), Z23

	// ===== 10 mixing rounds (BLAKE2s uses sigma[0..9] only) =====
	BLAKE2S_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE2S_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)
	BLAKE2S_ROUND(Z27, Z24, Z28, Z16, Z21, Z18, Z31, Z29, Z26, Z30, Z19, Z22, Z23, Z17, Z25, Z20)
	BLAKE2S_ROUND(Z23, Z25, Z19, Z17, Z29, Z28, Z27, Z30, Z18, Z22, Z21, Z26, Z20, Z16, Z31, Z24)
	BLAKE2S_ROUND(Z25, Z16, Z21, Z23, Z18, Z20, Z26, Z31, Z30, Z17, Z27, Z28, Z22, Z24, Z19, Z29)
	BLAKE2S_ROUND(Z18, Z28, Z22, Z26, Z16, Z27, Z24, Z19, Z20, Z29, Z23, Z21, Z31, Z30, Z17, Z25)
	BLAKE2S_ROUND(Z28, Z21, Z17, Z31, Z30, Z29, Z20, Z26, Z16, Z23, Z22, Z19, Z25, Z18, Z24, Z27)
	BLAKE2S_ROUND(Z29, Z27, Z23, Z30, Z28, Z17, Z19, Z25, Z21, Z16, Z31, Z20, Z24, Z22, Z18, Z26)
	BLAKE2S_ROUND(Z22, Z31, Z30, Z25, Z27, Z19, Z16, Z24, Z28, Z18, Z29, Z23, Z17, Z20, Z26, Z21)
	BLAKE2S_ROUND(Z26, Z18, Z24, Z20, Z23, Z22, Z17, Z21, Z31, Z27, Z25, Z30, Z19, Z28, Z29, Z16)

	// ===== Output XOR fold =====
	// out[k] = h0[k] ⊕ v[k] ⊕ v[k+8]  for k in 0..7.
	VPBROADCASTD 0(AX),  Z16
	VPXORD Z16, Z0, Z0
	VPBROADCASTD 4(AX),  Z16
	VPXORD Z16, Z1, Z1
	VPBROADCASTD 8(AX),  Z16
	VPXORD Z16, Z2, Z2
	VPBROADCASTD 12(AX), Z16
	VPXORD Z16, Z3, Z3
	VPBROADCASTD 16(AX), Z16
	VPXORD Z16, Z4, Z4
	VPBROADCASTD 20(AX), Z16
	VPXORD Z16, Z5, Z5
	VPBROADCASTD 24(AX), Z16
	VPXORD Z16, Z6, Z6
	VPBROADCASTD 28(AX), Z16
	VPXORD Z16, Z7, Z7

	VPXORD Z8,  Z0, Z0
	VPXORD Z9,  Z1, Z1
	VPXORD Z10, Z2, Z2
	VPXORD Z11, Z3, Z3
	VPXORD Z12, Z4, Z4
	VPXORD Z13, Z5, Z5
	VPXORD Z14, Z6, Z6
	VPXORD Z15, Z7, Z7

	// ===== Writeback =====
	// out is *[4][8]uint32 = 4 lanes × 32 bytes; per-lane stride 32 bytes.
	MOVQ R15, R8
	LEAQ 32(R15),  R9
	LEAQ 64(R15),  R10
	LEAQ 96(R15),  R11

	STORE_LANE_DW(Z0, 0)
	STORE_LANE_DW(Z1, 4)
	STORE_LANE_DW(Z2, 8)
	STORE_LANE_DW(Z3, 12)
	STORE_LANE_DW(Z4, 16)
	STORE_LANE_DW(Z5, 20)
	STORE_LANE_DW(Z6, 24)
	STORE_LANE_DW(Z7, 28)

	VZEROUPPER
	RET
