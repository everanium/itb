//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for BLAKE2s-256 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Lane-parallel layout across 4 pixels: the 4 × 32-bit lane
// dwords fill one XMM register exactly, so 16 XMM registers hold
// v[0..15] across all rounds, 16 more hold m[0..15]. No DIAG/UNDIAG
// permutations — column G uses X[0,4,8,12], diagonal G
// uses X[0,5,10,15]. BLAKE2s differs from BLAKE2b in word size
// (u32 vs u64), block size (64 vs 128), round count (10 vs 12), and
// G rotates (16, 12, 8, 7 vs 32, 24, 16, 63).
//
// Per-lane absorb construction (matches the public hashes.BLAKE2s256
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
// Register allocation:
//
//	AX        h0 ptr       (Blake2sIV256Param)
//	BX        b2key ptr    (32-byte shared key)
//	CX        seeds ptr    (4 lanes × 4 uint64; per-lane stride 32 bytes)
//	DX        dataPtrs ptr (4 lane pointers)
//	R8..R11   per-lane data ptrs (loaded at entry)
//	R12..R14, DI    scratch GPRs for lane packing
//	R15       out ptr (saved through the round body, used at writeback)
//	X0..X15   BLAKE2s state v[0..15] across all 10 rounds
//	X16..X23  m[0..7]  (key dwords broadcast to all 4 lanes)
//	X24..X31  m[8..15] (per-lane data ⊕ seed / seed-only)

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
	BLAKE2S_G(X0, X4, X8,  X12, s0,  s1); \
	BLAKE2S_G(X1, X5, X9,  X13, s2,  s3); \
	BLAKE2S_G(X2, X6, X10, X14, s4,  s5); \
	BLAKE2S_G(X3, X7, X11, X15, s6,  s7); \
	BLAKE2S_G(X0, X5, X10, X15, s8,  s9); \
	BLAKE2S_G(X1, X6, X11, X12, s10, s11); \
	BLAKE2S_G(X2, X7, X8,  X13, s12, s13); \
	BLAKE2S_G(X3, X4, X9,  X14, s14, s15)

// PACK_M_LANES — pack 4 × 32-bit values (one per lane) into dwords
// 0..3 of x_dst, filling the XMM exactly. Unlike the BLAKE2b
// counterpart, no X16/X17 scratch is required (4 dwords fit in a
// single XMM).
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

// STORE_LANE_DW — extract one dword per lane from x_src and store at
// out[lane]+off. Per-lane stride 32 bytes (out is *[4][8]uint32).
// Direct VPEXTRD from the XMM state — no VEXTRACTI32X4 hop.
#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

// func blake2s256ChainAbsorb20x4Asm(
//     h0       *[8]uint32,        // Blake2sIV256Param (paramBlock 0x01010020)
//     b2key    *[32]byte,         // shared 32-byte fixed key
//     seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//     dataPtrs *[4]*byte,         // 4 pointers, each to ≥20 bytes
//     out      *[4][8]uint32)     // output: 32 bytes per lane
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
	VPBROADCASTD 0(AX),  X0
	VPBROADCASTD 4(AX),  X1
	VPBROADCASTD 8(AX),  X2
	VPBROADCASTD 12(AX), X3
	VPBROADCASTD 16(AX), X4
	VPBROADCASTD 20(AX), X5
	VPBROADCASTD 24(AX), X6
	VPBROADCASTD 28(AX), X7

	// v[8..15] = Blake2sIV
	VPBROADCASTD ·Blake2sIV+0(SB),  X8
	VPBROADCASTD ·Blake2sIV+4(SB),  X9
	VPBROADCASTD ·Blake2sIV+8(SB),  X10
	VPBROADCASTD ·Blake2sIV+12(SB), X11
	VPBROADCASTD ·Blake2sIV+16(SB), X12
	VPBROADCASTD ·Blake2sIV+20(SB), X13
	VPBROADCASTD ·Blake2sIV+24(SB), X14
	VPBROADCASTD ·Blake2sIV+28(SB), X15

	// t_lo = 64 (low 32 bits of the BLAKE2s 64-bit counter).
	MOVL $64, R12
	VPBROADCASTD R12, X16
	VPXORD X16, X12, X12
	// t_hi = 0 — X13 unchanged.

	// f0 = ^0 (final block flag), into v[14]. f1 = 0 — X15 unchanged.
	VPTERNLOGD $0xff, X16, X16, X16
	VPXORD X16, X14, X14

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
	// out[k] = h0[k] ⊕ v[k] ⊕ v[k+8]  for k in 0..7.
	// Single VPTERNLOGD per word with truth table 0x96 (three-way XOR),
	// h0[k] re-read from (AX) via the embedded-broadcast memory operand.
	VPTERNLOGD.BCST $0x96, 0(AX),  X8,  X0
	VPTERNLOGD.BCST $0x96, 4(AX),  X9,  X1
	VPTERNLOGD.BCST $0x96, 8(AX),  X10, X2
	VPTERNLOGD.BCST $0x96, 12(AX), X11, X3
	VPTERNLOGD.BCST $0x96, 16(AX), X12, X4
	VPTERNLOGD.BCST $0x96, 20(AX), X13, X5
	VPTERNLOGD.BCST $0x96, 24(AX), X14, X6
	VPTERNLOGD.BCST $0x96, 28(AX), X15, X7

	// ===== Writeback =====
	// out is *[4][8]uint32 = 4 lanes × 32 bytes; per-lane stride 32 bytes.
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
