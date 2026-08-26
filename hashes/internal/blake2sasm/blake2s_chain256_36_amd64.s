//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for BLAKE2s-256 with 36-byte
// per-lane data input (the ITB SetNonceBits(256) buf shape). Two
// 64-byte BLAKE2s compression blocks per lane, with state-residency
// in XMM registers between the two compressions (the 4 × 32-bit
// lane dwords fill one XMM register exactly).
//
// Per-lane absorb construction (matches the public hashes.BLAKE2s256
// closure bit-exactly):
//
//	Block 1 (t=64,  f=0):  buf[0:64]   = b2key + (data[0:32] ⊕ seed)
//	Block 2 (t=68,  f=^0): buf[64:128] = data[32:36] + 60 zero pad
//
// Unlike BLAKE2b at the 36-byte data shape (which is single-block
// since 32+36=68 ≤ 128 block size), BLAKE2s at 36 bytes spills past
// the 64-byte block size and requires a second compression. Four
// pixels processed lane-parallel: 16 XMM registers hold v[0..15]
// across both compressions; the post-block-1 chaining hash
// h_after_block1 is held in X0..X7 (= the v[0..7] init for block 2)
// and also saved to stack so the final block-2 fold can XOR it back.
//
// Register allocation: identical to the 20-byte kernel
// (blake2s_chain256_20_amd64.s); the m-register set X16..X31 is
// rebuilt per block.
//
// Stack frame: 128 bytes for h_after_block1 spill (8 XMMs × 16 bytes).

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

// EMIT_M_FROM_DATAXSEEDLO — load 32-bit data dword at offset, XOR
// with seeds[lane][seed_idx]_lo32. Per-lane seed stride 32 bytes.
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

// EMIT_M_FROM_DATA — load 32-bit data dword at offset (no seed XOR;
// used for block-2 m[0] = data[32:36] which is past the seed
// injection region). Note: BLAKE2s message words are u32, so no
// zero-extension to u64 is needed (compare BLAKE2b's
// EMIT_M_FROM_DATAEXT4 which built a u64 from 4 data bytes).
#define EMIT_M_FROM_DATA(data_off, x_dst) \
	MOVL data_off(R8),  R12; \
	MOVL data_off(R9),  R13; \
	MOVL data_off(R10), R14; \
	MOVL data_off(R11), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

// func blake2s256ChainAbsorb36x4Asm(
//     h0       *[8]uint32,        // Blake2sIV256Param (paramBlock 0x01010020)
//     b2key    *[32]byte,         // shared 32-byte fixed key
//     seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//     dataPtrs *[4]*byte,         // 4 pointers, each to ≥36 bytes
//     out      *[4][8]uint32)     // output: 32 bytes per lane
TEXT ·blake2s256ChainAbsorb36x4Asm(SB), NOSPLIT, $128-40
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

	// Block 1: t_lo = 64. f = 0 (NOT final).
	MOVL $64, R12
	VPBROADCASTD R12, X16
	VPXORD X16, X12, X12

	// ===== Block 1 message-word build =====
	// m[8..15] = (data[0:32] ⊕ seed[0..3]) split into 8 dwords.
	EMIT_M_FROM_DATAXSEEDLO( 0, 0, X24)  // m[ 8]
	EMIT_M_FROM_DATAXSEEDHI( 4, 0, X25)  // m[ 9]
	EMIT_M_FROM_DATAXSEEDLO( 8, 1, X26)  // m[10]
	EMIT_M_FROM_DATAXSEEDHI(12, 1, X27)  // m[11]
	EMIT_M_FROM_DATAXSEEDLO(16, 2, X28)  // m[12]
	EMIT_M_FROM_DATAXSEEDHI(20, 2, X29)  // m[13]
	EMIT_M_FROM_DATAXSEEDLO(24, 3, X30)  // m[14]
	EMIT_M_FROM_DATAXSEEDHI(28, 3, X31)  // m[15]

	// m[0..7] = b2key dwords, broadcast.
	VPBROADCASTD 0(BX),  X16
	VPBROADCASTD 4(BX),  X17
	VPBROADCASTD 8(BX),  X18
	VPBROADCASTD 12(BX), X19
	VPBROADCASTD 16(BX), X20
	VPBROADCASTD 20(BX), X21
	VPBROADCASTD 24(BX), X22
	VPBROADCASTD 28(BX), X23

	// ===== Block 1: 10 rounds =====
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

	// ===== Block 1 fold: h_after_block1[k] = h0[k] ⊕ v[k] ⊕ v[k+8]
	// Result lives in X0..X7 (= v[0..7] init for block 2).
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

	// Save h_after_block1 to stack so the final block-2 fold can XOR
	// it back in (X0..X7 will be mutated by the block-2 rounds).
	VMOVDQU64 X0, 0(SP)
	VMOVDQU64 X1, 16(SP)
	VMOVDQU64 X2, 32(SP)
	VMOVDQU64 X3, 48(SP)
	VMOVDQU64 X4, 64(SP)
	VMOVDQU64 X5, 80(SP)
	VMOVDQU64 X6, 96(SP)
	VMOVDQU64 X7, 112(SP)

	// ===== Block 2 state init =====
	// v[0..7] = h_after_block1 (already in X0..X7).
	// v[8..15] = IV broadcast (re-init X8..X15).
	VPBROADCASTD ·Blake2sIV+0(SB),  X8
	VPBROADCASTD ·Blake2sIV+4(SB),  X9
	VPBROADCASTD ·Blake2sIV+8(SB),  X10
	VPBROADCASTD ·Blake2sIV+12(SB), X11
	VPBROADCASTD ·Blake2sIV+16(SB), X12
	VPBROADCASTD ·Blake2sIV+20(SB), X13
	VPBROADCASTD ·Blake2sIV+24(SB), X14
	VPBROADCASTD ·Blake2sIV+28(SB), X15

	// Block 2: t_lo = 68 (= 64 + 4 trailing data bytes).
	MOVL $68, R12
	VPBROADCASTD R12, X16
	VPXORD X16, X12, X12

	// f = ^0 (final block).
	VPTERNLOGD $0xff, X16, X16, X16
	VPXORD X16, X14, X14

	// ===== Block 2 message-word build =====
	// m[0] = data[32:36] (no seed XOR; seed only covers buf[32:64]
	// which is entirely in block 1).
	EMIT_M_FROM_DATA(32, X16)
	// m[1..15] = 0 (zero pad in buf[68:128]).
	VPXORD X17, X17, X17
	VPXORD X18, X18, X18
	VPXORD X19, X19, X19
	VPXORD X20, X20, X20
	VPXORD X21, X21, X21
	VPXORD X22, X22, X22
	VPXORD X23, X23, X23
	VPXORD X24, X24, X24
	VPXORD X25, X25, X25
	VPXORD X26, X26, X26
	VPXORD X27, X27, X27
	VPXORD X28, X28, X28
	VPXORD X29, X29, X29
	VPXORD X30, X30, X30
	VPXORD X31, X31, X31

	// ===== Block 2: 10 rounds =====
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

	// ===== Block 2 final fold: out[k] = h_after_block1[k] ⊕ v[k] ⊕ v[k+8]
	// Single VPTERNLOGD per word with truth table 0x96 (three-way XOR);
	// h_after_block1 reloaded from stack via the full-width memory operand.
	VPTERNLOGD $0x96, 0(SP),   X8,  X0
	VPTERNLOGD $0x96, 16(SP),  X9,  X1
	VPTERNLOGD $0x96, 32(SP), X10, X2
	VPTERNLOGD $0x96, 48(SP), X11, X3
	VPTERNLOGD $0x96, 64(SP), X12, X4
	VPTERNLOGD $0x96, 80(SP), X13, X5
	VPTERNLOGD $0x96, 96(SP), X14, X6
	VPTERNLOGD $0x96, 112(SP), X15, X7

	// ===== Writeback to out[4][8]uint32 =====
	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11

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
