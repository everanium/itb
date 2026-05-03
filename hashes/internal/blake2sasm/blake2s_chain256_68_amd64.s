//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for BLAKE2s-256 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape). Two
// 64-byte BLAKE2s compression blocks per lane, with state-residency
// in ZMM registers between the two compressions:
//
//	Block 1 (t=64,  f=0):  buf[0:64]   = b2key + (data[0:32] ⊕ seed)
//	Block 2 (t=100, f=^0): buf[64:128] = data[32:68] + 28 zero pad
//
// Same two-block structure as the 36-byte counterpart; the only
// differences are block 2's t value (100 vs 68) and the wider data
// fill in block 2 (data[32:68] = 36 bytes = 9 dwords m[0..8],
// vs 4 bytes = 1 dword m[0] in the 36-byte case).
//
//	blake2s256ChainAbsorb68x4Asm(
//	    h0       *[8]uint32,        // Blake2sIV256Param
//	    b2key    *[32]byte,         // shared 32-byte fixed key
//	    seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥68 bytes
//	    out      *[4][8]uint32)     // output: 32 bytes per lane
//
// Stack frame: 512 bytes for h_after_block1 spill (8 ZMMs × 64 bytes).

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
	BLAKE2S_G(Z0, Z4, Z8,  Z12, s0,  s1); \
	BLAKE2S_G(Z1, Z5, Z9,  Z13, s2,  s3); \
	BLAKE2S_G(Z2, Z6, Z10, Z14, s4,  s5); \
	BLAKE2S_G(Z3, Z7, Z11, Z15, s6,  s7); \
	BLAKE2S_G(Z0, Z5, Z10, Z15, s8,  s9); \
	BLAKE2S_G(Z1, Z6, Z11, Z12, s10, s11); \
	BLAKE2S_G(Z2, Z7, Z8,  Z13, s12, s13); \
	BLAKE2S_G(Z3, Z4, Z9,  Z14, s14, s15)

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

// EMIT_M_FROM_DATA — 32-bit data dword at offset, no seed XOR. Used
// for block-2 m[0..8] = data[32:68] (past seed-injection region).
#define EMIT_M_FROM_DATA(data_off, x_dst) \
	MOVL data_off(R8),  R12; \
	MOVL data_off(R9),  R13; \
	MOVL data_off(R10), R14; \
	MOVL data_off(R11), DI; \
	PACK_M_LANES(R12, R13, R14, DI, x_dst)

#define STORE_LANE_DW(z_src, off) \
	VEXTRACTI32X4 $0, z_src, X16; \
	VPEXTRD $0, X16, off(R8); \
	VPEXTRD $1, X16, off(R9); \
	VPEXTRD $2, X16, off(R10); \
	VPEXTRD $3, X16, off(R11)

// func blake2s256ChainAbsorb68x4Asm(
//     h0       *[8]uint32,
//     b2key    *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint32)
TEXT ·blake2s256ChainAbsorb68x4Asm(SB), NOSPLIT, $512-40
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
	VPBROADCASTD 0(AX),  Z0
	VPBROADCASTD 4(AX),  Z1
	VPBROADCASTD 8(AX),  Z2
	VPBROADCASTD 12(AX), Z3
	VPBROADCASTD 16(AX), Z4
	VPBROADCASTD 20(AX), Z5
	VPBROADCASTD 24(AX), Z6
	VPBROADCASTD 28(AX), Z7

	VPBROADCASTD ·Blake2sIV+0(SB),  Z8
	VPBROADCASTD ·Blake2sIV+4(SB),  Z9
	VPBROADCASTD ·Blake2sIV+8(SB),  Z10
	VPBROADCASTD ·Blake2sIV+12(SB), Z11
	VPBROADCASTD ·Blake2sIV+16(SB), Z12
	VPBROADCASTD ·Blake2sIV+20(SB), Z13
	VPBROADCASTD ·Blake2sIV+24(SB), Z14
	VPBROADCASTD ·Blake2sIV+28(SB), Z15

	// Block 1: t_lo = 64. f = 0.
	MOVL $64, R12
	VPBROADCASTD R12, Z16
	VPXORD Z16, Z12, Z12

	// ===== Block 1 message-word build (identical to 36-byte kernel) =====
	EMIT_M_FROM_DATAXSEEDLO( 0, 0, X24)  // m[ 8]
	EMIT_M_FROM_DATAXSEEDHI( 4, 0, X25)  // m[ 9]
	EMIT_M_FROM_DATAXSEEDLO( 8, 1, X26)  // m[10]
	EMIT_M_FROM_DATAXSEEDHI(12, 1, X27)  // m[11]
	EMIT_M_FROM_DATAXSEEDLO(16, 2, X28)  // m[12]
	EMIT_M_FROM_DATAXSEEDHI(20, 2, X29)  // m[13]
	EMIT_M_FROM_DATAXSEEDLO(24, 3, X30)  // m[14]
	EMIT_M_FROM_DATAXSEEDHI(28, 3, X31)  // m[15]

	VPBROADCASTD 0(BX),  Z16
	VPBROADCASTD 4(BX),  Z17
	VPBROADCASTD 8(BX),  Z18
	VPBROADCASTD 12(BX), Z19
	VPBROADCASTD 16(BX), Z20
	VPBROADCASTD 20(BX), Z21
	VPBROADCASTD 24(BX), Z22
	VPBROADCASTD 28(BX), Z23

	// ===== Block 1: 10 rounds =====
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

	// ===== Block 1 fold: h_after_block1[k] = h0[k] ⊕ v[k] ⊕ v[k+8]
	VPXORD Z8,  Z0, Z0
	VPXORD Z9,  Z1, Z1
	VPXORD Z10, Z2, Z2
	VPXORD Z11, Z3, Z3
	VPXORD Z12, Z4, Z4
	VPXORD Z13, Z5, Z5
	VPXORD Z14, Z6, Z6
	VPXORD Z15, Z7, Z7

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

	VMOVDQU64 Z0, 0(SP)
	VMOVDQU64 Z1, 64(SP)
	VMOVDQU64 Z2, 128(SP)
	VMOVDQU64 Z3, 192(SP)
	VMOVDQU64 Z4, 256(SP)
	VMOVDQU64 Z5, 320(SP)
	VMOVDQU64 Z6, 384(SP)
	VMOVDQU64 Z7, 448(SP)

	// ===== Block 2 state init =====
	VPBROADCASTD ·Blake2sIV+0(SB),  Z8
	VPBROADCASTD ·Blake2sIV+4(SB),  Z9
	VPBROADCASTD ·Blake2sIV+8(SB),  Z10
	VPBROADCASTD ·Blake2sIV+12(SB), Z11
	VPBROADCASTD ·Blake2sIV+16(SB), Z12
	VPBROADCASTD ·Blake2sIV+20(SB), Z13
	VPBROADCASTD ·Blake2sIV+24(SB), Z14
	VPBROADCASTD ·Blake2sIV+28(SB), Z15

	// Block 2: t_lo = 100 (= 64 + 36 trailing data bytes).
	MOVL $100, R12
	VPBROADCASTD R12, Z16
	VPXORD Z16, Z12, Z12

	// f = ^0 (final block).
	VPTERNLOGD $0xff, Z16, Z16, Z16
	VPXORD Z16, Z14, Z14

	// ===== Block 2 message-word build =====
	// m[0..8] = data[32:68] (36 bytes = 9 dwords). No seed XOR.
	EMIT_M_FROM_DATA(32, X16)  // m[0] = data[32:36]
	EMIT_M_FROM_DATA(36, X17)  // m[1] = data[36:40]
	EMIT_M_FROM_DATA(40, X18)  // m[2] = data[40:44]
	EMIT_M_FROM_DATA(44, X19)  // m[3] = data[44:48]
	EMIT_M_FROM_DATA(48, X20)  // m[4] = data[48:52]
	EMIT_M_FROM_DATA(52, X21)  // m[5] = data[52:56]
	EMIT_M_FROM_DATA(56, X22)  // m[6] = data[56:60]
	EMIT_M_FROM_DATA(60, X23)  // m[7] = data[60:64]
	EMIT_M_FROM_DATA(64, X24)  // m[8] = data[64:68]
	// m[9..15] = 0 (zero pad in buf[100:128]).
	VPXORD Z25, Z25, Z25
	VPXORD Z26, Z26, Z26
	VPXORD Z27, Z27, Z27
	VPXORD Z28, Z28, Z28
	VPXORD Z29, Z29, Z29
	VPXORD Z30, Z30, Z30
	VPXORD Z31, Z31, Z31

	// ===== Block 2: 10 rounds =====
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

	// ===== Block 2 final fold: out[k] = h_after_block1[k] ⊕ v[k] ⊕ v[k+8]
	VPXORD Z8,  Z0, Z0
	VPXORD Z9,  Z1, Z1
	VPXORD Z10, Z2, Z2
	VPXORD Z11, Z3, Z3
	VPXORD Z12, Z4, Z4
	VPXORD Z13, Z5, Z5
	VPXORD Z14, Z6, Z6
	VPXORD Z15, Z7, Z7

	VPXORD 0(SP),   Z0, Z0
	VPXORD 64(SP),  Z1, Z1
	VPXORD 128(SP), Z2, Z2
	VPXORD 192(SP), Z3, Z3
	VPXORD 256(SP), Z4, Z4
	VPXORD 320(SP), Z5, Z5
	VPXORD 384(SP), Z6, Z6
	VPXORD 448(SP), Z7, Z7

	// ===== Writeback to out[4][8]uint32 =====
	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11

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
