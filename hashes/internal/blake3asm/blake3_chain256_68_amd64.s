//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for BLAKE3-256 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape). Two
// 64-byte BLAKE3 compression blocks per lane, with state-residency
// in ZMM registers between the two compressions:
//
//	Block 1 (block_len=64, flags=0x11 = KEYED_HASH | CHUNK_START):
//	    m[0..7]  = data[0:32] ⊕ seed
//	    m[8..15] = data[32:64]    (no seed XOR — past byte 32)
//	    Output cv1[k] = v[k] ⊕ v[k+8] (k in 0..7), in Z0..Z7 in-place.
//
//	Block 2 (block_len=4,  flags=0x1A = KEYED_HASH | CHUNK_END | ROOT):
//	    v[0..7] = cv1 (from block 1; chunk-internal blocks chain
//	                   their chaining value, NOT the original key).
//	    m[0]     = data[64:68]
//	    m[1..15] = 0
//	    Final out[k] = v[k] ⊕ v[k+8].
//
// Unlike the BLAKE2{b,s} two-block kernels, NO cv1 stack spill is
// required: BLAKE3's final fold is `v[k] ⊕ v[k+8]` alone (no ⊕ cv1
// term that would need cv1 reloaded after block-2 rounds mutate
// Z0..Z7). The stack frame is therefore $0-32 instead of $512-32.
//
//	blake3256ChainAbsorb68x4Asm(
//	    key      *[32]byte,
//	    seeds    *[4][4]uint64,
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥68 bytes
//	    out      *[4][8]uint32)

#include "textflag.h"

#define BLAKE3_G(a, b, c, d, mx, my) \
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

#define BLAKE3_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
	BLAKE3_G(Z0, Z4, Z8,  Z12, s0,  s1); \
	BLAKE3_G(Z1, Z5, Z9,  Z13, s2,  s3); \
	BLAKE3_G(Z2, Z6, Z10, Z14, s4,  s5); \
	BLAKE3_G(Z3, Z7, Z11, Z15, s6,  s7); \
	BLAKE3_G(Z0, Z5, Z10, Z15, s8,  s9); \
	BLAKE3_G(Z1, Z6, Z11, Z12, s10, s11); \
	BLAKE3_G(Z2, Z7, Z8,  Z13, s12, s13); \
	BLAKE3_G(Z3, Z4, Z9,  Z14, s14, s15)

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

// func blake3256ChainAbsorb68x4Asm(
//     key      *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint32)
TEXT ·blake3256ChainAbsorb68x4Asm(SB), NOSPLIT, $0-32
	MOVQ key+0(FP),       AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== Block 1 state init =====
	// v[0..7] = KEY broadcast (chunk-start: chaining value = key).
	VPBROADCASTD 0(AX),  Z0
	VPBROADCASTD 4(AX),  Z1
	VPBROADCASTD 8(AX),  Z2
	VPBROADCASTD 12(AX), Z3
	VPBROADCASTD 16(AX), Z4
	VPBROADCASTD 20(AX), Z5
	VPBROADCASTD 24(AX), Z6
	VPBROADCASTD 28(AX), Z7

	VPBROADCASTD ·Blake3IV+0(SB),  Z8
	VPBROADCASTD ·Blake3IV+4(SB),  Z9
	VPBROADCASTD ·Blake3IV+8(SB),  Z10
	VPBROADCASTD ·Blake3IV+12(SB), Z11

	// t_lo = 0, t_hi = 0 (single chunk, counter=0).
	VPXORD Z12, Z12, Z12
	VPXORD Z13, Z13, Z13

	// Block 1: block_len = 64, flags = KEYED_HASH | CHUNK_START = 0x11.
	MOVL $64, R12
	VPBROADCASTD R12, Z14
	MOVL $0x11, R12
	VPBROADCASTD R12, Z15

	// ===== Block 1 message-word build =====
	// m[0..7] = data[0:32] ⊕ seed.
	EMIT_M_FROM_DATAXSEEDLO( 0, 0, X16)  // m[0]
	EMIT_M_FROM_DATAXSEEDHI( 4, 0, X17)  // m[1]
	EMIT_M_FROM_DATAXSEEDLO( 8, 1, X18)  // m[2]
	EMIT_M_FROM_DATAXSEEDHI(12, 1, X19)  // m[3]
	EMIT_M_FROM_DATAXSEEDLO(16, 2, X20)  // m[4]
	EMIT_M_FROM_DATAXSEEDHI(20, 2, X21)  // m[5]
	EMIT_M_FROM_DATAXSEEDLO(24, 3, X22)  // m[6]
	EMIT_M_FROM_DATAXSEEDHI(28, 3, X23)  // m[7]
	// m[8..15] = data[32:64] (no seed XOR).
	EMIT_M_FROM_DATA(32, X24)            // m[ 8]
	EMIT_M_FROM_DATA(36, X25)            // m[ 9]
	EMIT_M_FROM_DATA(40, X26)            // m[10]
	EMIT_M_FROM_DATA(44, X27)            // m[11]
	EMIT_M_FROM_DATA(48, X28)            // m[12]
	EMIT_M_FROM_DATA(52, X29)            // m[13]
	EMIT_M_FROM_DATA(56, X30)            // m[14]
	EMIT_M_FROM_DATA(60, X31)            // m[15]

	// ===== Block 1: 7 mixing rounds =====
	BLAKE3_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE3_ROUND(Z18, Z22, Z19, Z26, Z23, Z16, Z20, Z29, Z17, Z27, Z28, Z21, Z25, Z30, Z31, Z24)
	BLAKE3_ROUND(Z19, Z20, Z26, Z28, Z29, Z18, Z23, Z30, Z22, Z21, Z25, Z16, Z27, Z31, Z24, Z17)
	BLAKE3_ROUND(Z26, Z23, Z28, Z25, Z30, Z19, Z29, Z31, Z20, Z16, Z27, Z18, Z21, Z24, Z17, Z22)
	BLAKE3_ROUND(Z28, Z29, Z25, Z27, Z31, Z26, Z30, Z24, Z23, Z18, Z21, Z19, Z16, Z17, Z22, Z20)
	BLAKE3_ROUND(Z25, Z30, Z27, Z21, Z24, Z28, Z31, Z17, Z29, Z19, Z16, Z26, Z18, Z22, Z20, Z23)
	BLAKE3_ROUND(Z27, Z31, Z21, Z16, Z17, Z25, Z24, Z22, Z30, Z26, Z18, Z28, Z19, Z20, Z23, Z29)

	// ===== Block 1 fold: cv1[k] = v[k] ⊕ v[k+8] in-place into Z0..Z7.
	// (BLAKE3 does NOT XOR with the input chaining value here —
	// that's the difference from BLAKE2 that lets us skip the cv1
	// stack spill. The chaining value for block 2's state init is
	// just the lower-half output of block 1's compression.)
	VPXORD Z8,  Z0, Z0
	VPXORD Z9,  Z1, Z1
	VPXORD Z10, Z2, Z2
	VPXORD Z11, Z3, Z3
	VPXORD Z12, Z4, Z4
	VPXORD Z13, Z5, Z5
	VPXORD Z14, Z6, Z6
	VPXORD Z15, Z7, Z7

	// ===== Block 2 state init =====
	// v[0..7] = cv1 (already in Z0..Z7).
	// v[8..11] = IV[0..3] (re-init).
	VPBROADCASTD ·Blake3IV+0(SB),  Z8
	VPBROADCASTD ·Blake3IV+4(SB),  Z9
	VPBROADCASTD ·Blake3IV+8(SB),  Z10
	VPBROADCASTD ·Blake3IV+12(SB), Z11

	// t_lo / t_hi unchanged at 0 (Z12 / Z13). But Z12 was rotated
	// through the mix above — re-zero it.
	VPXORD Z12, Z12, Z12
	VPXORD Z13, Z13, Z13

	// Block 2: block_len = 4, flags = KEYED_HASH | CHUNK_END | ROOT = 0x1A.
	MOVL $4, R12
	VPBROADCASTD R12, Z14
	MOVL $0x1A, R12
	VPBROADCASTD R12, Z15

	// ===== Block 2 message-word build =====
	// m[0] = data[64:68] (no seed XOR).
	EMIT_M_FROM_DATA(64, X16)
	// m[1..15] = 0.
	VPXORD Z17, Z17, Z17
	VPXORD Z18, Z18, Z18
	VPXORD Z19, Z19, Z19
	VPXORD Z20, Z20, Z20
	VPXORD Z21, Z21, Z21
	VPXORD Z22, Z22, Z22
	VPXORD Z23, Z23, Z23
	VPXORD Z24, Z24, Z24
	VPXORD Z25, Z25, Z25
	VPXORD Z26, Z26, Z26
	VPXORD Z27, Z27, Z27
	VPXORD Z28, Z28, Z28
	VPXORD Z29, Z29, Z29
	VPXORD Z30, Z30, Z30
	VPXORD Z31, Z31, Z31

	// ===== Block 2: 7 mixing rounds =====
	BLAKE3_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE3_ROUND(Z18, Z22, Z19, Z26, Z23, Z16, Z20, Z29, Z17, Z27, Z28, Z21, Z25, Z30, Z31, Z24)
	BLAKE3_ROUND(Z19, Z20, Z26, Z28, Z29, Z18, Z23, Z30, Z22, Z21, Z25, Z16, Z27, Z31, Z24, Z17)
	BLAKE3_ROUND(Z26, Z23, Z28, Z25, Z30, Z19, Z29, Z31, Z20, Z16, Z27, Z18, Z21, Z24, Z17, Z22)
	BLAKE3_ROUND(Z28, Z29, Z25, Z27, Z31, Z26, Z30, Z24, Z23, Z18, Z21, Z19, Z16, Z17, Z22, Z20)
	BLAKE3_ROUND(Z25, Z30, Z27, Z21, Z24, Z28, Z31, Z17, Z29, Z19, Z16, Z26, Z18, Z22, Z20, Z23)
	BLAKE3_ROUND(Z27, Z31, Z21, Z16, Z17, Z25, Z24, Z22, Z30, Z26, Z18, Z28, Z19, Z20, Z23, Z29)

	// ===== Block 2 final fold: out[k] = v[k] ⊕ v[k+8] =====
	VPXORD Z8,  Z0, Z0
	VPXORD Z9,  Z1, Z1
	VPXORD Z10, Z2, Z2
	VPXORD Z11, Z3, Z3
	VPXORD Z12, Z4, Z4
	VPXORD Z13, Z5, Z5
	VPXORD Z14, Z6, Z6
	VPXORD Z15, Z7, Z7

	// ===== Writeback =====
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
