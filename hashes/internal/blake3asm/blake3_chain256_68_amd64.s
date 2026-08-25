//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for BLAKE3-256 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape). Two
// 64-byte BLAKE3 compression blocks per lane, with state-residency
// in XMM registers between the two compressions (the 4 × 32-bit
// lane dwords fill one XMM register exactly):
//
//	Block 1 (block_len=64, flags=0x11 = KEYED_HASH | CHUNK_START):
//	    m[0..7]  = data[0:32] ⊕ seed
//	    m[8..15] = data[32:64]    (no seed XOR — past byte 32)
//	    Output cv1[k] = v[k] ⊕ v[k+8] (k in 0..7), in X0..X7 in-place.
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
// X0..X7). The stack frame is therefore $0-32 instead of $512-32.
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
	BLAKE3_G(X0, X4, X8,  X12, s0,  s1); \
	BLAKE3_G(X1, X5, X9,  X13, s2,  s3); \
	BLAKE3_G(X2, X6, X10, X14, s4,  s5); \
	BLAKE3_G(X3, X7, X11, X15, s6,  s7); \
	BLAKE3_G(X0, X5, X10, X15, s8,  s9); \
	BLAKE3_G(X1, X6, X11, X12, s10, s11); \
	BLAKE3_G(X2, X7, X8,  X13, s12, s13); \
	BLAKE3_G(X3, X4, X9,  X14, s14, s15)

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

#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

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
	VPBROADCASTD 0(AX),  X0
	VPBROADCASTD 4(AX),  X1
	VPBROADCASTD 8(AX),  X2
	VPBROADCASTD 12(AX), X3
	VPBROADCASTD 16(AX), X4
	VPBROADCASTD 20(AX), X5
	VPBROADCASTD 24(AX), X6
	VPBROADCASTD 28(AX), X7

	VPBROADCASTD ·Blake3IV+0(SB),  X8
	VPBROADCASTD ·Blake3IV+4(SB),  X9
	VPBROADCASTD ·Blake3IV+8(SB),  X10
	VPBROADCASTD ·Blake3IV+12(SB), X11

	// t_lo = 0, t_hi = 0 (single chunk, counter=0).
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13

	// Block 1: block_len = 64, flags = KEYED_HASH | CHUNK_START = 0x11.
	MOVL $64, R12
	VPBROADCASTD R12, X14
	MOVL $0x11, R12
	VPBROADCASTD R12, X15

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
	BLAKE3_ROUND(X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, X31)
	BLAKE3_ROUND(X18, X22, X19, X26, X23, X16, X20, X29, X17, X27, X28, X21, X25, X30, X31, X24)
	BLAKE3_ROUND(X19, X20, X26, X28, X29, X18, X23, X30, X22, X21, X25, X16, X27, X31, X24, X17)
	BLAKE3_ROUND(X26, X23, X28, X25, X30, X19, X29, X31, X20, X16, X27, X18, X21, X24, X17, X22)
	BLAKE3_ROUND(X28, X29, X25, X27, X31, X26, X30, X24, X23, X18, X21, X19, X16, X17, X22, X20)
	BLAKE3_ROUND(X25, X30, X27, X21, X24, X28, X31, X17, X29, X19, X16, X26, X18, X22, X20, X23)
	BLAKE3_ROUND(X27, X31, X21, X16, X17, X25, X24, X22, X30, X26, X18, X28, X19, X20, X23, X29)

	// ===== Block 1 fold: cv1[k] = v[k] ⊕ v[k+8] in-place into X0..X7.
	// (BLAKE3 does NOT XOR with the input chaining value here —
	// that's the difference from BLAKE2 that lets us skip the cv1
	// stack spill. The chaining value for block 2's state init is
	// just the lower-half output of block 1's compression.)
	VPXORD X8,  X0, X0
	VPXORD X9,  X1, X1
	VPXORD X10, X2, X2
	VPXORD X11, X3, X3
	VPXORD X12, X4, X4
	VPXORD X13, X5, X5
	VPXORD X14, X6, X6
	VPXORD X15, X7, X7

	// ===== Block 2 state init =====
	// v[0..7] = cv1 (already in X0..X7).
	// v[8..11] = IV[0..3] (re-init).
	VPBROADCASTD ·Blake3IV+0(SB),  X8
	VPBROADCASTD ·Blake3IV+4(SB),  X9
	VPBROADCASTD ·Blake3IV+8(SB),  X10
	VPBROADCASTD ·Blake3IV+12(SB), X11

	// t_lo / t_hi unchanged at 0 (X12 / X13). But X12 was rotated
	// through the mix above — re-zero it.
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13

	// Block 2: block_len = 4, flags = KEYED_HASH | CHUNK_END | ROOT = 0x1A.
	MOVL $4, R12
	VPBROADCASTD R12, X14
	MOVL $0x1A, R12
	VPBROADCASTD R12, X15

	// ===== Block 2 message-word build =====
	// m[0] = data[64:68] (no seed XOR).
	EMIT_M_FROM_DATA(64, X16)
	// m[1..15] = 0.
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

	// ===== Block 2: 7 mixing rounds =====
	BLAKE3_ROUND(X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, X31)
	BLAKE3_ROUND(X18, X22, X19, X26, X23, X16, X20, X29, X17, X27, X28, X21, X25, X30, X31, X24)
	BLAKE3_ROUND(X19, X20, X26, X28, X29, X18, X23, X30, X22, X21, X25, X16, X27, X31, X24, X17)
	BLAKE3_ROUND(X26, X23, X28, X25, X30, X19, X29, X31, X20, X16, X27, X18, X21, X24, X17, X22)
	BLAKE3_ROUND(X28, X29, X25, X27, X31, X26, X30, X24, X23, X18, X21, X19, X16, X17, X22, X20)
	BLAKE3_ROUND(X25, X30, X27, X21, X24, X28, X31, X17, X29, X19, X16, X26, X18, X22, X20, X23)
	BLAKE3_ROUND(X27, X31, X21, X16, X17, X25, X24, X22, X30, X26, X18, X28, X19, X20, X23, X29)

	// ===== Block 2 final fold: out[k] = v[k] ⊕ v[k+8] =====
	VPXORD X8,  X0, X0
	VPXORD X9,  X1, X1
	VPXORD X10, X2, X2
	VPXORD X11, X3, X3
	VPXORD X12, X4, X4
	VPXORD X13, X5, X5
	VPXORD X14, X6, X6
	VPXORD X15, X7, X7

	// ===== Writeback =====
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
