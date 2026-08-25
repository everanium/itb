//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for BLAKE3-256 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Lane-parallel layout across 4 pixels: the 4 × 32-bit lane
// dwords fill one XMM register exactly, mirroring the blake2sasm
// XMM scaffold.
//
// Per-lane mixed buffer construction (matches the public hashes.BLAKE3
// closure bit-exactly):
//
//	mixed[0:20]  = data[lane]                 (per-lane, 20 bytes)
//	mixed[20:32] = zero pad
//	then for i in 0..3:
//	  mixed[i*8 : i*8+8] ^= seeds[lane][i]    (LE uint64; straddles
//	                                            two BLAKE3 message
//	                                            words m[2i], m[2i+1])
//
// The 32-byte keyed-hash key (shared across all 4 lanes) goes into
// the BLAKE3 state init as v[0..7] — NOT into the mixed buffer
// (different from BLAKE2{b,s} where the key was a literal payload
// prefix). One BLAKE3 compression with block_len=32, flags=0x1B
// (KEYED_HASH | CHUNK_START | CHUNK_END | ROOT). Single-block kernel
// since mixed (32 bytes) fits in a single 64-byte BLAKE3 block.
//
//	blake3256ChainAbsorb20x4Asm(
//	    key      *[32]byte,         // shared 32-byte BLAKE3 key
//	    seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥20 bytes
//	    out      *[4][8]uint32)     // output: 32 bytes per lane

#include "textflag.h"

// BLAKE3_G — full BLAKE3 G-function, lane-parallel on 4 pixels.
// Same shape as BLAKE2S_G — rotates 16, 12, 8, 7. All in-place.
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

// func blake3256ChainAbsorb20x4Asm(
//     key      *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint32)
TEXT ·blake3256ChainAbsorb20x4Asm(SB), NOSPLIT, $0-32
	MOVQ key+0(FP),       AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== State init =====
	// v[0..7] = KEY broadcast (8 × u32 = 32 bytes)
	VPBROADCASTD 0(AX),  X0
	VPBROADCASTD 4(AX),  X1
	VPBROADCASTD 8(AX),  X2
	VPBROADCASTD 12(AX), X3
	VPBROADCASTD 16(AX), X4
	VPBROADCASTD 20(AX), X5
	VPBROADCASTD 24(AX), X6
	VPBROADCASTD 28(AX), X7

	// v[8..11] = IV[0..3]
	VPBROADCASTD ·Blake3IV+0(SB),  X8
	VPBROADCASTD ·Blake3IV+4(SB),  X9
	VPBROADCASTD ·Blake3IV+8(SB),  X10
	VPBROADCASTD ·Blake3IV+12(SB), X11

	// v[12] = t_lo = 0, v[13] = t_hi = 0 (single chunk, counter=0).
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13

	// v[14] = block_len = 32 (mixed buffer is zero-padded to 32 bytes).
	MOVL $32, R12
	VPBROADCASTD R12, X14

	// v[15] = flags = KEYED_HASH | CHUNK_START | CHUNK_END | ROOT = 0x1B
	MOVL $0x1B, R12
	VPBROADCASTD R12, X15

	// ===== Build message words m[0..15] =====
	// m[0..4]: data-derived dwords with seed XOR. m[5..7]: seed-only
	// (data exhausted at byte 20 = m[4] high half). m[8..15]: zeros.
	EMIT_M_FROM_DATAXSEEDLO( 0, 0, X16)  // m[0] = data[ 0: 4] ⊕ seed[0]_lo
	EMIT_M_FROM_DATAXSEEDHI( 4, 0, X17)  // m[1] = data[ 4: 8] ⊕ seed[0]_hi
	EMIT_M_FROM_DATAXSEEDLO( 8, 1, X18)  // m[2] = data[ 8:12] ⊕ seed[1]_lo
	EMIT_M_FROM_DATAXSEEDHI(12, 1, X19)  // m[3] = data[12:16] ⊕ seed[1]_hi
	EMIT_M_FROM_DATAXSEEDLO(16, 2, X20)  // m[4] = data[16:20] ⊕ seed[2]_lo
	EMIT_M_FROM_SEEDHI(2, X21)            // m[5] = seed[2]_hi
	EMIT_M_FROM_SEEDLO(3, X22)            // m[6] = seed[3]_lo
	EMIT_M_FROM_SEEDHI(3, X23)            // m[7] = seed[3]_hi

	// m[8..15] = 0 (mixed buffer ends at byte 32; positions 8..15 are
	// past the buffer end and contribute zero to the compression).
	VPXORD X24, X24, X24
	VPXORD X25, X25, X25
	VPXORD X26, X26, X26
	VPXORD X27, X27, X27
	VPXORD X28, X28, X28
	VPXORD X29, X29, X29
	VPXORD X30, X30, X30
	VPXORD X31, X31, X31

	// ===== 7 mixing rounds (BLAKE3 message schedule) =====
	BLAKE3_ROUND(X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, X31)
	BLAKE3_ROUND(X18, X22, X19, X26, X23, X16, X20, X29, X17, X27, X28, X21, X25, X30, X31, X24)
	BLAKE3_ROUND(X19, X20, X26, X28, X29, X18, X23, X30, X22, X21, X25, X16, X27, X31, X24, X17)
	BLAKE3_ROUND(X26, X23, X28, X25, X30, X19, X29, X31, X20, X16, X27, X18, X21, X24, X17, X22)
	BLAKE3_ROUND(X28, X29, X25, X27, X31, X26, X30, X24, X23, X18, X21, X19, X16, X17, X22, X20)
	BLAKE3_ROUND(X25, X30, X27, X21, X24, X28, X31, X17, X29, X19, X16, X26, X18, X22, X20, X23)
	BLAKE3_ROUND(X27, X31, X21, X16, X17, X25, X24, X22, X30, X26, X18, X28, X19, X20, X23, X29)

	// ===== Output XOR fold =====
	// out[k] = v[k] ⊕ v[k+8]  for k in 0..7. Note: NO ⊕ KEY term
	// (BLAKE3 differs from BLAKE2 here — the chaining-value half
	// of the output emits chaining_value[k] ⊕ v[k+8], but that is
	// the upper 32 bytes of the 64-byte output. For root output
	// at 256-bit width, only the lower 32 bytes are returned.)
	VPXORD X8,  X0, X0
	VPXORD X9,  X1, X1
	VPXORD X10, X2, X2
	VPXORD X11, X3, X3
	VPXORD X12, X4, X4
	VPXORD X13, X5, X5
	VPXORD X14, X6, X6
	VPXORD X15, X7, X7

	// ===== Writeback =====
	// out is *[4][8]uint32 = 4 lanes × 32 bytes; per-lane stride 32 bytes.
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
