//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for BLAKE3-256 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Lane-parallel layout across 4 pixels, mirroring the
// blake2{b,s}asm ZMM scaffold.
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

#define STORE_LANE_DW(z_src, off) \
	VEXTRACTI32X4 $0, z_src, X16; \
	VPEXTRD $0, X16, off(R8); \
	VPEXTRD $1, X16, off(R9); \
	VPEXTRD $2, X16, off(R10); \
	VPEXTRD $3, X16, off(R11)

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
	VPBROADCASTD 0(AX),  Z0
	VPBROADCASTD 4(AX),  Z1
	VPBROADCASTD 8(AX),  Z2
	VPBROADCASTD 12(AX), Z3
	VPBROADCASTD 16(AX), Z4
	VPBROADCASTD 20(AX), Z5
	VPBROADCASTD 24(AX), Z6
	VPBROADCASTD 28(AX), Z7

	// v[8..11] = IV[0..3]
	VPBROADCASTD ·Blake3IV+0(SB),  Z8
	VPBROADCASTD ·Blake3IV+4(SB),  Z9
	VPBROADCASTD ·Blake3IV+8(SB),  Z10
	VPBROADCASTD ·Blake3IV+12(SB), Z11

	// v[12] = t_lo = 0, v[13] = t_hi = 0 (single chunk, counter=0).
	VPXORD Z12, Z12, Z12
	VPXORD Z13, Z13, Z13

	// v[14] = block_len = 32 (mixed buffer is zero-padded to 32 bytes).
	MOVL $32, R12
	VPBROADCASTD R12, Z14

	// v[15] = flags = KEYED_HASH | CHUNK_START | CHUNK_END | ROOT = 0x1B
	MOVL $0x1B, R12
	VPBROADCASTD R12, Z15

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
	VPXORD Z24, Z24, Z24
	VPXORD Z25, Z25, Z25
	VPXORD Z26, Z26, Z26
	VPXORD Z27, Z27, Z27
	VPXORD Z28, Z28, Z28
	VPXORD Z29, Z29, Z29
	VPXORD Z30, Z30, Z30
	VPXORD Z31, Z31, Z31

	// ===== 7 mixing rounds (BLAKE3 message schedule) =====
	BLAKE3_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	BLAKE3_ROUND(Z18, Z22, Z19, Z26, Z23, Z16, Z20, Z29, Z17, Z27, Z28, Z21, Z25, Z30, Z31, Z24)
	BLAKE3_ROUND(Z19, Z20, Z26, Z28, Z29, Z18, Z23, Z30, Z22, Z21, Z25, Z16, Z27, Z31, Z24, Z17)
	BLAKE3_ROUND(Z26, Z23, Z28, Z25, Z30, Z19, Z29, Z31, Z20, Z16, Z27, Z18, Z21, Z24, Z17, Z22)
	BLAKE3_ROUND(Z28, Z29, Z25, Z27, Z31, Z26, Z30, Z24, Z23, Z18, Z21, Z19, Z16, Z17, Z22, Z20)
	BLAKE3_ROUND(Z25, Z30, Z27, Z21, Z24, Z28, Z31, Z17, Z29, Z19, Z16, Z26, Z18, Z22, Z20, Z23)
	BLAKE3_ROUND(Z27, Z31, Z21, Z16, Z17, Z25, Z24, Z22, Z30, Z26, Z18, Z28, Z19, Z20, Z23, Z29)

	// ===== Output XOR fold =====
	// out[k] = v[k] ⊕ v[k+8]  for k in 0..7. Note: NO ⊕ KEY term
	// (BLAKE3 differs from BLAKE2 here — the chaining-value half
	// of the output emits chaining_value[k] ⊕ v[k+8], but that is
	// the upper 32 bytes of the 64-byte output. For root output
	// at 256-bit width, only the lower 32 bytes are returned.)
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
