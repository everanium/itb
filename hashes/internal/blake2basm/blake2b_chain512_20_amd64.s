//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for BLAKE2b-512 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Four pixels processed lane-parallel: 16 ZMM registers hold
// the four lane-isolated BLAKE2b states v[0..15] (qwords 0..3 used
// per ZMM, qwords 4..7 are padding garbage) across all 12 mixing
// rounds. The remaining 16 ZMMs hold m[0..15] across the four lanes
// in the same lane-parallel layout, fully eliminating per-round
// memory loads.
//
// Per-lane buffer construction (matches the public hashes.BLAKE2b512
// closure bit-exactly):
//
//	buf[0:64]   = b2key                (shared across all 4 lanes)
//	buf[64:84]  = data[lane]           (per-lane, 20 bytes)
//	buf[84:128] = zero pad
//	then for i in 0..7:
//	  buf[64+i*8 : 72+i*8] ^= seeds[lane][i]   (LE)
//
// Single 128-byte BLAKE2b compression with t=128, f=^0 (final block).
//
// Function signature (Go-side prototype in blake2basm_chain_amd64.go):
//
//	blake2b512ChainAbsorb20x4Asm(
//	    h0       *[8]uint64,        // param-XOR'd IV (broadcast to 4 lanes)
//	    b2key    *[64]byte,         // shared 64-byte fixed key
//	    seeds    *[4][8]uint64,     // per-lane 8 seed components
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥20 bytes
//	    out      *[4][8]uint64)     // output: 4 lanes × 8 uint64
//
// Register allocation:
//
//	Z0..Z7    state v[0..7]   (initialised from h0 broadcast, h0[0] carries paramBlock XOR)
//	Z8..Z15   state v[8..15]  (initialised from IV, then v[12] ^= t, v[14] ^= ^0)
//	Z16..Z23  m[0..7]         (key bytes 0..63 broadcast to all 4 lanes)
//	Z24..Z31  m[8..15]        (per-lane (data⊕seed) for k∈8..10, seed-only for k∈11..15)
//
//	AX        h0 ptr
//	BX        b2key ptr
//	CX        seeds ptr (base of [4][8]uint64; per-lane stride 64 bytes)
//	DX        dataPtrs ptr (base of [4]*byte)
//	R8..R11   per-lane data pointers (loaded once)
//	R12..R14  scratch GPRs
//	R15       out ptr (saved through the round body, used at writeback)

#include "textflag.h"

// BLAKE2B_G — full BLAKE2b G-function, lane-parallel on 4 pixels.
// All four argument ZMMs (a/b/c/d) are state v-registers; mx, my are
// the two message ZMMs picked by sigma for this G call.
//
// Spec body:
//   v[a] += v[b] + x
//   v[d] = ROR(v[d] ^ v[a], 32)
//   v[c] += v[d]
//   v[b] = ROR(v[b] ^ v[c], 24)
//   v[a] += v[b] + y
//   v[d] = ROR(v[d] ^ v[a], 16)
//   v[c] += v[d]
//   v[b] = ROR(v[b] ^ v[c], 63)
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

// BLAKE2B_ROUND — one full BLAKE2b mixing round (4 column G calls
// followed by 4 diagonal G calls). Message ZMM operands per call are
// chosen by the round's sigma permutation, which the caller
// pre-resolves at macro-expansion time as 16 specific Z16..Z31
// register names.
#define BLAKE2B_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
	BLAKE2B_G(Z0, Z4, Z8,  Z12, s0,  s1); \
	BLAKE2B_G(Z1, Z5, Z9,  Z13, s2,  s3); \
	BLAKE2B_G(Z2, Z6, Z10, Z14, s4,  s5); \
	BLAKE2B_G(Z3, Z7, Z11, Z15, s6,  s7); \
	BLAKE2B_G(Z0, Z5, Z10, Z15, s8,  s9); \
	BLAKE2B_G(Z1, Z6, Z11, Z12, s10, s11); \
	BLAKE2B_G(Z2, Z7, Z8,  Z13, s12, s13); \
	BLAKE2B_G(Z3, Z4, Z9,  Z14, s14, s15)

// PACK_M_LANES_FROM_GPRS — assemble one lane-parallel ZMM message
// register from four scalar uint64 values held in GPRs.
//
//   Step 1: scratch X16 ← (l0 in qword 0, l1 in qword 1)
//   Step 2: scratch X17 ← (l2 in qword 0, l3 in qword 1)
//   Step 3: target ZMM Y_dst ← (X16 in lanes 0..1, X17 in lanes 2..3)
//
// Y_dst written via 256-bit operation zeros the upper ZMM half.
// Lanes 4..7 of the resulting Z_dst carry zero — irrelevant since
// the v-state ZMMs also have zero lanes 4..7 at init and the round
// arithmetic keeps the lanes independent.
#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, y_dst) \
	VMOVQ l0, X16; \
	VPINSRQ $1, l1, X16, X16; \
	VMOVQ l2, X17; \
	VPINSRQ $1, l3, X17, X17; \
	VINSERTI64X2 $1, X17, Y16, y_dst

// EMIT_M_FROM_DATAXSEED — load data uint64 at offset (data_off) for
// each lane, XOR with seeds[lane][seed_idx] (offset = seed_idx*8 in
// per-lane stride 64), and pack into target message ZMM Z_dst.
//
// Assumes: R8..R11 = data ptrs lane 0..3, CX = seeds base (per-lane
// stride 64 bytes; seed[lane][k] at off = lane*64 + k*8).
#define EMIT_M_FROM_DATAXSEED(data_off, seed_idx, y_dst) \
	MOVQ data_off(R8),  R12; \
	XORQ seed_idx*8 + 0*64(CX), R12; \
	MOVQ data_off(R9),  R13; \
	XORQ seed_idx*8 + 1*64(CX), R13; \
	MOVQ data_off(R10), R14; \
	XORQ seed_idx*8 + 2*64(CX), R14; \
	MOVQ data_off(R11), DI; \
	XORQ seed_idx*8 + 3*64(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

// EMIT_M_FROM_DATAEXT4XSEED — load data 32-bit fragment at offset
// (data_off) for each lane (zero-extended to 64 bits), XOR with
// seeds[lane][seed_idx], and pack into target message ZMM. Used for
// m[10] which carries (data[16:20] || zero[0:4]) ⊕ seed[2].
#define EMIT_M_FROM_DATAEXT4XSEED(data_off, seed_idx, y_dst) \
	MOVL data_off(R8),  R12; \
	XORQ seed_idx*8 + 0*64(CX), R12; \
	MOVL data_off(R9),  R13; \
	XORQ seed_idx*8 + 1*64(CX), R13; \
	MOVL data_off(R10), R14; \
	XORQ seed_idx*8 + 2*64(CX), R14; \
	MOVL data_off(R11), DI; \
	XORQ seed_idx*8 + 3*64(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

// EMIT_M_FROM_SEED — pack four lanes' seeds[lane][seed_idx] (no data
// XOR) into target message ZMM. Used for m[11..15] in the 20-byte
// shape since those positions contain only seed bytes (data is
// shorter than 64-byte payload region).
#define EMIT_M_FROM_SEED(seed_idx, y_dst) \
	MOVQ seed_idx*8 + 0*64(CX), R12; \
	MOVQ seed_idx*8 + 1*64(CX), R13; \
	MOVQ seed_idx*8 + 2*64(CX), R14; \
	MOVQ seed_idx*8 + 3*64(CX), DI; \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, y_dst)

// STORE_LANE_QW — for state ZMM Z_src holding (l0, l1, l2, l3, _, _, _, _),
// write each lane's qword to out[lane][off]. Uses VEXTRACTI64X2 to
// split the lower 256 bits of Z_src into (X_tmp pair holding l0+l1,
// l2+l3) and VPEXTRQ to memory for direct 8-byte stores.
//
// out[lane] base addresses are pre-loaded into R8/R9/R10/R11 at the
// writeback stage (the data pointers from packing are no longer
// needed by then). Macro takes the offset within each lane's 64-byte
// output region.
#define STORE_LANE_QW(z_src, off) \
	VEXTRACTI64X2 $0, z_src, X16; \
	VPEXTRQ $0, X16, off(R8); \
	VPEXTRQ $1, X16, off(R9); \
	VEXTRACTI64X2 $1, z_src, X17; \
	VPEXTRQ $0, X17, off(R10); \
	VPEXTRQ $1, X17, off(R11)

// func blake2b512ChainAbsorb20x4Asm(
//     h0       *[8]uint64,
//     b2key    *[64]byte,
//     seeds    *[4][8]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][8]uint64)
TEXT ·blake2b512ChainAbsorb20x4Asm(SB), NOSPLIT, $0-40
	MOVQ h0+0(FP),       AX
	MOVQ b2key+8(FP),    BX
	MOVQ seeds+16(FP),   CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP),     R15

	// Load four data pointers into R8..R11. dataPtrs is *[4]*byte,
	// so each element is an 8-byte pointer.
	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== State init =====
	// v[0..7] = h0 broadcast across 4 lanes. h0[0] already carries
	// the param-block XOR (paramBlock 0x01010040 for digest length 64,
	// fanout 1, depth 1) since the caller passes &Blake2bIV512Param.
	VPBROADCASTQ 0(AX),  Z0
	VPBROADCASTQ 8(AX),  Z1
	VPBROADCASTQ 16(AX), Z2
	VPBROADCASTQ 24(AX), Z3
	VPBROADCASTQ 32(AX), Z4
	VPBROADCASTQ 40(AX), Z5
	VPBROADCASTQ 48(AX), Z6
	VPBROADCASTQ 56(AX), Z7

	// v[8..15] = IV[0..7] broadcast. IV is RFC 7693 §3.2 fixed.
	VPBROADCASTQ ·Blake2bIV+0(SB),  Z8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Z9
	VPBROADCASTQ ·Blake2bIV+16(SB), Z10
	VPBROADCASTQ ·Blake2bIV+24(SB), Z11
	VPBROADCASTQ ·Blake2bIV+32(SB), Z12
	VPBROADCASTQ ·Blake2bIV+40(SB), Z13
	VPBROADCASTQ ·Blake2bIV+48(SB), Z14
	VPBROADCASTQ ·Blake2bIV+56(SB), Z15

	// v[12] ^= t = 128 (the byte count fed into this single
	// compression — the per-lane buf is exactly 128 bytes).
	MOVQ $128, R12
	VPBROADCASTQ R12, Z16
	VPXORQ Z16, Z12, Z12

	// v[14] ^= 0xFFFF...FF (final-block flag). Build all-ones via
	// VPTERNLOGQ with truth-table 0xFF (constant-true) — produces
	// all-ones regardless of input operands.
	VPTERNLOGQ $0xff, Z16, Z16, Z16
	VPXORQ Z16, Z14, Z14

	// ===== Build message words m[0..15] =====
	// Order matters: pack m[8..15] FIRST since the per-lane assembly
	// macros use X16/X17 as scratch for VMOVQ + VPINSRQ + VINSERTI64X2.
	// EVEX/VEX writes to XMM zero the upper ZMM lanes, so writing X16
	// would clobber Z16. Doing m[8..15] before m[0..7] broadcast leaves
	// Z16..Z23 clean for the subsequent VPBROADCASTQ.

	// m[8] = (data[lane][0:8]) ⊕ seeds[lane][0]
	EMIT_M_FROM_DATAXSEED(0, 0, Y24)
	// m[9] = (data[lane][8:16]) ⊕ seeds[lane][1]
	EMIT_M_FROM_DATAXSEED(8, 1, Y25)
	// m[10] = (data[lane][16:20] || zero[0:4]) ⊕ seeds[lane][2]
	EMIT_M_FROM_DATAEXT4XSEED(16, 2, Y26)
	// m[11..15] = seeds[lane][3..7] (data region exhausted at byte 84;
	// buf[88..128] = pure zero ⊕ seed = seed)
	EMIT_M_FROM_SEED(3, Y27)
	EMIT_M_FROM_SEED(4, Y28)
	EMIT_M_FROM_SEED(5, Y29)
	EMIT_M_FROM_SEED(6, Y30)
	EMIT_M_FROM_SEED(7, Y31)

	// m[0..7] from b2key — same value for all 4 lanes (key prefix).
	VPBROADCASTQ 0(BX),  Z16
	VPBROADCASTQ 8(BX),  Z17
	VPBROADCASTQ 16(BX), Z18
	VPBROADCASTQ 24(BX), Z19
	VPBROADCASTQ 32(BX), Z20
	VPBROADCASTQ 40(BX), Z21
	VPBROADCASTQ 48(BX), Z22
	VPBROADCASTQ 56(BX), Z23

	// ===== 12 mixing rounds (sigma-permuted message indices) =====
	// Each line below selects the 16 message ZMM operands for that
	// round per RFC 7693 §3.1; each invocation expands to 8 G-function
	// calls (4 column + 4 diagonal).
	//
	// sigma[0]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15}
	BLAKE2B_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	// sigma[1]  = {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
	BLAKE2B_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)
	// sigma[2]  = {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4}
	BLAKE2B_ROUND(Z27, Z24, Z28, Z16, Z21, Z18, Z31, Z29, Z26, Z30, Z19, Z22, Z23, Z17, Z25, Z20)
	// sigma[3]  = { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8}
	BLAKE2B_ROUND(Z23, Z25, Z19, Z17, Z29, Z28, Z27, Z30, Z18, Z22, Z21, Z26, Z20, Z16, Z31, Z24)
	// sigma[4]  = { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13}
	BLAKE2B_ROUND(Z25, Z16, Z21, Z23, Z18, Z20, Z26, Z31, Z30, Z17, Z27, Z28, Z22, Z24, Z19, Z29)
	// sigma[5]  = { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9}
	BLAKE2B_ROUND(Z18, Z28, Z22, Z26, Z16, Z27, Z24, Z19, Z20, Z29, Z23, Z21, Z31, Z30, Z17, Z25)
	// sigma[6]  = {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11}
	BLAKE2B_ROUND(Z28, Z21, Z17, Z31, Z30, Z29, Z20, Z26, Z16, Z23, Z22, Z19, Z25, Z18, Z24, Z27)
	// sigma[7]  = {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10}
	BLAKE2B_ROUND(Z29, Z27, Z23, Z30, Z28, Z17, Z19, Z25, Z21, Z16, Z31, Z20, Z24, Z22, Z18, Z26)
	// sigma[8]  = { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5}
	BLAKE2B_ROUND(Z22, Z31, Z30, Z25, Z27, Z19, Z16, Z24, Z28, Z18, Z29, Z23, Z17, Z20, Z26, Z21)
	// sigma[9]  = {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}
	BLAKE2B_ROUND(Z26, Z18, Z24, Z20, Z23, Z22, Z17, Z21, Z31, Z27, Z25, Z30, Z19, Z28, Z29, Z16)
	// sigma[10] = sigma[0]
	BLAKE2B_ROUND(Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31)
	// sigma[11] = sigma[1]
	BLAKE2B_ROUND(Z30, Z26, Z20, Z24, Z25, Z31, Z29, Z22, Z17, Z28, Z16, Z18, Z27, Z23, Z21, Z19)

	// ===== Output XOR fold: out[lane][k] = h0_initial[k] ⊕ v[k] ⊕ v[k+8] =====
	//
	// BLAKE2b spec final state update is:
	//   h_new[k] = h_old[k] ⊕ v[k] ⊕ v[k+8]  for k in 0..7
	//
	// The original h_old is what was loaded from h0 before round 1. We
	// reload that via VPBROADCASTQ from (AX) and XOR into Z0..Z7,
	// which currently hold v[0..7]. Then XOR Z0..Z7 with Z8..Z15
	// (= v[8..15]) — the result in Z0..Z7 is h_new[0..7], the kernel
	// output per BLAKE2b spec.
	VPBROADCASTQ 0(AX),  Z16
	VPXORQ Z16, Z0, Z0
	VPBROADCASTQ 8(AX),  Z16
	VPXORQ Z16, Z1, Z1
	VPBROADCASTQ 16(AX), Z16
	VPXORQ Z16, Z2, Z2
	VPBROADCASTQ 24(AX), Z16
	VPXORQ Z16, Z3, Z3
	VPBROADCASTQ 32(AX), Z16
	VPXORQ Z16, Z4, Z4
	VPBROADCASTQ 40(AX), Z16
	VPXORQ Z16, Z5, Z5
	VPBROADCASTQ 48(AX), Z16
	VPXORQ Z16, Z6, Z6
	VPBROADCASTQ 56(AX), Z16
	VPXORQ Z16, Z7, Z7

	VPXORQ Z8,  Z0, Z0
	VPXORQ Z9,  Z1, Z1
	VPXORQ Z10, Z2, Z2
	VPXORQ Z11, Z3, Z3
	VPXORQ Z12, Z4, Z4
	VPXORQ Z13, Z5, Z5
	VPXORQ Z14, Z6, Z6
	VPXORQ Z15, Z7, Z7

	// ===== Writeback to out[4][8]uint64 =====
	// Compute per-lane output base addresses. Each lane occupies 64
	// bytes (8 × uint64) in out, so out[lane] = out_base + lane*64.
	// R15 was loaded with out_base; pre-compute lanes 1..3 bases into
	// R8..R11. (R8..R11 are now free since data pointers have been
	// fully consumed in the packing stage.)
	MOVQ R15, R8
	LEAQ 64(R15), R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11

	// For each k in 0..7, extract 4 lane qwords from Z_k and store
	// to out[lane][k*8].
	STORE_LANE_QW(Z0, 0)
	STORE_LANE_QW(Z1, 8)
	STORE_LANE_QW(Z2, 16)
	STORE_LANE_QW(Z3, 24)
	STORE_LANE_QW(Z4, 32)
	STORE_LANE_QW(Z5, 40)
	STORE_LANE_QW(Z6, 48)
	STORE_LANE_QW(Z7, 56)

	VZEROUPPER
	RET
