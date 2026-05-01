//go:build amd64 && !purego

// ZMM-batched fused chain-absorb kernel for ChaCha20-256 with 68-byte
// per-lane data input (the ITB SetNonceBits(512) buf shape). Two
// ChaCha20 compressions (counter=0 then counter=1) per kernel call;
// three XKS calls — first two consume halves of compression block 0
// (ks_lo, then ks_hi), the third consumes ks_lo of compression block
// 1.
//
// Per-lane absorb construction (matches the public hashes.ChaCha20
// closure bit-exactly):
//
//	state[0:8]  = uint64(68) (LE)
//	state[8:32] = data[lane][0:24]
//	XKS call 1: state[i] ^= ks_lo_dword[i] (block 0)  for i in 0..7
//	state[8:32] ^= data[lane][24:48]            (6 dwords absorbXOR)
//	XKS call 2: state[i] ^= ks_hi_dword[i] (block 0)  for i in 0..7
//	state[8:28] ^= data[lane][48:68]            (5 dwords absorbXOR)
//	XKS call 3: state[i] ^= ks_lo_dword[i] (block 1)  for i in 0..7
//	output:    state[0:32] (4 × LE uint64)
//
// Register allocation (kept consistent across both compressions):
//
//	Z0..Z15   ChaCha20 state during rounds (compression 1, then
//	          re-init for compression 2)
//	Z16..Z23  absorb_state (built after compression 1, preserved
//	          across compression 2's round body)
//	Z24..Z31  per-lane key save — populated before compression 1,
//	          consumed in both compressions' keystream `+ v_init`
//	          add phases. After the second compression's add, Z24
//	          is reused as broadcast scratch for sigma / counter
//	          adds (the 8 key adds happen first, freeing Z24..Z31
//	          for scratch use thereafter).
//
//	chaCha20256ChainAbsorb68x4Asm(
//	    fixedKey *[32]byte,
//	    seeds    *[4][4]uint64,
//	    dataPtrs *[4]*byte,
//	    out      *[4][4]uint64)

#include "textflag.h"

#define CHACHA_QR(a, b, c, d) \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $16, d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $12, b, b; \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $8,  d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $7,  b, b

#define CHACHA_DR \
	CHACHA_QR(Z0, Z4, Z8,  Z12); \
	CHACHA_QR(Z1, Z5, Z9,  Z13); \
	CHACHA_QR(Z2, Z6, Z10, Z14); \
	CHACHA_QR(Z3, Z7, Z11, Z15); \
	CHACHA_QR(Z0, Z5, Z10, Z15); \
	CHACHA_QR(Z1, Z6, Z11, Z12); \
	CHACHA_QR(Z2, Z7, Z8,  Z13); \
	CHACHA_QR(Z3, Z4, Z9,  Z14)

#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

#define PACK_KEY_DWORD(k, x_dst) \
	MOVL k*4(AX),         R12; XORL k*4 + 0*32(CX), R12; \
	MOVL k*4(AX),         R13; XORL k*4 + 1*32(CX), R13; \
	MOVL k*4(AX),         R14; XORL k*4 + 2*32(CX), R14; \
	MOVL k*4(AX),         DI;  XORL k*4 + 3*32(CX), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst)

#define PACK_DATA_DWORD(off, x_dst) \
	MOVL off(R8),  R12; \
	MOVL off(R9),  R13; \
	MOVL off(R10), R14; \
	MOVL off(R11), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst)

#define STORE_LANE_DW(z_src, off) \
	VEXTRACTI32X4 $0, z_src, X16; \
	VPEXTRD $0, X16, off(R8); \
	VPEXTRD $1, X16, off(R9); \
	VPEXTRD $2, X16, off(R10); \
	VPEXTRD $3, X16, off(R11)

// func chaCha20256ChainAbsorb68x4Asm(
//     fixedKey *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][4]uint64)
TEXT ·chaCha20256ChainAbsorb68x4Asm(SB), NOSPLIT, $0-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// =================== Compression 1 (counter=0) ===================

	// State init.
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Z0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Z1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Z2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Z3

	PACK_KEY_DWORD(0, X4)
	PACK_KEY_DWORD(1, X5)
	PACK_KEY_DWORD(2, X6)
	PACK_KEY_DWORD(3, X7)
	PACK_KEY_DWORD(4, X8)
	PACK_KEY_DWORD(5, X9)
	PACK_KEY_DWORD(6, X10)
	PACK_KEY_DWORD(7, X11)

	VPXORD Z12, Z12, Z12
	VPXORD Z13, Z13, Z13
	VPXORD Z14, Z14, Z14
	VPXORD Z15, Z15, Z15

	// Save the per-lane key (= v_init[4..11]) to Z24..Z31. Used in
	// both compressions' keystream `+ v_init` add phases. Sigma
	// constants and counter / nonce are recomputed via broadcast.
	VMOVDQA64 Z4,  Z24
	VMOVDQA64 Z5,  Z25
	VMOVDQA64 Z6,  Z26
	VMOVDQA64 Z7,  Z27
	VMOVDQA64 Z8,  Z28
	VMOVDQA64 Z9,  Z29
	VMOVDQA64 Z10, Z30
	VMOVDQA64 Z11, Z31

	// 10 doublerounds.
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR

	// keystream block 0 = state + v_init. v_init[12..15] = 0 for
	// compression 1 (counter=0, zero nonce) — those adds are no-ops.
	// Sigma constants are re-broadcast through Z16 (Z16 is about to
	// be overwritten by absorb_state[0] anyway).
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Z16; VPADDD Z16, Z0, Z0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Z16; VPADDD Z16, Z1, Z1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Z16; VPADDD Z16, Z2, Z2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Z16; VPADDD Z16, Z3, Z3
	VPADDD Z24, Z4,  Z4
	VPADDD Z25, Z5,  Z5
	VPADDD Z26, Z6,  Z6
	VPADDD Z27, Z7,  Z7
	VPADDD Z28, Z8,  Z8
	VPADDD Z29, Z9,  Z9
	VPADDD Z30, Z10, Z10
	VPADDD Z31, Z11, Z11

	// Now Z0..Z7 = ks_lo of block 0, Z8..Z15 = ks_hi of block 0.

	// Build absorb_state into Z16..Z23.
	// state[0:8]  = uint64(68) (LE)         → absorb_state[0]=68, [1]=0
	// state[8:32] = data[lane][0:24]        → absorb_state[2..7]
	MOVL $68, R12
	VPBROADCASTD R12, Z16
	VPXORD Z17, Z17, Z17
	PACK_DATA_DWORD( 0, X18)
	PACK_DATA_DWORD( 4, X19)
	PACK_DATA_DWORD( 8, X20)
	PACK_DATA_DWORD(12, X21)
	PACK_DATA_DWORD(16, X22)
	PACK_DATA_DWORD(20, X23)

	// XKS call 1: absorb_state ^= ks_lo of block 0.
	VPXORD Z0, Z16, Z16
	VPXORD Z1, Z17, Z17
	VPXORD Z2, Z18, Z18
	VPXORD Z3, Z19, Z19
	VPXORD Z4, Z20, Z20
	VPXORD Z5, Z21, Z21
	VPXORD Z6, Z22, Z22
	VPXORD Z7, Z23, Z23

	// absorbXOR: state[8:32] ^= data[24:48] (6 dwords).
	// Z0..Z5 are dead post-XOR (Z0..Z7 held ks_lo; we used the values
	// in the XOR but VPXORD doesn't modify the source — those ZMMs
	// still contain ks_lo bits which are no longer needed). Reuse
	// them as packing scratch for the 6 absorbed data dwords.
	PACK_DATA_DWORD(24, X0); VPXORD Z0, Z18, Z18
	PACK_DATA_DWORD(28, X1); VPXORD Z1, Z19, Z19
	PACK_DATA_DWORD(32, X2); VPXORD Z2, Z20, Z20
	PACK_DATA_DWORD(36, X3); VPXORD Z3, Z21, Z21
	PACK_DATA_DWORD(40, X4); VPXORD Z4, Z22, Z22
	PACK_DATA_DWORD(44, X5); VPXORD Z5, Z23, Z23

	// XKS call 2: absorb_state ^= ks_hi of block 0.
	VPXORD Z8,  Z16, Z16
	VPXORD Z9,  Z17, Z17
	VPXORD Z10, Z18, Z18
	VPXORD Z11, Z19, Z19
	VPXORD Z12, Z20, Z20
	VPXORD Z13, Z21, Z21
	VPXORD Z14, Z22, Z22
	VPXORD Z15, Z23, Z23

	// absorbXOR: state[8:28] ^= data[48:68] (5 dwords).
	// Z8..Z12 are dead post-XOR. Reuse as packing scratch.
	PACK_DATA_DWORD(48, X8);  VPXORD Z8,  Z18, Z18
	PACK_DATA_DWORD(52, X9);  VPXORD Z9,  Z19, Z19
	PACK_DATA_DWORD(56, X10); VPXORD Z10, Z20, Z20
	PACK_DATA_DWORD(60, X11); VPXORD Z11, Z21, Z21
	PACK_DATA_DWORD(64, X12); VPXORD Z12, Z22, Z22

	// =================== Compression 2 (counter=1) ===================

	// Re-init Z0..Z15 for compression 2. absorb_state in Z16..Z23
	// and key save in Z24..Z31 are preserved across this re-init.
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Z0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Z1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Z2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Z3

	VMOVDQA64 Z24, Z4
	VMOVDQA64 Z25, Z5
	VMOVDQA64 Z26, Z6
	VMOVDQA64 Z27, Z7
	VMOVDQA64 Z28, Z8
	VMOVDQA64 Z29, Z9
	VMOVDQA64 Z30, Z10
	VMOVDQA64 Z31, Z11

	MOVL $1, R12
	VPBROADCASTD R12, Z12
	VPXORD Z13, Z13, Z13
	VPXORD Z14, Z14, Z14
	VPXORD Z15, Z15, Z15

	// 10 doublerounds.
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR

	// keystream block 1 = state + v_init for compression 2.
	// Add the key first (consumes Z24..Z31), then reuse Z24 as
	// broadcast scratch for sigma / counter adds. v_init[13..15] = 0
	// → those adds are no-ops.
	VPADDD Z24, Z4,  Z4
	VPADDD Z25, Z5,  Z5
	VPADDD Z26, Z6,  Z6
	VPADDD Z27, Z7,  Z7
	VPADDD Z28, Z8,  Z8
	VPADDD Z29, Z9,  Z9
	VPADDD Z30, Z10, Z10
	VPADDD Z31, Z11, Z11
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Z24; VPADDD Z24, Z0, Z0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Z24; VPADDD Z24, Z1, Z1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Z24; VPADDD Z24, Z2, Z2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Z24; VPADDD Z24, Z3, Z3
	MOVL $1, R12
	VPBROADCASTD R12, Z24
	VPADDD Z24, Z12, Z12

	// Now Z0..Z7 = ks_lo of block 1. Block 1's ks_hi is unused for
	// the 68-byte buf shape (3 XKS calls × 32 bytes = 96 bytes
	// keystream consumed; only the lower 8 dwords of block 1 are
	// touched).

	// XKS call 3: absorb_state ^= ks_lo of block 1.
	VPXORD Z0, Z16, Z16
	VPXORD Z1, Z17, Z17
	VPXORD Z2, Z18, Z18
	VPXORD Z3, Z19, Z19
	VPXORD Z4, Z20, Z20
	VPXORD Z5, Z21, Z21
	VPXORD Z6, Z22, Z22
	VPXORD Z7, Z23, Z23

	// =================== Writeback ===================

	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11

	STORE_LANE_DW(Z16, 0)
	STORE_LANE_DW(Z17, 4)
	STORE_LANE_DW(Z18, 8)
	STORE_LANE_DW(Z19, 12)
	STORE_LANE_DW(Z20, 16)
	STORE_LANE_DW(Z21, 20)
	STORE_LANE_DW(Z22, 24)
	STORE_LANE_DW(Z23, 28)

	VZEROUPPER
	RET
