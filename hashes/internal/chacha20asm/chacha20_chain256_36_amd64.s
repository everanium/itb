//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for ChaCha20-256 with 36-byte
// per-lane data input (the ITB SetNonceBits(256) buf shape). One
// ChaCha20 compression (counter=0); two XKS calls consume both
// halves of block 0 (ks_lo, then ks_hi) with a 12-byte absorbXOR
// between them.
//
// Per-lane absorb construction (matches the public hashes.ChaCha20
// closure bit-exactly):
//
//	state[0:8]  = uint64(36) (LE)
//	state[8:32] = data[lane][0:24]
//	XKS call 1: state[i] ^= ks_lo_dword[i]  for i in 0..7
//	state[8:20] ^= data[lane][24:36]            (3 dwords absorbXOR)
//	XKS call 2: state[i] ^= ks_hi_dword[i]  for i in 0..7
//	output:    state[0:32] (4 × LE uint64)
//
//	chaCha20256ChainAbsorb36x4Asm(
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

// func chaCha20256ChainAbsorb36x4Asm(
//     fixedKey *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][4]uint64)
TEXT ·chaCha20256ChainAbsorb36x4Asm(SB), NOSPLIT, $0-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== State init =====
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

	// ===== Save v_init to Z16..Z31 =====
	VMOVDQA64 Z0,  Z16
	VMOVDQA64 Z1,  Z17
	VMOVDQA64 Z2,  Z18
	VMOVDQA64 Z3,  Z19
	VMOVDQA64 Z4,  Z20
	VMOVDQA64 Z5,  Z21
	VMOVDQA64 Z6,  Z22
	VMOVDQA64 Z7,  Z23
	VMOVDQA64 Z8,  Z24
	VMOVDQA64 Z9,  Z25
	VMOVDQA64 Z10, Z26
	VMOVDQA64 Z11, Z27
	VMOVDQA64 Z12, Z28
	VMOVDQA64 Z13, Z29
	VMOVDQA64 Z14, Z30
	VMOVDQA64 Z15, Z31

	// ===== 10 doublerounds = 20 ChaCha20 rounds =====
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

	// ===== keystream = state + v_init =====
	VPADDD Z16, Z0,  Z0
	VPADDD Z17, Z1,  Z1
	VPADDD Z18, Z2,  Z2
	VPADDD Z19, Z3,  Z3
	VPADDD Z20, Z4,  Z4
	VPADDD Z21, Z5,  Z5
	VPADDD Z22, Z6,  Z6
	VPADDD Z23, Z7,  Z7
	VPADDD Z24, Z8,  Z8
	VPADDD Z25, Z9,  Z9
	VPADDD Z26, Z10, Z10
	VPADDD Z27, Z11, Z11
	VPADDD Z28, Z12, Z12
	VPADDD Z29, Z13, Z13
	VPADDD Z30, Z14, Z14
	VPADDD Z31, Z15, Z15

	// Now Z0..Z7 = ks_lo, Z8..Z15 = ks_hi (full 64-byte block 0).

	// ===== Build absorb_state into Z16..Z23 =====
	// state[0:8]  = uint64(36) (LE)         → absorb_state[0]=36, [1]=0
	// state[8:32] = data[lane][0:24]        → absorb_state[2..7]
	MOVL $36, R12
	VPBROADCASTD R12, Z16   // absorb_state[0] = 36
	VPXORD Z17, Z17, Z17    // absorb_state[1] = 0
	PACK_DATA_DWORD( 0, X18) // absorb_state[2] = data[0:4]
	PACK_DATA_DWORD( 4, X19) // absorb_state[3] = data[4:8]
	PACK_DATA_DWORD( 8, X20) // absorb_state[4] = data[8:12]
	PACK_DATA_DWORD(12, X21) // absorb_state[5] = data[12:16]
	PACK_DATA_DWORD(16, X22) // absorb_state[6] = data[16:20]
	PACK_DATA_DWORD(20, X23) // absorb_state[7] = data[20:24]

	// ===== XKS call 1: absorb_state ^= ks_lo =====
	VPXORD Z0, Z16, Z16
	VPXORD Z1, Z17, Z17
	VPXORD Z2, Z18, Z18
	VPXORD Z3, Z19, Z19
	VPXORD Z4, Z20, Z20
	VPXORD Z5, Z21, Z21
	VPXORD Z6, Z22, Z22
	VPXORD Z7, Z23, Z23

	// ===== absorbXOR: state[8:20] ^= data[24:36] (3 dwords) =====
	// In dword terms: absorb_state[2..4] ^= pack(data[24:28..32..36]).
	// Z24..Z26 are free (their v_init save was consumed by the
	// VPADDD above, and ks_hi already lives in Z8..Z15).
	PACK_DATA_DWORD(24, X24); VPXORD Z24, Z18, Z18
	PACK_DATA_DWORD(28, X25); VPXORD Z25, Z19, Z19
	PACK_DATA_DWORD(32, X26); VPXORD Z26, Z20, Z20

	// ===== XKS call 2: absorb_state ^= ks_hi =====
	VPXORD Z8,  Z16, Z16
	VPXORD Z9,  Z17, Z17
	VPXORD Z10, Z18, Z18
	VPXORD Z11, Z19, Z19
	VPXORD Z12, Z20, Z20
	VPXORD Z13, Z21, Z21
	VPXORD Z14, Z22, Z22
	VPXORD Z15, Z23, Z23

	// ===== Writeback =====
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
