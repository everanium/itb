//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for ChaCha20-256 with 36-byte
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
// Register allocation: identical to the 20-byte kernel
// (chacha20_chain256_20_amd64.s).

#include "textflag.h"

#define CHACHA_QR(a, b, c, d) \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $16, d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $12, b, b; \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $8,  d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $7,  b, b

#define CHACHA_DR \
	CHACHA_QR(X0, X4, X8,  X12); \
	CHACHA_QR(X1, X5, X9,  X13); \
	CHACHA_QR(X2, X6, X10, X14); \
	CHACHA_QR(X3, X7, X11, X15); \
	CHACHA_QR(X0, X5, X10, X15); \
	CHACHA_QR(X1, X6, X11, X12); \
	CHACHA_QR(X2, X7, X8,  X13); \
	CHACHA_QR(X3, X4, X9,  X14)

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

#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

// func chaCha20256ChainAbsorb36x4Asm(
//     fixedKey *[32]byte,         // shared 32-byte fixed key
//     seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//     dataPtrs *[4]*byte,         // 4 pointers, each to ≥36 bytes
//     out      *[4][4]uint64)     // output: 32 bytes per lane
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
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  X0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  X1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  X2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), X3

	PACK_KEY_DWORD(0, X4)
	PACK_KEY_DWORD(1, X5)
	PACK_KEY_DWORD(2, X6)
	PACK_KEY_DWORD(3, X7)
	PACK_KEY_DWORD(4, X8)
	PACK_KEY_DWORD(5, X9)
	PACK_KEY_DWORD(6, X10)
	PACK_KEY_DWORD(7, X11)

	VPXORD X12, X12, X12
	VPXORD X13, X13, X13
	VPXORD X14, X14, X14
	VPXORD X15, X15, X15

	// ===== Save v_init to X16..X31 =====
	VMOVDQA64 X0,  X16
	VMOVDQA64 X1,  X17
	VMOVDQA64 X2,  X18
	VMOVDQA64 X3,  X19
	VMOVDQA64 X4,  X20
	VMOVDQA64 X5,  X21
	VMOVDQA64 X6,  X22
	VMOVDQA64 X7,  X23
	VMOVDQA64 X8,  X24
	VMOVDQA64 X9,  X25
	VMOVDQA64 X10, X26
	VMOVDQA64 X11, X27
	VMOVDQA64 X12, X28
	VMOVDQA64 X13, X29
	VMOVDQA64 X14, X30
	VMOVDQA64 X15, X31

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
	VPADDD X16, X0,  X0
	VPADDD X17, X1,  X1
	VPADDD X18, X2,  X2
	VPADDD X19, X3,  X3
	VPADDD X20, X4,  X4
	VPADDD X21, X5,  X5
	VPADDD X22, X6,  X6
	VPADDD X23, X7,  X7
	VPADDD X24, X8,  X8
	VPADDD X25, X9,  X9
	VPADDD X26, X10, X10
	VPADDD X27, X11, X11
	VPADDD X28, X12, X12
	VPADDD X29, X13, X13
	VPADDD X30, X14, X14
	VPADDD X31, X15, X15

	// Now X0..X7 = ks_lo, X8..X15 = ks_hi (full 64-byte block 0).

	// ===== Build absorb_state into X16..X23 =====
	// state[0:8]  = uint64(36) (LE)         → absorb_state[0]=36, [1]=0
	// state[8:32] = data[lane][0:24]        → absorb_state[2..7]
	MOVL $36, R12
	VPBROADCASTD R12, X16   // absorb_state[0] = 36
	VPXORD X17, X17, X17    // absorb_state[1] = 0
	PACK_DATA_DWORD( 0, X18) // absorb_state[2] = data[0:4]
	PACK_DATA_DWORD( 4, X19) // absorb_state[3] = data[4:8]
	PACK_DATA_DWORD( 8, X20) // absorb_state[4] = data[8:12]
	PACK_DATA_DWORD(12, X21) // absorb_state[5] = data[12:16]
	PACK_DATA_DWORD(16, X22) // absorb_state[6] = data[16:20]
	PACK_DATA_DWORD(20, X23) // absorb_state[7] = data[20:24]

	// ===== XKS call 1: absorb_state ^= ks_lo =====
	VPXORD X0, X16, X16
	VPXORD X1, X17, X17
	VPXORD X2, X18, X18
	VPXORD X3, X19, X19
	VPXORD X4, X20, X20
	VPXORD X5, X21, X21
	VPXORD X6, X22, X22
	VPXORD X7, X23, X23

	// ===== absorbXOR: state[8:20] ^= data[24:36] (3 dwords) =====
	// In dword terms: absorb_state[2..4] ^= pack(data[24:28..32..36]).
	// X24..X26 are free (their v_init save was consumed by the
	// VPADDD above, and ks_hi already lives in X8..X15).
	PACK_DATA_DWORD(24, X24); VPXORD X24, X18, X18
	PACK_DATA_DWORD(28, X25); VPXORD X25, X19, X19
	PACK_DATA_DWORD(32, X26); VPXORD X26, X20, X20

	// ===== XKS call 2: absorb_state ^= ks_hi =====
	VPXORD X8,  X16, X16
	VPXORD X9,  X17, X17
	VPXORD X10, X18, X18
	VPXORD X11, X19, X19
	VPXORD X12, X20, X20
	VPXORD X13, X21, X21
	VPXORD X14, X22, X22
	VPXORD X15, X23, X23

	// ===== Writeback =====
	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11

	STORE_LANE_DW(X16, 0)
	STORE_LANE_DW(X17, 4)
	STORE_LANE_DW(X18, 8)
	STORE_LANE_DW(X19, 12)
	STORE_LANE_DW(X20, 16)
	STORE_LANE_DW(X21, 20)
	STORE_LANE_DW(X22, 24)
	STORE_LANE_DW(X23, 28)

	VZEROUPPER
	RET
