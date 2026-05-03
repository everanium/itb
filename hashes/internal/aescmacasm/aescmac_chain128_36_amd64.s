//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for AES-CMAC-128 with 36-byte
// per-lane data input (the ITB SetNonceBits(256) buf shape). Three
// AES-CMAC rounds per lane:
//
//	state[0:8]  = seeds[lane][0] ^ uint64(36)
//	state[8:16] = seeds[lane][1] ^ uint64(36)
//	state      ^= data[lane][0:16];  state = AES_K(state)   (round 1)
//	state      ^= data[lane][16:32]; state = AES_K(state)   (round 2)
//	state[0:4] ^= data[lane][32:36]; state = AES_K(state)   (round 3)
//
//	aesCMAC128ChainAbsorb36x4Asm(
//	    roundKeys *[176]byte,
//	    seeds     *[4][2]uint64,
//	    dataPtrs  *[4]*byte,
//	    out       *[4][2]uint64)

#include "textflag.h"

#define AES_ROUND \
	VPXORD Z1, Z0, Z0; \
	VAESENC Z2,  Z0, Z0; \
	VAESENC Z3,  Z0, Z0; \
	VAESENC Z4,  Z0, Z0; \
	VAESENC Z5,  Z0, Z0; \
	VAESENC Z6,  Z0, Z0; \
	VAESENC Z7,  Z0, Z0; \
	VAESENC Z8,  Z0, Z0; \
	VAESENC Z9,  Z0, Z0; \
	VAESENC Z10, Z0, Z0; \
	VAESENCLAST Z11, Z0, Z0

#define LOAD_ROUND_KEYS \
	VBROADCASTI32X4   0(AX), Z1; \
	VBROADCASTI32X4  16(AX), Z2; \
	VBROADCASTI32X4  32(AX), Z3; \
	VBROADCASTI32X4  48(AX), Z4; \
	VBROADCASTI32X4  64(AX), Z5; \
	VBROADCASTI32X4  80(AX), Z6; \
	VBROADCASTI32X4  96(AX), Z7; \
	VBROADCASTI32X4 112(AX), Z8; \
	VBROADCASTI32X4 128(AX), Z9; \
	VBROADCASTI32X4 144(AX), Z10; \
	VBROADCASTI32X4 160(AX), Z11

// LOAD_LANE_BLOCK16 — load 16 bytes from each lane data pointer at
// byte offset `off` into Z_dst lanes 0..3. Used to absorb full
// 16-byte AES blocks (rounds 1 and 2 for the 36-byte case).
#define LOAD_LANE_BLOCK16(off, z_dst, x_dst, y_dst) \
	VMOVDQU off(R8),  x_dst; \
	VINSERTI64X2 $1, off(R9),  y_dst, y_dst; \
	VINSERTI64X2 $2, off(R10), z_dst, z_dst; \
	VINSERTI64X2 $3, off(R11), z_dst, z_dst

TEXT ·aesCMAC128ChainAbsorb36x4Asm(SB), NOSPLIT, $64-32
	MOVQ roundKeys+0(FP), AX
	MOVQ seeds+8(FP),     BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== State init: seeds ⊕ broadcast(lenTag) ⊕ data[0:16] =====
	VMOVDQU 0(BX),    X0
	VINSERTI64X2 $1, 16(BX), Y0, Y0
	VINSERTI64X2 $2, 32(BX), Z0, Z0
	VINSERTI64X2 $3, 48(BX), Z0, Z0

	MOVQ $36, R12
	VPBROADCASTQ R12, Z12
	VPXORQ Z12, Z0, Z0

	LOAD_LANE_BLOCK16(0, Z12, X12, Y12)
	VPXORD Z12, Z0, Z0

	// ===== Broadcast round keys =====
	LOAD_ROUND_KEYS

	// ===== Round 1 =====
	AES_ROUND

	// ===== Round 2: absorb data[16:32] =====
	LOAD_LANE_BLOCK16(16, Z12, X12, Y12)
	VPXORD Z12, Z0, Z0

	AES_ROUND

	// ===== Round 3: absorb 4-byte tail data[32:36] =====
	VPXORD Z12, Z12, Z12
	VMOVDQU64 Z12, 0(SP)

	MOVL 32(R8),  R12
	MOVL R12, 0(SP)
	MOVL 32(R9),  R12
	MOVL R12, 16(SP)
	MOVL 32(R10), R12
	MOVL R12, 32(SP)
	MOVL 32(R11), R12
	MOVL R12, 48(SP)

	VMOVDQU64 0(SP), Z12
	VPXORD Z12, Z0, Z0

	AES_ROUND

	// ===== Writeback =====
	VEXTRACTI64X2 $0, Z0, 0(DX)
	VEXTRACTI64X2 $1, Z0, 16(DX)
	VEXTRACTI64X2 $2, Z0, 32(DX)
	VEXTRACTI64X2 $3, Z0, 48(DX)

	VZEROUPPER
	RET
