//go:build amd64 && !purego && !noitbasm

// VAES ZMM, four lanes per register (needs VAES + AVX-512) 16-lane fused ChainHash cascade kernel
// for AES-ITB-128 at the 13-byte per-lane fill shape (1 PKCS#7 block, 3 AES rounds per lane and cascade round).
// See aesitbasm_fused.go for the construction; every tier is pinned to
// the pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 4 ZMM states, four lanes per ZMM (lanes 4j..4j+3 in Z[j]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// per-group VPADDQ (applying laneIdxZ offsets) and VPUNPCKLQDQ. The whole
// cascade is register-resident: the four block registers are built once
// and every cascade round folds key XOR pair and the block into the state
// with one VPTERNLOGQ per group.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z5      RC[0], RC[1] broadcasts
//   Z6–Z7      groupIdxBase / absorb13Block broadcasts (prologue only)
//   Z8–Z11     fill blocks, group j = lanes (4j .. 4j+3)
//   Z12, Z15   scratch for per-lane groupIdx synthesis
//   Z13        key broadcast
//   Z14        key XOR component pair, broadcast per cascade round
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ/VPUNPCKLQDQ to transform into [gi<<8, gi>>56] per lane
//   - XOR with absorb13Block to form the fill block

#include "textflag.h"

// func aesITB128FusedChain13x16Avx512Asm(key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ out+32(FP), DI

	// Broadcast groupIdxBase to Z6 (all 8 qwords) and absorb13Block to Z7
	VPBROADCASTQ groupIdxBase+24(FP), Z6
	VBROADCASTI32X4 ·absorb13Block(SB), Z7

	// ========== Group 0: lanes 0–3 ==========
	VPADDQ ·laneIdxZ+0(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z8

	// ========== Group 1: lanes 4–7 ==========
	VPADDQ ·laneIdxZ+64(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z9

	// ========== Group 2: lanes 8–11 ==========
	VPADDQ ·laneIdxZ+128(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z10

	// ========== Group 3: lanes 12–15 ==========
	VPADDQ ·laneIdxZ+192(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z11

	// Load round constants and key
	VBROADCASTI32X4 ·RC+0(SB), Z4
	VBROADCASTI32X4 ·RC+16(SB), Z5
	VBROADCASTI32X4 0(AX), Z13
	VPXORD Z0, Z0, Z0
	VPXORD Z1, Z1, Z1
	VPXORD Z2, Z2, Z2
	VPXORD Z3, Z3, Z3

loop:
	VBROADCASTI32X4 0(BX), Z14
	VPXORD Z13, Z14, Z14
	VPTERNLOGQ $0x96, Z14, Z8, Z0     // Z0 ^= Z8 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z9, Z1     // Z1 ^= Z9 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z10, Z2     // Z2 ^= Z10 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z11, Z3     // Z3 ^= Z11 ^ Z14
	// AES rounds: 3 rounds on all 4 ZMM groups (RC[0], RC[0], RC[1])
	VAESENC Z4, Z0, Z0; VAESENC Z4, Z1, Z1; VAESENC Z4, Z2, Z2; VAESENC Z4, Z3, Z3
	VAESENC Z4, Z0, Z0; VAESENC Z4, Z1, Z1; VAESENC Z4, Z2, Z2; VAESENC Z4, Z3, Z3
	VAESENC Z5, Z0, Z0; VAESENC Z5, Z1, Z1; VAESENC Z5, Z2, Z2; VAESENC Z5, Z3, Z3
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	// Store outputs: group j at [64j..64j+64]
	VMOVDQU64 Z0, 0(DI)
	VMOVDQU64 Z1, 64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)

	VZEROUPPER
	RET
