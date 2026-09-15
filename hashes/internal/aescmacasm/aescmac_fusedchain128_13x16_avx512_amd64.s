//go:build amd64 && !purego && !noitbasm

// VAES ZMM, four lanes per register (needs VAES + AVX-512) 16-lane fused ChainHash cascade kernel
// for AES-CMAC at the 13-byte per-lane fill shape (1 zero-padded block,
// 1 AES-128 permutation per lane and cascade round). See
// aescmacasm_fused.go for the construction; every tier is pinned to the
// pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 4 ZMM states, four lanes per ZMM (lanes 4j..4j+3 in Z[j]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// per-group VPADDQ (applying laneIdxZ offsets) and VPUNPCKLQDQ. The whole
// cascade is register-resident: the four block registers are built once
// and every cascade round folds the pair and the block into the state
// with one VPTERNLOGQ per group.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z13     K1..K10 broadcasts
//   Z14        component pair, broadcast per cascade round
//   Z15        block template: absorb13Block ^ K0 ^ length tag (prologue only)
//   Z16–Z19    fill blocks, group j = lanes (4j .. 4j+3)
//   Z20–Z22    groupIdxBase broadcast and synthesis scratch (prologue only)
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ/VPUNPCKLQDQ to transform into [gi<<8, gi>>56] per lane
//   - XOR with the template to form the fill block

#include "textflag.h"

// func aesCMAC128FusedChain13x16Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesCMAC128FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-40
	MOVQ roundKeys+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ out+32(FP), DI

	// Broadcast groupIdxBase to Z20 (all 8 qwords); template Z15 = absorb13Block ^ K0 ^ (13 || 13)
	VPBROADCASTQ groupIdxBase+24(FP), Z20
	VBROADCASTI32X4 ·absorb13Block(SB), Z15
	VBROADCASTI32X4 0(AX), Z21
	VPXORD Z21, Z15, Z15
	MOVQ $13, R12
	VPBROADCASTQ R12, Z21
	VPXORD Z21, Z15, Z15

	// ========== Group 0: lanes 0–3 ==========
	VPADDQ ·laneIdxZ+0(SB), Z20, Z21
	VPSRLQ $56, Z21, Z22
	VPSLLQ $8, Z21, Z21
	VPUNPCKLQDQ Z22, Z21, Z21
	VPXORD Z15, Z21, Z16

	// ========== Group 1: lanes 4–7 ==========
	VPADDQ ·laneIdxZ+64(SB), Z20, Z21
	VPSRLQ $56, Z21, Z22
	VPSLLQ $8, Z21, Z21
	VPUNPCKLQDQ Z22, Z21, Z21
	VPXORD Z15, Z21, Z17

	// ========== Group 2: lanes 8–11 ==========
	VPADDQ ·laneIdxZ+128(SB), Z20, Z21
	VPSRLQ $56, Z21, Z22
	VPSLLQ $8, Z21, Z21
	VPUNPCKLQDQ Z22, Z21, Z21
	VPXORD Z15, Z21, Z18

	// ========== Group 3: lanes 12–15 ==========
	VPADDQ ·laneIdxZ+192(SB), Z20, Z21
	VPSRLQ $56, Z21, Z22
	VPSLLQ $8, Z21, Z21
	VPUNPCKLQDQ Z22, Z21, Z21
	VPXORD Z15, Z21, Z19

	// Load K1..K10
	VBROADCASTI32X4 16(AX), Z4
	VBROADCASTI32X4 32(AX), Z5
	VBROADCASTI32X4 48(AX), Z6
	VBROADCASTI32X4 64(AX), Z7
	VBROADCASTI32X4 80(AX), Z8
	VBROADCASTI32X4 96(AX), Z9
	VBROADCASTI32X4 112(AX), Z10
	VBROADCASTI32X4 128(AX), Z11
	VBROADCASTI32X4 144(AX), Z12
	VBROADCASTI32X4 160(AX), Z13
	VPXORD Z0, Z0, Z0
	VPXORD Z1, Z1, Z1
	VPXORD Z2, Z2, Z2
	VPXORD Z3, Z3, Z3

loop:
	VBROADCASTI32X4 0(BX), Z14
	VPTERNLOGQ $0x96, Z14, Z16, Z0     // Z0 ^= Z16 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z17, Z1     // Z1 ^= Z17 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z18, Z2     // Z2 ^= Z18 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z19, Z3     // Z3 ^= Z19 ^ Z14
	// AES rounds 1..10 on all 4 ZMM groups
	VAESENC Z4, Z0, Z0; VAESENC Z4, Z1, Z1; VAESENC Z4, Z2, Z2; VAESENC Z4, Z3, Z3
	VAESENC Z5, Z0, Z0; VAESENC Z5, Z1, Z1; VAESENC Z5, Z2, Z2; VAESENC Z5, Z3, Z3
	VAESENC Z6, Z0, Z0; VAESENC Z6, Z1, Z1; VAESENC Z6, Z2, Z2; VAESENC Z6, Z3, Z3
	VAESENC Z7, Z0, Z0; VAESENC Z7, Z1, Z1; VAESENC Z7, Z2, Z2; VAESENC Z7, Z3, Z3
	VAESENC Z8, Z0, Z0; VAESENC Z8, Z1, Z1; VAESENC Z8, Z2, Z2; VAESENC Z8, Z3, Z3
	VAESENC Z9, Z0, Z0; VAESENC Z9, Z1, Z1; VAESENC Z9, Z2, Z2; VAESENC Z9, Z3, Z3
	VAESENC Z10, Z0, Z0; VAESENC Z10, Z1, Z1; VAESENC Z10, Z2, Z2; VAESENC Z10, Z3, Z3
	VAESENC Z11, Z0, Z0; VAESENC Z11, Z1, Z1; VAESENC Z11, Z2, Z2; VAESENC Z11, Z3, Z3
	VAESENC Z12, Z0, Z0; VAESENC Z12, Z1, Z1; VAESENC Z12, Z2, Z2; VAESENC Z12, Z3, Z3
	VAESENCLAST Z13, Z0, Z0; VAESENCLAST Z13, Z1, Z1; VAESENCLAST Z13, Z2, Z2; VAESENCLAST Z13, Z3, Z3
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
