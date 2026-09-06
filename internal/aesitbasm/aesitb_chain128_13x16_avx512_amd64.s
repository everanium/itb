//go:build amd64 && !purego && !noitbasm

// VAES ZMM, four lanes per register (needs VAES + AVX-512) 16-lane chain-absorb kernel
// for AES-ITB-128 at the 13-byte per-lane shape (1 PKCS#7 block, 3 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Batch layout: 4 ZMM states, four lanes per ZMM (lanes 4j..4j+3 in Z[j]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// per-group VPADDQ (applying laneIdxZ offsets) and VPUNPCKLQDQ.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z5      RC[0], RC[1] broadcasts
//   Z6–Z8      scratch for template and per-lane groupIdx synthesis
//   Z9–Z15     free
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ/VPUNPCKLQDQ to transform into [gi<<8, gi>>56] per lane

#include "textflag.h"

// func aesITB128ChainAbsorb13x16VaesAvx512Asm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128ChainAbsorb13x16VaesAvx512Asm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ out+32(FP), DI

	// Broadcast groupIdxBase to Z6 (all 8 qwords)
	VPBROADCASTQ groupIdxBase+24(FP), Z6

	// Load template: seed0 and seed1, compute XOR with key and absorb13Block
	VPBROADCASTQ seed0+8(FP), Z7
	VPBROADCASTQ seed1+16(FP), Z8
	VPUNPCKLQDQ Z8, Z7, Z7           // Per lane: [seed0, seed1]
	VBROADCASTI32X4 0(AX), Z8        // Key broadcast to all 4 lanes per ZMM
	VBROADCASTI32X4 ·absorb13Block(SB), Z9
	VPTERNLOGQ $0x96, Z9, Z8, Z7     // Z7 ^= Z8 ^ Z9 (template = key XOR seeds XOR absorb13Block)

	// Load round constants
	VBROADCASTI32X4 ·RC+0(SB), Z4
	VBROADCASTI32X4 ·RC+16(SB), Z5

	// ========== Group 0: lanes 0–3 ==========
	VPADDQ ·laneIdxZ+0(SB), Z6, Z8
	VPSRLQ $56, Z8, Z9
	VPSLLQ $8, Z8, Z8
	VPUNPCKLQDQ Z9, Z8, Z8
	VPXORD Z7, Z8, Z0

	// ========== Group 1: lanes 4–7 ==========
	VPADDQ ·laneIdxZ+64(SB), Z6, Z8
	VPSRLQ $56, Z8, Z9
	VPSLLQ $8, Z8, Z8
	VPUNPCKLQDQ Z9, Z8, Z8
	VPXORD Z7, Z8, Z1

	// ========== Group 2: lanes 8–11 ==========
	VPADDQ ·laneIdxZ+128(SB), Z6, Z8
	VPSRLQ $56, Z8, Z9
	VPSLLQ $8, Z8, Z8
	VPUNPCKLQDQ Z9, Z8, Z8
	VPXORD Z7, Z8, Z2

	// ========== Group 3: lanes 12–15 ==========
	VPADDQ ·laneIdxZ+192(SB), Z6, Z8
	VPSRLQ $56, Z8, Z9
	VPSLLQ $8, Z8, Z8
	VPUNPCKLQDQ Z9, Z8, Z8
	VPXORD Z7, Z8, Z3

	// AES rounds: 3 rounds on all 4 ZMM pairs (RC[0], RC[0], RC[1])
	VAESENC Z4, Z0, Z0; VAESENC Z4, Z1, Z1; VAESENC Z4, Z2, Z2; VAESENC Z4, Z3, Z3
	VAESENC Z4, Z0, Z0; VAESENC Z4, Z1, Z1; VAESENC Z4, Z2, Z2; VAESENC Z4, Z3, Z3
	VAESENC Z5, Z0, Z0; VAESENC Z5, Z1, Z1; VAESENC Z5, Z2, Z2; VAESENC Z5, Z3, Z3

	// Store outputs: group j at [64j..64j+64]
	VMOVDQU64 Z0, 0(DI)
	VMOVDQU64 Z1, 64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)

	VZEROUPPER
	RET
