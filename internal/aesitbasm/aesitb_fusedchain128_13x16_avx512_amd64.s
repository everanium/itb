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
// with the key folded in, and every cascade round folds the component
// pair and the key-folded block into the state with one VPTERNLOGQ per
// group.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z6      RC[0], RC[1], RC[2] broadcasts (Z6 holds the
//              groupIdxBase broadcast during the prologue)
//   Z7         absorb13Block broadcast (prologue only)
//   Z8–Z11     fill blocks, group j = lanes (4j .. 4j+3)
//   Z12, Z15   scratch for per-lane groupIdx synthesis
//   Z13        key broadcast (prologue only, folded into Z8–Z11)
//   Z14        component pair, broadcast per cascade round
//   Z16        interlock-nonce fold v << 8 broadcast (prologue only)
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ, OR of the fold into the gi>>56 word, VPUNPCKLQDQ to
//     transform into [gi<<8, gi>>56 | v<<8] per lane
//   - XOR with absorb13Block to form the fill block

#include "textflag.h"

// func aesITB128FusedChain13x16Avx512Asm(key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64, v uint32)
TEXT ·aesITB128FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-44
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ out+32(FP), DI

	// Broadcast groupIdxBase to Z6 (all 8 qwords), absorb13Block to Z7 and the
	// interlock-nonce fold v << 8 to Z16
	VPBROADCASTQ groupIdxBase+24(FP), Z6
	VBROADCASTI32X4 ·absorb13Block(SB), Z7
	MOVL v+40(FP), R9
	SHLQ $8, R9
	VPBROADCASTQ R9, Z16

	// ========== Group 0: lanes 0–3 ==========
	VPADDQ ·laneIdxZ+0(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPORQ Z16, Z15, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z8

	// ========== Group 1: lanes 4–7 ==========
	VPADDQ ·laneIdxZ+64(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPORQ Z16, Z15, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z9

	// ========== Group 2: lanes 8–11 ==========
	VPADDQ ·laneIdxZ+128(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPORQ Z16, Z15, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z10

	// ========== Group 3: lanes 12–15 ==========
	VPADDQ ·laneIdxZ+192(SB), Z6, Z12
	VPSRLQ $56, Z12, Z15
	VPORQ Z16, Z15, Z15
	VPSLLQ $8, Z12, Z12
	VPUNPCKLQDQ Z15, Z12, Z12
	VPXORD Z7, Z12, Z11

	// Load round constants and key
	VBROADCASTI32X4 ·RC+0(SB), Z4
	VBROADCASTI32X4 ·RC+16(SB), Z5
	VBROADCASTI32X4 ·RC+32(SB), Z6
	VBROADCASTI32X4 0(AX), Z13
	// Fold the key into the fill blocks once
	VPXORD Z13, Z8, Z8
	VPXORD Z13, Z9, Z9
	VPXORD Z13, Z10, Z10
	VPXORD Z13, Z11, Z11
	VPXORD Z0, Z0, Z0
	VPXORD Z1, Z1, Z1
	VPXORD Z2, Z2, Z2
	VPXORD Z3, Z3, Z3

loop:
	VBROADCASTI32X4 0(BX), Z14
	VPTERNLOGQ $0x96, Z14, Z8, Z0     // Z0 ^= Z8 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z9, Z1     // Z1 ^= Z9 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z10, Z2     // Z2 ^= Z10 ^ Z14
	VPTERNLOGQ $0x96, Z14, Z11, Z3     // Z3 ^= Z11 ^ Z14
	// AES rounds: 3 rounds on all 4 ZMM groups (RC[0], RC[1], RC[2])
	VAESENC Z4, Z0, Z0; VAESENC Z4, Z1, Z1; VAESENC Z4, Z2, Z2; VAESENC Z4, Z3, Z3
	VAESENC Z5, Z0, Z0; VAESENC Z5, Z1, Z1; VAESENC Z5, Z2, Z2; VAESENC Z5, Z3, Z3
	VAESENC Z6, Z0, Z0; VAESENC Z6, Z1, Z1; VAESENC Z6, Z2, Z2; VAESENC Z6, Z3, Z3
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	// Store outputs: group j at [64j..64j+64]
	VMOVDQU64 Z0, 0(DI)
	VMOVDQU64 Z1, 64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X3, X3, X3
	VPXORD X4, X4, X4
	VPXORD X5, X5, X5
	VPXORD X6, X6, X6
	VPXORD X7, X7, X7
	VPXORD X8, X8, X8
	VPXORD X9, X9, X9
	VPXORD X10, X10, X10
	VPXORD X11, X11, X11
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13
	VPXORD X14, X14, X14
	VPXORD X15, X15, X15
	VPXORD X16, X16, X16
	VPXORD X17, X17, X17
	VPXORD X18, X18, X18
	VPXORD X19, X19, X19
	VPXORD X20, X20, X20
	VPXORD X21, X21, X21
	VPXORD X22, X22, X22
	VPXORD X23, X23, X23
	VPXORD X24, X24, X24
	VPXORD X25, X25, X25
	VPXORD X26, X26, X26
	VPXORD X27, X27, X27
	VPXORD X28, X28, X28
	VPXORD X29, X29, X29
	VPXORD X30, X30, X30
	VPXORD X31, X31, X31
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DI, DI
	XORQ R9, R9

	VZEROUPPER
	RET
