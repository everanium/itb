//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) 4-lane fused chain-absorb kernel for
// AES-CMAC-128 with 36-byte per-lane data input (the ITB
// SetNonceBits(256) buf shape). Three CBC-MAC absorb rounds per lane.
// AES-NI-only fallback (see aescmac_chain128_20_aesni_amd64.s for the
// register-layout rationale).
//
// Per-lane absorb construction (matches hashes.AESCMAC bit-exactly):
//
//	state[0:8]  = seeds[lane][0] ^ uint64(36)
//	state[8:16] = seeds[lane][1] ^ uint64(36)
//	state      ^= data[lane][0:16];  state = AES_K(state)   (round 1)
//	state      ^= data[lane][16:32]; state = AES_K(state)   (round 2)
//	state[0:4] ^= data[lane][32:36]; state = AES_K(state)   (round 3)
//
// Register allocation: identical to the 20-byte kernel. Stack frame:
// 64 bytes for the 4-byte tail staging of round 3.

#include "textflag.h"

#define AES_PERM4 \
	PXOR X5, X0; PXOR X5, X1; PXOR X5, X2; PXOR X5, X3; \
	AESENC X6, X0;  AESENC X6, X1;  AESENC X6, X2;  AESENC X6, X3; \
	AESENC X7, X0;  AESENC X7, X1;  AESENC X7, X2;  AESENC X7, X3; \
	AESENC X8, X0;  AESENC X8, X1;  AESENC X8, X2;  AESENC X8, X3; \
	AESENC X9, X0;  AESENC X9, X1;  AESENC X9, X2;  AESENC X9, X3; \
	AESENC X10, X0; AESENC X10, X1; AESENC X10, X2; AESENC X10, X3; \
	AESENC X11, X0; AESENC X11, X1; AESENC X11, X2; AESENC X11, X3; \
	AESENC X12, X0; AESENC X12, X1; AESENC X12, X2; AESENC X12, X3; \
	AESENC X13, X0; AESENC X13, X1; AESENC X13, X2; AESENC X13, X3; \
	AESENC X14, X0; AESENC X14, X1; AESENC X14, X2; AESENC X14, X3; \
	AESENCLAST X15, X0; AESENCLAST X15, X1; AESENCLAST X15, X2; AESENCLAST X15, X3

#define LOAD_KEYS \
	MOVOU 0(AX), X5;    MOVOU 16(AX), X6;   MOVOU 32(AX), X7;   MOVOU 48(AX), X8; \
	MOVOU 64(AX), X9;   MOVOU 80(AX), X10;  MOVOU 96(AX), X11;  MOVOU 112(AX), X12; \
	MOVOU 128(AX), X13; MOVOU 144(AX), X14; MOVOU 160(AX), X15

// ABSORB16 — XOR the full 16-byte block at data offset `off` of every
// lane into the four lane states (rounds 1 and 2).
#define ABSORB16(off) \
	MOVOU off(R8),  X4; PXOR X4, X0; \
	MOVOU off(R9),  X4; PXOR X4, X1; \
	MOVOU off(R10), X4; PXOR X4, X2; \
	MOVOU off(R11), X4; PXOR X4, X3

// func aesCMAC128ChainAbsorb36x4AesNiAsm(
//     roundKeys *[176]byte,
//     seeds     *[4][2]uint64,
//     dataPtrs  *[4]*byte,
//     out       *[4][2]uint64)
TEXT ·aesCMAC128ChainAbsorb36x4AesNiAsm(SB), NOSPLIT, $64-32
	MOVQ roundKeys+0(FP), AX
	MOVQ seeds+8(FP),     BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== State init: seeds ⊕ broadcast(lenTag) ⊕ data[0:16] =====
	MOVOU 0(BX),  X0
	MOVOU 16(BX), X1
	MOVOU 32(BX), X2
	MOVOU 48(BX), X3

	MOVQ $36, R12
	VMOVQ R12, X4
	PUNPCKLQDQ X4, X4
	PXOR X4, X0
	PXOR X4, X1
	PXOR X4, X2
	PXOR X4, X3

	ABSORB16(0)

	LOAD_KEYS

	// ===== Round 1 =====
	AES_PERM4

	// ===== Round 2: absorb data[16:32] =====
	ABSORB16(16)
	AES_PERM4

	// ===== Round 3: absorb 4-byte tail data[32:36] =====
	PXOR X4, X4
	MOVOU X4, 0(SP)
	MOVOU X4, 16(SP)
	MOVOU X4, 32(SP)
	MOVOU X4, 48(SP)

	MOVL 32(R8),  R12
	MOVL R12, 0(SP)
	MOVL 32(R9),  R12
	MOVL R12, 16(SP)
	MOVL 32(R10), R12
	MOVL R12, 32(SP)
	MOVL 32(R11), R12
	MOVL R12, 48(SP)

	MOVOU 0(SP),  X4
	PXOR X4, X0
	MOVOU 16(SP), X4
	PXOR X4, X1
	MOVOU 32(SP), X4
	PXOR X4, X2
	MOVOU 48(SP), X4
	PXOR X4, X3

	AES_PERM4

	// ===== Writeback =====
	MOVOU X0, 0(DX)
	MOVOU X1, 16(DX)
	MOVOU X2, 32(DX)
	MOVOU X3, 48(DX)

	RET
