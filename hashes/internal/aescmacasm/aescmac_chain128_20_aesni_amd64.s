//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) 4-lane fused chain-absorb kernel for
// AES-CMAC-128 with 20-byte per-lane data input (the ITB
// SetNonceBits(128) buf shape — default config). This is the
// AES-NI-only fallback for hosts that expose AESENC on XMM but lack the
// VAES + AVX-512 ZMM path (Cascade Lake Xeon Gold, AMD Zen 3, every
// AVX2-no-VAES cloud VM).
//
// Lane-parallel layout: each of the four 16-byte AES-CMAC states lives
// in its own XMM register (X0..X3). One AES-128 permutation is applied
// to all four states by issuing four AESENC instructions per round key,
// one per lane — four independent dependency chains that hide the
// ~4-cycle AESENC latency on a single AES issue port (playbook §8: ILP
// restore). The 11 round keys are loaded once into X5..X15 and reused
// across both CBC-MAC rounds.
//
// Per-lane absorb construction (matches the public hashes.AESCMAC
// closure bit-exactly — identical to the ZMM kernel's contract):
//
//	state[0:8]  = seeds[lane][0] ^ uint64(20)  (LE)
//	state[8:16] = seeds[lane][1] ^ uint64(20)
//	state[0:16] ^= data[lane][0:16]
//	state = AES_K(state)                        (CBC-MAC round 1)
//	state[0:4] ^= data[lane][16:20]             (4-byte tail XOR)
//	state = AES_K(state)                        (CBC-MAC round 2)
//	out[lane][0] = LE uint64 of state[0:8]
//	out[lane][1] = LE uint64 of state[8:16]
//
// Register allocation:
//
//	AX        roundKeys ptr (176 bytes = 11 × 16-byte AES round keys)
//	BX        seeds ptr     (4 lanes × 2 uint64; per-lane stride 16 bytes)
//	CX        dataPtrs ptr  (4 lane pointers)
//	DX        out ptr
//	R8..R11   per-lane data ptrs
//	R12       scratch GPR for lenTag / stack staging
//	X0..X3    per-lane AES-CMAC state (16 bytes per lane)
//	X4        absorb / staging scratch
//	X5..X15   round keys K0..K10 (one XMM each)
//
// Stack frame: 64 bytes of scratch for the 4-byte tail staging of
// round 2 (zero-padded to 16 bytes per lane).

#include "textflag.h"

// AES_PERM4 — full 10-round AES-128 forward permutation applied in
// parallel to the four lane states X0..X3, using round keys K0..K10
// preloaded in X5..X15. Initial AddRoundKey via PXOR with K0 (X5);
// rounds 1..9 via AESENC with K1..K9 (X6..X14); final round via
// AESENCLAST with K10 (X15). The four per-key AESENC issue as four
// independent chains for ILP.
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

// LOAD_KEYS — load all 11 AES round keys into X5..X15. MOVOU is
// unaligned-safe (the *[176]byte schedule carries no alignment
// guarantee).
#define LOAD_KEYS \
	MOVOU 0(AX), X5;    MOVOU 16(AX), X6;   MOVOU 32(AX), X7;   MOVOU 48(AX), X8; \
	MOVOU 64(AX), X9;   MOVOU 80(AX), X10;  MOVOU 96(AX), X11;  MOVOU 112(AX), X12; \
	MOVOU 128(AX), X13; MOVOU 144(AX), X14; MOVOU 160(AX), X15

// func aesCMAC128ChainAbsorb20x4AesNiAsm(
//     roundKeys *[176]byte,
//     seeds     *[4][2]uint64,
//     dataPtrs  *[4]*byte,
//     out       *[4][2]uint64)
TEXT ·aesCMAC128ChainAbsorb20x4AesNiAsm(SB), NOSPLIT, $64-32
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

	// X4 = broadcast(uint64(20)) into both qwords.
	MOVQ $20, R12
	VMOVQ R12, X4
	PUNPCKLQDQ X4, X4
	PXOR X4, X0
	PXOR X4, X1
	PXOR X4, X2
	PXOR X4, X3

	// data[0:16] per lane (full 16-byte block — direct load safe for
	// the 20-byte shape).
	MOVOU 0(R8),  X4
	PXOR X4, X0
	MOVOU 0(R9),  X4
	PXOR X4, X1
	MOVOU 0(R10), X4
	PXOR X4, X2
	MOVOU 0(R11), X4
	PXOR X4, X3

	LOAD_KEYS

	// ===== AES-CMAC round 1 =====
	AES_PERM4

	// ===== Round-2 absorb tail: data[16:20] (4 bytes) into state[0:4] =====
	// Stack-stage zero-padded per-lane 16-byte blocks, then PXOR.
	PXOR X4, X4
	MOVOU X4, 0(SP)
	MOVOU X4, 16(SP)
	MOVOU X4, 32(SP)
	MOVOU X4, 48(SP)

	MOVL 16(R8),  R12
	MOVL R12, 0(SP)
	MOVL 16(R9),  R12
	MOVL R12, 16(SP)
	MOVL 16(R10), R12
	MOVL R12, 32(SP)
	MOVL 16(R11), R12
	MOVL R12, 48(SP)

	MOVOU 0(SP),  X4
	PXOR X4, X0
	MOVOU 16(SP), X4
	PXOR X4, X1
	MOVOU 32(SP), X4
	PXOR X4, X2
	MOVOU 48(SP), X4
	PXOR X4, X3

	// ===== AES-CMAC round 2 =====
	AES_PERM4

	// ===== Writeback =====
	MOVOU X0, 0(DX)
	MOVOU X1, 16(DX)
	MOVOU X2, 32(DX)
	MOVOU X3, 48(DX)

	RET
