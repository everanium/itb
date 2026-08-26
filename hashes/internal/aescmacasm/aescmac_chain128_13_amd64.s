//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for AES-CMAC-128 with 13-byte
// per-lane data input — the Interlocked Barrier PRF fill message shape
// (0x03 || uint64-LE(groupIdx) || 4 reserved). Lane-parallel across 4
// pixels; VAESENC on ZMM advances four independent AES blocks per
// instruction.
//
// Per-lane absorb construction (matches hashes.AESCMAC bit-exactly).
// 13 < 16, so the CBC-MAC chain is a SINGLE block (one AES round) —
// structurally simpler than the 20-byte kernel's two rounds:
//
//	state[0:8]  = seeds[lane][0] ^ uint64(13)  (LE)
//	state[8:16] = seeds[lane][1] ^ uint64(13)
//	state[0:13] ^= data[lane][0:13]            (13-byte XOR, padded to 16)
//	state = AES_K(state)                        (CBC-MAC round 1)
//	out[lane][0] = LE uint64 of state[0:8]
//	out[lane][1] = LE uint64 of state[8:16]
//
// The 13 data bytes are stack-staged (zero 64 bytes, then per lane
// MOVQ 8B + MOVL 4B + MOVBLZX 1B = exactly 13 bytes) so a lane data
// pointer to an exactly-13-byte buffer is never over-read; a 16-byte
// VMOVDQU as in the 20-byte kernel would read 3 bytes past the buffer.
//
// Register allocation: identical to the 20-byte kernel
// (aescmac_chain128_20_amd64.s).
//
// Stack frame: 64 bytes of scratch for the per-lane 13-byte data
// staging (zero-padded to 16 bytes per lane, loaded into Z12).

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

// func aesCMAC128ChainAbsorb13x4Asm(
//     roundKeys *[176]byte,
//     seeds     *[4][2]uint64,
//     dataPtrs  *[4]*byte,
//     out       *[4][2]uint64)
TEXT ·aesCMAC128ChainAbsorb13x4Asm(SB), NOSPLIT, $64-32
	MOVQ roundKeys+0(FP), AX
	MOVQ seeds+8(FP),     BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== State init =====
	// Z0 = seeds[lane] per lane (16 bytes each = (seed0, seed1)).
	VMOVDQU64 0(BX), Z0

	// Z0 ^= broadcast(uint64(13)) per qword (lenTag folded into both
	// halves of every lane's state).
	MOVQ $13, R12
	VPBROADCASTQ R12, Z12
	VPXORQ Z12, Z0, Z0

	// ===== Stage data[0:13] per lane, zero-padded to 16 =====
	// Zero 64 bytes of stack scratch, then write exactly 13 bytes per
	// lane (MOVQ 8B + MOVL 4B + MOVBLZX 1B) at lane offsets 0/16/32/48.
	VPXORD Z12, Z12, Z12
	VMOVDQU64 Z12, 0(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 0(SP)
	MOVL 8(R8),  R12
	MOVL R12, 8(SP)
	MOVBLZX 12(R8), R12
	MOVB R12, 12(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 16(SP)
	MOVL 8(R9),  R12
	MOVL R12, 24(SP)
	MOVBLZX 12(R9), R12
	MOVB R12, 28(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 32(SP)
	MOVL 8(R10), R12
	MOVL R12, 40(SP)
	MOVBLZX 12(R10), R12
	MOVB R12, 44(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 48(SP)
	MOVL 8(R11), R12
	MOVL R12, 56(SP)
	MOVBLZX 12(R11), R12
	MOVB R12, 60(SP)

	VMOVDQU64 0(SP), Z12
	VPXORD Z12, Z0, Z0

	// ===== Broadcast round keys and run the single CBC-MAC round =====
	LOAD_ROUND_KEYS
	AES_ROUND

	// ===== Writeback =====
	VEXTRACTI64X2 $0, Z0, 0(DX)
	VEXTRACTI64X2 $1, Z0, 16(DX)
	VEXTRACTI64X2 $2, Z0, 32(DX)
	VEXTRACTI64X2 $3, Z0, 48(DX)

	VZEROUPPER
	RET
