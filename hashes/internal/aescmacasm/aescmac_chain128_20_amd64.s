//go:build amd64 && !purego

// ZMM-batched fused chain-absorb kernel for AES-CMAC-128 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Lane-parallel layout across 4 pixels: one ZMM register
// holds all four lanes' 16-byte AES states; VAESENC on ZMM operates
// on each 128-bit lane independently using the same broadcast round
// key.
//
// Per-lane absorb construction (matches the public hashes.AESCMAC
// closure bit-exactly):
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
// Two AES-128 permutations per kernel call. Each permutation = 1 ×
// VPXORD (initial AddRoundKey) + 9 × VAESENC + 1 × VAESENCLAST. The
// 11 round keys K0..K10 are pre-broadcast via VBROADCASTI32X4 at
// function entry (each round key replicated to all 4 ZMM lanes).
//
// Register allocation:
//
//	AX        roundKeys ptr (176 bytes = 11 × 16-byte AES round keys)
//	BX        seeds ptr     (4 lanes × 2 uint64; per-lane stride 16 bytes)
//	CX        dataPtrs ptr  (4 lane pointers)
//	DX        out ptr
//	R8..R11   per-lane data ptrs (loaded at entry)
//	R12       scratch GPR for stack staging
//	Z0        AES state across all 4 lanes (16 bytes per lane)
//	Z1..Z11   broadcast round keys K0..K10
//	Z12       absorb data scratch
//
// $64-32: 64 bytes of stack scratch are used to assemble the partial
// 4-byte tail XOR for round 2 (zero-padded to 16 bytes per lane,
// loaded into Z12 and XOR'd into Z0).
//
//	aesCMAC128ChainAbsorb20x4Asm(
//	    roundKeys *[176]byte,       // 11 × 16-byte AES round keys
//	    seeds     *[4][2]uint64,    // per-lane (seed0, seed1)
//	    dataPtrs  *[4]*byte,        // 4 pointers, each to ≥20 bytes
//	    out       *[4][2]uint64)    // output: 16 bytes per lane

#include "textflag.h"

// AES_ROUND — full 10-round AES-128 forward permutation in-place on
// Z0. Uses K0..K10 broadcast in Z1..Z11. Initial AddRoundKey via
// VPXORD with K0; rounds 1..9 via VAESENC with K1..K9; final round
// via VAESENCLAST with K10 (skips MixColumns per FIPS 197 §5.1).
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

// LOAD_ROUND_KEYS — broadcast all 11 AES round keys into Z1..Z11.
// VBROADCASTI32X4 replicates the 16-byte source across all 4 ZMM
// lanes (the same round key applies to every lane in the batched
// dispatch).
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

// func aesCMAC128ChainAbsorb20x4Asm(
//     roundKeys *[176]byte,
//     seeds     *[4][2]uint64,
//     dataPtrs  *[4]*byte,
//     out       *[4][2]uint64)
TEXT ·aesCMAC128ChainAbsorb20x4Asm(SB), NOSPLIT, $64-32
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
	VMOVDQU 0(BX),    X0
	VINSERTI64X2 $1, 16(BX), Y0, Y0
	VINSERTI64X2 $2, 32(BX), Z0, Z0
	VINSERTI64X2 $3, 48(BX), Z0, Z0

	// Z0 ^= broadcast(uint64(20)) per qword.
	// VPBROADCASTQ broadcasts an 8-byte value to all 8 qwords of Z12;
	// XOR'ing into Z0 applies lenTag to BOTH halves of every lane's
	// (seed0, seed1) state slot — bit-exact to the closure's
	// `seed0 ^ lenTag`, `seed1 ^ lenTag` shape.
	MOVQ $20, R12
	VPBROADCASTQ R12, Z12
	VPXORQ Z12, Z0, Z0

	// Z12 = data[lane][0:16] per lane.
	VMOVDQU 0(R8),  X12
	VINSERTI64X2 $1, 0(R9),  Y12, Y12
	VINSERTI64X2 $2, 0(R10), Z12, Z12
	VINSERTI64X2 $3, 0(R11), Z12, Z12

	// Z0 ^= data[0:16] (per lane). Round-1 input state ready.
	VPXORD Z12, Z0, Z0

	// ===== Broadcast round keys =====
	LOAD_ROUND_KEYS

	// ===== AES-CMAC round 1 =====
	AES_ROUND

	// ===== Build round-2 absorb tail in Z12 =====
	// Per-lane: bytes [0..3] = data[16:20], bytes [4..15] = 0.
	// Stack-stage (cleanest pattern): zero 64 bytes, write 4 data
	// bytes at lane offsets 0 / 16 / 32 / 48, then VMOVDQU64 → Z12.
	VPXORD Z12, Z12, Z12
	VMOVDQU64 Z12, 0(SP)

	MOVL 16(R8),  R12
	MOVL R12, 0(SP)
	MOVL 16(R9),  R12
	MOVL R12, 16(SP)
	MOVL 16(R10), R12
	MOVL R12, 32(SP)
	MOVL 16(R11), R12
	MOVL R12, 48(SP)

	VMOVDQU64 0(SP), Z12
	VPXORD Z12, Z0, Z0

	// ===== AES-CMAC round 2 =====
	AES_ROUND

	// ===== Writeback =====
	// out is *[4][2]uint64 = 4 lanes × 16 bytes.
	VEXTRACTI64X2 $0, Z0, 0(DX)
	VEXTRACTI64X2 $1, Z0, 16(DX)
	VEXTRACTI64X2 $2, Z0, 32(DX)
	VEXTRACTI64X2 $3, Z0, 48(DX)

	VZEROUPPER
	RET
