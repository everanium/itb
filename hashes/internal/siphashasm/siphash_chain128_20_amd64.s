//go:build amd64 && !purego

// ZMM-batched fused chain-absorb kernel for SipHash-2-4-128 with
// 20-byte per-lane data input (the ITB SetNonceBits(128) buf shape —
// default config). Lane-parallel layout: 4 lanes × 4 SipHash state
// words held in qwords 0..3 of Z0..Z3 (one ZMM per state word, lane
// = qword index).
//
// Per-lane absorb construction (matches the public hashes.SipHash24
// closure / dchest/siphash.Hash128 bit-exactly):
//
//	K0, K1 = seeds[lane][0], seeds[lane][1]
//	v0 = K0 ^ 0x736f6d6570736575
//	v1 = K1 ^ 0x646f72616e646f83  (Const1 ^ 0xee, SipHash-128 init fold)
//	v2 = K0 ^ 0x6c7967656e657261
//	v3 = K1 ^ 0x7465646279746573
//
//	Compress block at offset 0:  m = LE u64 of data[0:8]
//	  v3 ^= m; SipRound × 2; v0 ^= m
//	Compress block at offset 8:  m = LE u64 of data[8:16]
//	  v3 ^= m; SipRound × 2; v0 ^= m
//	Final padded block:          m = uint64(data[16:20]) | (20 << 56)
//	  v3 ^= m; SipRound × 2; v0 ^= m
//
//	Finalization (SipHash-128 first half):
//	  v2 ^= 0xee; SipRound × 4
//	  out0 = v0 ^ v1 ^ v2 ^ v3
//	Finalization (SipHash-128 second half):
//	  v1 ^= 0xdd; SipRound × 4
//	  out1 = v0 ^ v1 ^ v2 ^ v3
//
// 14 SipRounds total per pixel. Z0..Z3 hold the state across all
// rounds; Z4 holds the current message word (per-lane LE u64);
// Z16 / Z17 hold the per-lane (K0, K1) seed pack (used at state
// init only); Z18 / Z19 hold the per-half output during finalization.
//
//	sipHash24Chain128Absorb20x4Asm(
//	    seeds    *[4][2]uint64,
//	    dataPtrs *[4]*byte,
//	    out      *[4][2]uint64)

#include "textflag.h"

// SIP_ROUND — one full SipHash round, lane-parallel on 4 pixels.
// Spec rotates: 13, 32, 16, 21, 17, 32 (left rotates — VPROLQ).
#define SIP_ROUND \
	VPADDQ Z1, Z0, Z0; VPROLQ $13, Z1, Z1; VPXORQ Z0, Z1, Z1; VPROLQ $32, Z0, Z0; \
	VPADDQ Z3, Z2, Z2; VPROLQ $16, Z3, Z3; VPXORQ Z2, Z3, Z3;                      \
	VPADDQ Z3, Z0, Z0; VPROLQ $21, Z3, Z3; VPXORQ Z0, Z3, Z3;                      \
	VPADDQ Z1, Z2, Z2; VPROLQ $17, Z1, Z1; VPXORQ Z2, Z1, Z1; VPROLQ $32, Z2, Z2

// PACK_M_QWORD — load LE u64 from each lane data ptr at offset
// `off` into Z4 qwords 0..3. Upper qwords 4..7 of Z4 are zeroed
// implicitly by the VINSERTI64X2 Y-form write semantics.
#define PACK_M_QWORD(off) \
	MOVQ off(R8),  R12; \
	VMOVQ R12, X4; \
	MOVQ off(R9),  R12; \
	VPINSRQ $1, R12, X4, X4; \
	MOVQ off(R10), R12; \
	VMOVQ R12, X5; \
	MOVQ off(R11), R12; \
	VPINSRQ $1, R12, X5, X5; \
	VINSERTI64X2 $1, X5, Y4, Y4

// SIP_ABSORB — one full SipHash compression block: v3 ^= m;
// SipRound × 2; v0 ^= m. Caller pre-loads m into Z4.
#define SIP_ABSORB \
	VPXORQ Z4, Z3, Z3; \
	SIP_ROUND;         \
	SIP_ROUND;         \
	VPXORQ Z4, Z0, Z0

TEXT ·sipHash24Chain128Absorb20x4Asm(SB), NOSPLIT, $0-24
	MOVQ seeds+0(FP),     BX
	MOVQ dataPtrs+8(FP),  CX
	MOVQ out+16(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== Pack per-lane seeds into Z16 (K0) / Z17 (K1) =====
	// Z16 qwords 0..3 = seeds[0..3][0]
	MOVQ 0(BX),  R12
	VMOVQ R12, X16
	MOVQ 16(BX), R12
	VPINSRQ $1, R12, X16, X16
	MOVQ 32(BX), R12
	VMOVQ R12, X18
	MOVQ 48(BX), R12
	VPINSRQ $1, R12, X18, X18
	VINSERTI64X2 $1, X18, Y16, Y16

	// Z17 qwords 0..3 = seeds[0..3][1]
	MOVQ 8(BX),  R12
	VMOVQ R12, X17
	MOVQ 24(BX), R12
	VPINSRQ $1, R12, X17, X17
	MOVQ 40(BX), R12
	VMOVQ R12, X18
	MOVQ 56(BX), R12
	VPINSRQ $1, R12, X18, X18
	VINSERTI64X2 $1, X18, Y17, Y17

	// ===== Initialize state v0..v3 =====
	MOVQ $0x736f6d6570736575, R12
	VPBROADCASTQ R12, Z0
	VPXORQ Z16, Z0, Z0

	MOVQ $0x646f72616e646f83, R12  // Const1 ^ 0xee
	VPBROADCASTQ R12, Z1
	VPXORQ Z17, Z1, Z1

	MOVQ $0x6c7967656e657261, R12
	VPBROADCASTQ R12, Z2
	VPXORQ Z16, Z2, Z2

	MOVQ $0x7465646279746573, R12
	VPBROADCASTQ R12, Z3
	VPXORQ Z17, Z3, Z3

	// ===== Compression block 1: data[0:8] =====
	PACK_M_QWORD(0)
	SIP_ABSORB

	// ===== Compression block 2: data[8:16] =====
	PACK_M_QWORD(8)
	SIP_ABSORB

	// ===== Final padded block: m = uint64(data[16:20]) | (20 << 56) =====
	// MOVL zero-extends 32-bit data into u64; broadcast (lenTag<<56)
	// XOR'd in afterwards sets the top byte.
	MOVL 16(R8),  R12
	VMOVQ R12, X4
	MOVL 16(R9),  R12
	VPINSRQ $1, R12, X4, X4
	MOVL 16(R10), R12
	VMOVQ R12, X5
	MOVL 16(R11), R12
	VPINSRQ $1, R12, X5, X5
	VINSERTI64X2 $1, X5, Y4, Y4
	MOVQ $0x1400000000000000, R12  // 20 << 56
	VPBROADCASTQ R12, Z5
	VPXORQ Z5, Z4, Z4
	SIP_ABSORB

	// ===== Finalization first half =====
	MOVQ $0xee, R12
	VPBROADCASTQ R12, Z18
	VPXORQ Z18, Z2, Z2
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	// out0 per lane = v0 ^ v1 ^ v2 ^ v3, capture in Z18.
	VMOVDQA64 Z0, Z18
	VPXORQ Z1, Z18, Z18
	VPXORQ Z2, Z18, Z18
	VPXORQ Z3, Z18, Z18

	// ===== Finalization second half =====
	MOVQ $0xdd, R12
	VPBROADCASTQ R12, Z19
	VPXORQ Z19, Z1, Z1
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	// out1 per lane = v0 ^ v1 ^ v2 ^ v3, capture in Z19.
	VMOVDQA64 Z0, Z19
	VPXORQ Z1, Z19, Z19
	VPXORQ Z2, Z19, Z19
	VPXORQ Z3, Z19, Z19

	// ===== Writeback =====
	// out *[4][2]uint64: lane k at byte offset k*16,
	// with [0] = out0, [1] = out1.
	VPEXTRQ $0, X18, 0(DX)
	VPEXTRQ $0, X19, 8(DX)
	VPEXTRQ $1, X18, 16(DX)
	VPEXTRQ $1, X19, 24(DX)

	VEXTRACTI64X2 $1, Z18, X18
	VEXTRACTI64X2 $1, Z19, X19
	VPEXTRQ $0, X18, 32(DX)
	VPEXTRQ $0, X19, 40(DX)
	VPEXTRQ $1, X18, 48(DX)
	VPEXTRQ $1, X19, 56(DX)

	VZEROUPPER
	RET
