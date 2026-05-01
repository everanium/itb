//go:build amd64 && !purego

// ZMM-batched fused chain-absorb kernel for SipHash-2-4-128 with
// 36-byte per-lane data input (the ITB SetNonceBits(256) buf shape).
// Same lane-parallel layout as the 20-byte kernel; differs only in
// the number of compression blocks: 4 full + 1 padded = 5 absorbs ×
// 2 SipRounds = 10 + 8 finalization SipRounds = 18 SipRounds total
// per pixel.
//
//	sipHash24Chain128Absorb36x4Asm(
//	    seeds    *[4][2]uint64,
//	    dataPtrs *[4]*byte,
//	    out      *[4][2]uint64)

#include "textflag.h"

#define SIP_ROUND \
	VPADDQ Z1, Z0, Z0; VPROLQ $13, Z1, Z1; VPXORQ Z0, Z1, Z1; VPROLQ $32, Z0, Z0; \
	VPADDQ Z3, Z2, Z2; VPROLQ $16, Z3, Z3; VPXORQ Z2, Z3, Z3;                      \
	VPADDQ Z3, Z0, Z0; VPROLQ $21, Z3, Z3; VPXORQ Z0, Z3, Z3;                      \
	VPADDQ Z1, Z2, Z2; VPROLQ $17, Z1, Z1; VPXORQ Z2, Z1, Z1; VPROLQ $32, Z2, Z2

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

#define SIP_ABSORB \
	VPXORQ Z4, Z3, Z3; \
	SIP_ROUND;         \
	SIP_ROUND;         \
	VPXORQ Z4, Z0, Z0

TEXT ·sipHash24Chain128Absorb36x4Asm(SB), NOSPLIT, $0-24
	MOVQ seeds+0(FP),     BX
	MOVQ dataPtrs+8(FP),  CX
	MOVQ out+16(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// Pack seeds → Z16 (K0), Z17 (K1).
	MOVQ 0(BX),  R12
	VMOVQ R12, X16
	MOVQ 16(BX), R12
	VPINSRQ $1, R12, X16, X16
	MOVQ 32(BX), R12
	VMOVQ R12, X18
	MOVQ 48(BX), R12
	VPINSRQ $1, R12, X18, X18
	VINSERTI64X2 $1, X18, Y16, Y16

	MOVQ 8(BX),  R12
	VMOVQ R12, X17
	MOVQ 24(BX), R12
	VPINSRQ $1, R12, X17, X17
	MOVQ 40(BX), R12
	VMOVQ R12, X18
	MOVQ 56(BX), R12
	VPINSRQ $1, R12, X18, X18
	VINSERTI64X2 $1, X18, Y17, Y17

	// State init.
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

	// 4 full compression blocks at offsets 0, 8, 16, 24.
	PACK_M_QWORD(0)
	SIP_ABSORB
	PACK_M_QWORD(8)
	SIP_ABSORB
	PACK_M_QWORD(16)
	SIP_ABSORB
	PACK_M_QWORD(24)
	SIP_ABSORB

	// Final padded block: m = uint64(data[32:36]) | (36 << 56).
	MOVL 32(R8),  R12
	VMOVQ R12, X4
	MOVL 32(R9),  R12
	VPINSRQ $1, R12, X4, X4
	MOVL 32(R10), R12
	VMOVQ R12, X5
	MOVL 32(R11), R12
	VPINSRQ $1, R12, X5, X5
	VINSERTI64X2 $1, X5, Y4, Y4
	MOVQ $0x2400000000000000, R12  // 36 << 56
	VPBROADCASTQ R12, Z5
	VPXORQ Z5, Z4, Z4
	SIP_ABSORB

	// Finalization first half.
	MOVQ $0xee, R12
	VPBROADCASTQ R12, Z18
	VPXORQ Z18, Z2, Z2
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VMOVDQA64 Z0, Z18
	VPXORQ Z1, Z18, Z18
	VPXORQ Z2, Z18, Z18
	VPXORQ Z3, Z18, Z18

	// Finalization second half.
	MOVQ $0xdd, R12
	VPBROADCASTQ R12, Z19
	VPXORQ Z19, Z1, Z1
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VMOVDQA64 Z0, Z19
	VPXORQ Z1, Z19, Z19
	VPXORQ Z2, Z19, Z19
	VPXORQ Z3, Z19, Z19

	// Writeback.
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
