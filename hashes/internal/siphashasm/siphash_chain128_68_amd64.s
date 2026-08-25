//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for SipHash-2-4-128 with
// 68-byte per-lane data input (the ITB SetNonceBits(512) buf shape).
// Same lane-parallel layout as the 20- / 36-byte kernels; 8 full +
// 1 padded compression blocks = 9 absorbs × 2 SipRounds = 18 + 8
// finalization SipRounds = 26 SipRounds total per pixel.
//
//	sipHash24Chain128Absorb68x4Asm(
//	    seeds    *[4][2]uint64,
//	    dataPtrs *[4]*byte,
//	    out      *[4][2]uint64)

#include "textflag.h"

// sipSeedDeint<> — VPERMQ qword indices de-interleaving the
// contiguous seeds block [K0 K1 K0 K1 K0 K1 K0 K1] (lane-major)
// into [K0 K0 K0 K0 | K1 K1 K1 K1]. Public compile-time constant;
// the permute is data-oblivious.
DATA sipSeedDeint<>+0x00(SB)/8, $0
DATA sipSeedDeint<>+0x08(SB)/8, $2
DATA sipSeedDeint<>+0x10(SB)/8, $4
DATA sipSeedDeint<>+0x18(SB)/8, $6
DATA sipSeedDeint<>+0x20(SB)/8, $1
DATA sipSeedDeint<>+0x28(SB)/8, $3
DATA sipSeedDeint<>+0x30(SB)/8, $5
DATA sipSeedDeint<>+0x38(SB)/8, $7
GLOBL sipSeedDeint<>(SB), RODATA|NOPTR, $64

#define SIP_ROUND \
	VPADDQ Y1, Y0, Y0; VPROLQ $13, Y1, Y1; VPXORQ Y0, Y1, Y1; VPROLQ $32, Y0, Y0; \
	VPADDQ Y3, Y2, Y2; VPROLQ $16, Y3, Y3; VPXORQ Y2, Y3, Y3;                      \
	VPADDQ Y3, Y0, Y0; VPROLQ $21, Y3, Y3; VPXORQ Y0, Y3, Y3;                      \
	VPADDQ Y1, Y2, Y2; VPROLQ $17, Y1, Y1; VPXORQ Y2, Y1, Y1; VPROLQ $32, Y2, Y2

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
	VPXORQ Y4, Y3, Y3; \
	SIP_ROUND;         \
	SIP_ROUND;         \
	VPXORQ Y4, Y0, Y0

TEXT ·sipHash24Chain128Absorb68x4Asm(SB), NOSPLIT, $0-24
	MOVQ seeds+0(FP),     BX
	MOVQ dataPtrs+8(FP),  CX
	MOVQ out+16(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// Pack seeds → Y16 (K0), Y17 (K1). One qword permute
	// de-interleaves straight from memory: Y16 = [K0 lanes 0..3 |
	// K1 lanes 0..3]; the K1 half is extracted into Y17 (upper
	// Y17 zeroed by the EVEX Y-form write). Y16 qwords 4..7 carry
	// the K1 copies — don't-care lanes: every state op is
	// element-wise and the writeback reads qwords 0..3 only.
	VMOVDQU64 sipSeedDeint<>(SB), Z19
	VPERMQ 0(BX), Z19, Z16
	VEXTRACTI64X4 $1, Z16, Y17

	// State init.
	MOVQ $0x736f6d6570736575, R12
	VPBROADCASTQ R12, Y0
	VPXORQ Y16, Y0, Y0

	MOVQ $0x646f72616e646f83, R12  // Const1 ^ 0xee
	VPBROADCASTQ R12, Y1
	VPXORQ Y17, Y1, Y1

	MOVQ $0x6c7967656e657261, R12
	VPBROADCASTQ R12, Y2
	VPXORQ Y16, Y2, Y2

	MOVQ $0x7465646279746573, R12
	VPBROADCASTQ R12, Y3
	VPXORQ Y17, Y3, Y3

	// 8 full compression blocks at offsets 0, 8, 16, 24, 32, 40, 48, 56.
	PACK_M_QWORD(0)
	SIP_ABSORB
	PACK_M_QWORD(8)
	SIP_ABSORB
	PACK_M_QWORD(16)
	SIP_ABSORB
	PACK_M_QWORD(24)
	SIP_ABSORB
	PACK_M_QWORD(32)
	SIP_ABSORB
	PACK_M_QWORD(40)
	SIP_ABSORB
	PACK_M_QWORD(48)
	SIP_ABSORB
	PACK_M_QWORD(56)
	SIP_ABSORB

	// Final padded block: m = uint64(data[64:68]) | (68 << 56).
	MOVL 64(R8),  R12
	VMOVQ R12, X4
	MOVL 64(R9),  R12
	VPINSRQ $1, R12, X4, X4
	MOVL 64(R10), R12
	VMOVQ R12, X5
	MOVL 64(R11), R12
	VPINSRQ $1, R12, X5, X5
	VINSERTI64X2 $1, X5, Y4, Y4
	MOVQ $0x4400000000000000, R12  // 68 << 56
	VPBROADCASTQ R12, Y5
	VPXORQ Y5, Y4, Y4
	SIP_ABSORB

	// Finalization first half.
	MOVQ $0xee, R12
	VPBROADCASTQ R12, Y18
	VPXORQ Y18, Y2, Y2
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VPXORQ Y1, Y0, Y18
	VPTERNLOGQ $0x96, Y3, Y2, Y18

	// Finalization second half.
	MOVQ $0xdd, R12
	VPBROADCASTQ R12, Y19
	VPXORQ Y19, Y1, Y1
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VPXORQ Y1, Y0, Y19
	VPTERNLOGQ $0x96, Y3, Y2, Y19

	// Writeback.
	VPEXTRQ $0, X18, 0(DX)
	VPEXTRQ $0, X19, 8(DX)
	VPEXTRQ $1, X18, 16(DX)
	VPEXTRQ $1, X19, 24(DX)

	VEXTRACTI64X2 $1, Y18, X18
	VEXTRACTI64X2 $1, Y19, X19
	VPEXTRQ $0, X18, 32(DX)
	VPEXTRQ $0, X19, 40(DX)
	VPEXTRQ $1, X18, 48(DX)
	VPEXTRQ $1, X19, 56(DX)

	VZEROUPPER
	RET
