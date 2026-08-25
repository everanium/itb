//go:build amd64 && !purego && !noitbasm

// YMM-batched fused chain-absorb kernel for SipHash-2-4-128 with
// 13-byte per-lane data input — the Interlocked Barrier PRF fill
// message shape (0x03 || uint64-LE(groupIdx) || 4 reserved).
// Lane-parallel: 4 lanes × 4 SipHash state words in qwords 0..3 of
// Y0..Y3.
//
// 13 bytes = one full 8-byte compression block (data[0:8]) plus the
// final padded block (data[8:13], 5 bytes, with lenTag 13 in the top
// byte) — one fewer block than the 20-byte kernel:
//
//	K0, K1 = seeds[lane][0], seeds[lane][1]
//	v0 = K0 ^ 0x736f6d6570736575
//	v1 = K1 ^ 0x646f72616e646f83
//	v2 = K0 ^ 0x6c7967656e657261
//	v3 = K1 ^ 0x7465646279746573
//
//	Compress block at offset 0:  m = LE u64 of data[0:8]
//	  v3 ^= m; SipRound × 2; v0 ^= m
//	Final padded block:          m = uint64(data[8:13]) | (13 << 56)
//	  v3 ^= m; SipRound × 2; v0 ^= m
//
//	Finalization identical to the 20-byte kernel.
//
// The final block loads exactly 5 data bytes per lane (MOVL 8(Rx) +
// MOVBLZX 12(Rx)); block 1 reads data[0:8]. Total 13 bytes read, so a
// lane data pointer to an exactly-13-byte buffer is never over-read.
//
//	sipHash24Chain128Absorb13x4Asm(
//	    seeds    *[4][2]uint64,
//	    dataPtrs *[4]*byte,
//	    out      *[4][2]uint64)

#include "textflag.h"

DATA sipSeedDeint13<>+0x00(SB)/8, $0
DATA sipSeedDeint13<>+0x08(SB)/8, $2
DATA sipSeedDeint13<>+0x10(SB)/8, $4
DATA sipSeedDeint13<>+0x18(SB)/8, $6
DATA sipSeedDeint13<>+0x20(SB)/8, $1
DATA sipSeedDeint13<>+0x28(SB)/8, $3
DATA sipSeedDeint13<>+0x30(SB)/8, $5
DATA sipSeedDeint13<>+0x38(SB)/8, $7
GLOBL sipSeedDeint13<>(SB), RODATA|NOPTR, $64

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

TEXT ·sipHash24Chain128Absorb13x4Asm(SB), NOSPLIT, $0-24
	MOVQ seeds+0(FP),     BX
	MOVQ dataPtrs+8(FP),  CX
	MOVQ out+16(FP),      DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== Pack per-lane seeds into Y16 (K0) / Y17 (K1) =====
	VMOVDQU64 sipSeedDeint13<>(SB), Z19
	VPERMQ 0(BX), Z19, Z16
	VEXTRACTI64X4 $1, Z16, Y17

	// ===== Initialize state v0..v3 =====
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

	// ===== Compression block 1: data[0:8] =====
	PACK_M_QWORD(0)
	SIP_ABSORB

	// ===== Final padded block: m = uint64(data[8:13]) | (13 << 56) =====
	// Per lane: MOVL 8(Rx) (data[8:12]) into low 32 + MOVBLZX 12(Rx)
	// (data[12]) shifted into byte 4 = exactly 5 data bytes.
	MOVL 8(R8),  R12
	MOVBLZX 12(R8), R13
	SHLQ $32, R13
	ORQ R13, R12
	VMOVQ R12, X4
	MOVL 8(R9),  R12
	MOVBLZX 12(R9), R13
	SHLQ $32, R13
	ORQ R13, R12
	VPINSRQ $1, R12, X4, X4
	MOVL 8(R10), R12
	MOVBLZX 12(R10), R13
	SHLQ $32, R13
	ORQ R13, R12
	VMOVQ R12, X5
	MOVL 8(R11), R12
	MOVBLZX 12(R11), R13
	SHLQ $32, R13
	ORQ R13, R12
	VPINSRQ $1, R12, X5, X5
	VINSERTI64X2 $1, X5, Y4, Y4
	MOVQ $0x0d00000000000000, R12  // 13 << 56
	VPBROADCASTQ R12, Y5
	VPXORQ Y5, Y4, Y4
	SIP_ABSORB

	// ===== Finalization first half =====
	MOVQ $0xee, R12
	VPBROADCASTQ R12, Y18
	VPXORQ Y18, Y2, Y2
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VPXORQ Y1, Y0, Y18
	VPTERNLOGQ $0x96, Y3, Y2, Y18

	// ===== Finalization second half =====
	MOVQ $0xdd, R12
	VPBROADCASTQ R12, Y19
	VPXORQ Y19, Y1, Y1
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VPXORQ Y1, Y0, Y19
	VPTERNLOGQ $0x96, Y3, Y2, Y19

	// ===== Writeback =====
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
