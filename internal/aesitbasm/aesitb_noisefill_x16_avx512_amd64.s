//go:build amd64 && !purego && !noitbasm

// VAES ZMM (four blocks per register, needs VAES + AVX-512) AES-ITB
// noise filler kernel, sixteen blocks per iteration. Lane l of register
// Zj carries counter (lo + 4j + l, hi): the broadcast counter base plus
// the increment table quad at offset 64·j, one XOR with the broadcast
// pre-whitening block C, five VAESENC rounds under the broadcast
// RK[0..4], one 64-byte store. The sixteen blocks are independent AES
// chains. The kernel is reached only through ITB_FORCE_HASH_TIER=avx512;
// auto-dispatch selects the VAES YMM kernel on every VAES host, because
// this kernel's throughput matches it within run-to-run spread on the
// hosts measured (Rocket Lake, Sapphire Rapids, Zen 4) and the YMM
// kernel keeps the noise fill off the ZMM register file. See
// noisefill.go for the construction and the in-package parity tests for
// the bit-exact pin against the pure-Go reference.
//
// Register allocation:
//   Z0..Z3   the four state registers (four blocks each)
//   Z8       counter base [lo, hi] in all four lanes, advanced by sixteen per iteration
//   Z9       C (pre-whitening), broadcast
//   Z10..Z14 RK[0..4], broadcast
//   Z15      increment [16, 0] in all four lanes
//
// Frame: none. VZEROALL before RET wipes every state, the counter and
// the schedule from the register file and clears the upper halves.

#include "textflag.h"

#define ROUND4(RK) \
	VAESENC RK, Z0, Z0; \
	VAESENC RK, Z1, Z1; \
	VAESENC RK, Z2, Z2; \
	VAESENC RK, Z3, Z3

// func noiseFillX16Avx512Asm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
TEXT ·noiseFillX16Avx512Asm(SB), NOSPLIT, $0-40
	MOVQ sched+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ nblk+16(FP), CX
	MOVQ lo+24(FP), SI
	MOVQ hi+32(FP), DX
	VMOVQ SI, X8
	VPINSRQ $1, DX, X8, X8
	VSHUFI64X2 $0x00, Z8, Z8, Z8
	VBROADCASTI32X4 0(AX), Z9
	VBROADCASTI32X4 16(AX), Z10
	VBROADCASTI32X4 32(AX), Z11
	VBROADCASTI32X4 48(AX), Z12
	VBROADCASTI32X4 64(AX), Z13
	VBROADCASTI32X4 80(AX), Z14
	VBROADCASTI32X4 ·noiseIncTab+256(SB), Z15

loop:
	VPADDQ ·noiseIncTab+0(SB), Z8, Z0
	VPADDQ ·noiseIncTab+64(SB), Z8, Z1
	VPADDQ ·noiseIncTab+128(SB), Z8, Z2
	VPADDQ ·noiseIncTab+192(SB), Z8, Z3
	VPXORQ Z9, Z0, Z0
	VPXORQ Z9, Z1, Z1
	VPXORQ Z9, Z2, Z2
	VPXORQ Z9, Z3, Z3
	ROUND4(Z10)
	ROUND4(Z11)
	ROUND4(Z12)
	ROUND4(Z13)
	ROUND4(Z14)
	VMOVDQU64 Z0, 0(DI)
	VMOVDQU64 Z1, 64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VPADDQ Z15, Z8, Z8
	ADDQ $256, DI
	SUBQ $16, CX
	JNZ loop
	// VZEROALL wipes every state, the counter and the key-derived
	// schedule from the register file (ZMM0..ZMM15 in full) and leaves
	// the upper halves clean, which also serves as the VZEROUPPER on
	// exit.
	VZEROALL
	RET
