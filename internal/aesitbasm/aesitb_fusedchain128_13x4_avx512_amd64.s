//go:build amd64 && !purego && !noitbasm

// VAES ZMM (four lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 13-byte shape, 4 lanes (1 PKCS#7 block, 3 AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain13x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain13x4Avx512Asm(SB), NOSPLIT, $64-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	VMOVDQU ·pad13Tail(SB), X13
	VPINSRQ $0, 0(R8), X13, X4
	VPINSRD $2, 8(R8), X4, X4
	VPINSRB $12, 12(R8), X4, X4
	VMOVDQU X4, 0(SP)
	VPINSRQ $0, 0(R9), X13, X4
	VPINSRD $2, 8(R9), X4, X4
	VPINSRB $12, 12(R9), X4, X4
	VMOVDQU X4, 16(SP)
	VPINSRQ $0, 0(R10), X13, X4
	VPINSRD $2, 8(R10), X4, X4
	VPINSRB $12, 12(R10), X4, X4
	VMOVDQU X4, 32(SP)
	VPINSRQ $0, 0(R11), X13, X4
	VPINSRD $2, 8(R11), X4, X4
	VPINSRB $12, 12(R11), X4, X4
	VMOVDQU X4, 48(SP)

	VBROADCASTI32X4 ·RC+0(SB), Z2
	VBROADCASTI32X4 ·RC+16(SB), Z3
	VBROADCASTI32X4 ·RC+32(SB), Z4
	VBROADCASTI32X4 ·RC+48(SB), Z5
	VBROADCASTI32X4 ·RC+64(SB), Z6
	VBROADCASTI32X4 ·RC+80(SB), Z7
	VBROADCASTI32X4 ·RC+96(SB), Z8
	VBROADCASTI32X4 ·RC+112(SB), Z9
	VBROADCASTI32X4 0(AX), Z13
	VPXORD Z0, Z0, Z0

loop:
	VBROADCASTI32X4 0(BX), Z14
	VPXORD Z13, Z14, Z14
	VPXORD Z14, Z0, Z0
	VPXORD 0(SP), Z0, Z0
	VAESENC Z2, Z0, Z0
	VAESENC Z2, Z0, Z0
	VAESENC Z3, Z0, Z0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU64 Z0, 0(DI)
	VZEROUPPER
	RET
