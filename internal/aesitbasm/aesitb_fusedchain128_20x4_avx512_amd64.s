//go:build amd64 && !purego && !noitbasm

// VAES ZMM (four lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 20-byte shape, 4 lanes (2 PKCS#7 blocks, 4 AES rounds per
// cascade round).
// The padded data blocks are staged once in registers (Z15..) and
// every cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain20x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain20x4Avx512Asm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	VMOVDQU ·pad4Tail(SB), X13
	VPINSRD $0, 0(R8), X13, X4
	VPINSRD $1, 4(R8), X4, X4
	VPINSRQ $1, 8(R8), X4, X4
	VINSERTI64X2 $0, X4, Z15, Z15
	VPINSRD $0, 0(R9), X13, X4
	VPINSRD $1, 4(R9), X4, X4
	VPINSRQ $1, 8(R9), X4, X4
	VINSERTI64X2 $1, X4, Z15, Z15
	VPINSRD $0, 0(R10), X13, X4
	VPINSRD $1, 4(R10), X4, X4
	VPINSRQ $1, 8(R10), X4, X4
	VINSERTI64X2 $2, X4, Z15, Z15
	VPINSRD $0, 0(R11), X13, X4
	VPINSRD $1, 4(R11), X4, X4
	VPINSRQ $1, 8(R11), X4, X4
	VINSERTI64X2 $3, X4, Z15, Z15
	VPINSRD $0, 16(R8), X13, X4
	VINSERTI64X2 $0, X4, Z16, Z16
	VPINSRD $0, 16(R9), X13, X4
	VINSERTI64X2 $1, X4, Z16, Z16
	VPINSRD $0, 16(R10), X13, X4
	VINSERTI64X2 $2, X4, Z16, Z16
	VPINSRD $0, 16(R11), X13, X4
	VINSERTI64X2 $3, X4, Z16, Z16

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
	VPXORD Z15, Z0, Z0
	VAESENC Z2, Z0, Z0
	VPXORD Z16, Z0, Z0
	VAESENC Z3, Z0, Z0
	VAESENC Z2, Z0, Z0
	VAESENC Z3, Z0, Z0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VEXTRACTI64X2 $1, Z0, 16(DI)
	VEXTRACTI64X2 $2, Z0, 32(DI)
	VEXTRACTI64X2 $3, Z0, 48(DI)
	VZEROUPPER
	RET
