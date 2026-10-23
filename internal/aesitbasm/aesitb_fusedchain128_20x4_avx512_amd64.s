//go:build amd64 && !purego && !noitbasm

// VAES ZMM (four lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 20-byte shape, 4 lanes (2 PKCS#7 blocks, 4 AES rounds per
// cascade round).
// The padded data blocks are staged once in registers (Z15..), block 0
// with the key folded in and every later block with the round constant
// of the preceding absorb round folded in so it serves as that round's
// key, and every cascade round runs from registers; see aesitbasm_fused.go for the
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

	VBROADCASTI32X4 0(AX), Z13
	VPXORD Z13, Z15, Z15
	VBROADCASTI32X4 ·RC+0(SB), Z13
	VPXORD Z13, Z16, Z16
	VBROADCASTI32X4 ·RC+16(SB), Z2
	VBROADCASTI32X4 ·RC+32(SB), Z3
	VBROADCASTI32X4 ·RC+48(SB), Z4
	VPXORD Z0, Z0, Z0

loop:
	VBROADCASTI32X4 0(BX), Z14
	VPTERNLOGQ $0x96, Z14, Z15, Z0
	VAESENC Z16, Z0, Z0
	VAESENC Z2, Z0, Z0
	VAESENC Z3, Z0, Z0
	VAESENC Z4, Z0, Z0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VEXTRACTI64X2 $1, Z0, 16(DI)
	VEXTRACTI64X2 $2, Z0, 32(DI)
	VEXTRACTI64X2 $3, Z0, 48(DI)
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X3, X3, X3
	VPXORD X4, X4, X4
	VPXORD X5, X5, X5
	VPXORD X6, X6, X6
	VPXORD X7, X7, X7
	VPXORD X8, X8, X8
	VPXORD X9, X9, X9
	VPXORD X10, X10, X10
	VPXORD X11, X11, X11
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13
	VPXORD X14, X14, X14
	VPXORD X15, X15, X15
	VPXORD X16, X16, X16
	VPXORD X17, X17, X17
	VPXORD X18, X18, X18
	VPXORD X19, X19, X19
	VPXORD X20, X20, X20
	VPXORD X21, X21, X21
	VPXORD X22, X22, X22
	VPXORD X23, X23, X23
	VPXORD X24, X24, X24
	VPXORD X25, X25, X25
	VPXORD X26, X26, X26
	VPXORD X27, X27, X27
	VPXORD X28, X28, X28
	VPXORD X29, X29, X29
	VPXORD X30, X30, X30
	VPXORD X31, X31, X31
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ DI, DI
	XORQ R8, R8
	XORQ R9, R9
	XORQ R10, R10
	XORQ R11, R11
	VZEROUPPER
	RET
