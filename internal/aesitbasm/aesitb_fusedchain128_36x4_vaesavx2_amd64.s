//go:build amd64 && !purego && !noitbasm

// VAES YMM (two lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 36-byte shape, 4 lanes (3 PKCS#7 blocks, 5 AES rounds per
// cascade round).
// The padded data blocks are staged once — in registers, with any
// block the register file cannot hold written to the frame as a
// 32-byte store that the round loop reads back at the same width —
// and every cascade round runs from that staging; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain36x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain36x4VaesAvx2Asm(SB), NOSPLIT, $0-40
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
	VPINSRD $0, 0(R8), X13, X2
	VPINSRD $1, 4(R8), X2, X2
	VPINSRQ $1, 8(R8), X2, X2
	VPINSRD $0, 0(R9), X13, X4
	VPINSRD $1, 4(R9), X4, X4
	VPINSRQ $1, 8(R9), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VPINSRD $0, 0(R10), X13, X6
	VPINSRD $1, 4(R10), X6, X6
	VPINSRQ $1, 8(R10), X6, X6
	VPINSRD $0, 0(R11), X13, X4
	VPINSRD $1, 4(R11), X4, X4
	VPINSRQ $1, 8(R11), X4, X4
	VINSERTI128 $1, X4, Y6, Y6
	VMOVDQU 16(R8), X7
	VINSERTI128 $1, 16(R9), Y7, Y7
	VMOVDQU 16(R10), X8
	VINSERTI128 $1, 16(R11), Y8, Y8
	VPINSRD $0, 32(R8), X13, X9
	VPINSRD $0, 32(R9), X13, X4
	VINSERTI128 $1, X4, Y9, Y9
	VPINSRD $0, 32(R10), X13, X10
	VPINSRD $0, 32(R11), X13, X4
	VINSERTI128 $1, X4, Y10, Y10

	VBROADCASTI128 ·RC+0(SB), Y3
	VBROADCASTI128 ·RC+16(SB), Y4
	VBROADCASTI128 ·RC+32(SB), Y5
	VBROADCASTI128 0(AX), Y13
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1

loop:
	VBROADCASTI128 0(BX), Y14
	VPXOR Y13, Y14, Y14
	VPXOR Y14, Y0, Y0
	VPXOR Y14, Y1, Y1
	VPXOR Y2, Y0, Y0
	VPXOR Y6, Y1, Y1
	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1
	VPXOR Y7, Y0, Y0
	VPXOR Y8, Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1
	VPXOR Y9, Y0, Y0
	VPXOR Y10, Y1, Y1
	VAESENC Y5, Y0, Y0; VAESENC Y5, Y1, Y1
	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VEXTRACTI128 $1, Y0, 16(DI)
	VMOVDQU X1, 32(DI)
	VEXTRACTI128 $1, Y1, 48(DI)
	VZEROUPPER
	RET
