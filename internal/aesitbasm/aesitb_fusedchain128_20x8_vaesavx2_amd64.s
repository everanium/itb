//go:build amd64 && !purego && !noitbasm

// VAES YMM (two lanes per register, four state groups) fused ChainHash cascade kernel for AES-ITB-128 at the
// 20-byte shape, 8 lanes (2 PKCS#7 blocks, 4 AES rounds per
// cascade round).
// The padded data blocks are staged once — in registers, with any
// block the register file cannot hold written to the frame as a
// 32-byte store that the round loop reads back at the same width —
// and every cascade round runs from that staging; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain20x8VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)
TEXT ·aesITB128FusedChain20x8VaesAvx2Asm(SB), NOSPLIT, $256-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI

	VMOVDQU ·pad4Tail(SB), X13
	// Lanes 0..3: pairs 0 and 1
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11
	VPINSRD $0, 0(R8), X13, X2
	VPINSRD $1, 4(R8), X2, X2
	VPINSRQ $1, 8(R8), X2, X2
	VPINSRD $0, 0(R9), X13, X4
	VPINSRD $1, 4(R9), X4, X4
	VPINSRQ $1, 8(R9), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 0(SP)
	VPINSRD $0, 0(R10), X13, X2
	VPINSRD $1, 4(R10), X2, X2
	VPINSRQ $1, 8(R10), X2, X2
	VPINSRD $0, 0(R11), X13, X4
	VPINSRD $1, 4(R11), X4, X4
	VPINSRQ $1, 8(R11), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 32(SP)
	VPINSRD $0, 16(R8), X13, X2
	VPINSRD $0, 16(R9), X13, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 128(SP)
	VPINSRD $0, 16(R10), X13, X2
	VPINSRD $0, 16(R11), X13, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 160(SP)
	// Lanes 4..7: pairs 2 and 3
	MOVQ 32(DX), R8
	MOVQ 40(DX), R9
	MOVQ 48(DX), R10
	MOVQ 56(DX), R11
	VPINSRD $0, 0(R8), X13, X2
	VPINSRD $1, 4(R8), X2, X2
	VPINSRQ $1, 8(R8), X2, X2
	VPINSRD $0, 0(R9), X13, X4
	VPINSRD $1, 4(R9), X4, X4
	VPINSRQ $1, 8(R9), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 64(SP)
	VPINSRD $0, 0(R10), X13, X2
	VPINSRD $1, 4(R10), X2, X2
	VPINSRQ $1, 8(R10), X2, X2
	VPINSRD $0, 0(R11), X13, X4
	VPINSRD $1, 4(R11), X4, X4
	VPINSRQ $1, 8(R11), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 96(SP)
	VPINSRD $0, 16(R8), X13, X2
	VPINSRD $0, 16(R9), X13, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 192(SP)
	VPINSRD $0, 16(R10), X13, X2
	VPINSRD $0, 16(R11), X13, X4
	VINSERTI128 $1, X4, Y2, Y2
	VMOVDQU Y2, 224(SP)

	VBROADCASTI128 ·RC+0(SB), Y4
	VBROADCASTI128 ·RC+16(SB), Y5
	VBROADCASTI128 0(AX), Y13
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1
	VPXOR Y2, Y2, Y2
	VPXOR Y3, Y3, Y3

loop:
	VBROADCASTI128 0(BX), Y14
	VPXOR Y13, Y14, Y14
	VPXOR Y14, Y0, Y0
	VPXOR Y14, Y1, Y1
	VPXOR Y14, Y2, Y2
	VPXOR Y14, Y3, Y3
	VPXOR 0(SP), Y0, Y0
	VPXOR 32(SP), Y1, Y1
	VPXOR 64(SP), Y2, Y2
	VPXOR 96(SP), Y3, Y3
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1; VAESENC Y4, Y2, Y2; VAESENC Y4, Y3, Y3
	VPXOR 128(SP), Y0, Y0
	VPXOR 160(SP), Y1, Y1
	VPXOR 192(SP), Y2, Y2
	VPXOR 224(SP), Y3, Y3
	VAESENC Y5, Y0, Y0; VAESENC Y5, Y1, Y1; VAESENC Y5, Y2, Y2; VAESENC Y5, Y3, Y3
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1; VAESENC Y4, Y2, Y2; VAESENC Y4, Y3, Y3
	VAESENC Y5, Y0, Y0; VAESENC Y5, Y1, Y1; VAESENC Y5, Y2, Y2; VAESENC Y5, Y3, Y3
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VEXTRACTI128 $1, Y0, 16(DI)
	VMOVDQU X1, 32(DI)
	VEXTRACTI128 $1, Y1, 48(DI)
	VMOVDQU X2, 64(DI)
	VEXTRACTI128 $1, Y2, 80(DI)
	VMOVDQU X3, 96(DI)
	VEXTRACTI128 $1, Y3, 112(DI)
	VZEROUPPER
	RET
