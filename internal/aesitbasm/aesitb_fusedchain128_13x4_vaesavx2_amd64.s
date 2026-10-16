//go:build amd64 && !purego && !noitbasm

// VAES YMM (two lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 13-byte shape, 4 lanes (1 PKCS#7 block, 3 AES rounds per
// cascade round).
// The padded data blocks are staged once in registers, block 0 with
// the key folded in and every later block with the round constant of
// the preceding absorb round folded in so it serves as that round's
// key, and every cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain13x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain13x4VaesAvx2Asm(SB), NOSPLIT, $0-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	VMOVDQU ·pad13Tail(SB), X5
	VPINSRQ $0, 0(R8), X5, X2
	VPINSRD $2, 8(R8), X2, X2
	VPINSRB $12, 12(R8), X2, X2
	VPINSRQ $0, 0(R9), X5, X4
	VPINSRD $2, 8(R9), X4, X4
	VPINSRB $12, 12(R9), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VPINSRQ $0, 0(R10), X5, X6
	VPINSRD $2, 8(R10), X6, X6
	VPINSRB $12, 12(R10), X6, X6
	VPINSRQ $0, 0(R11), X5, X4
	VPINSRD $2, 8(R11), X4, X4
	VPINSRB $12, 12(R11), X4, X4
	VINSERTI128 $1, X4, Y6, Y6

	VBROADCASTI128 0(AX), Y14
	VPXOR Y14, Y2, Y2
	VPXOR Y14, Y6, Y6
	VBROADCASTI128 ·RC+0(SB), Y3
	VBROADCASTI128 ·RC+16(SB), Y4
	VBROADCASTI128 ·RC+32(SB), Y5
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1

loop:
	VBROADCASTI128 0(BX), Y14
	VPXOR Y14, Y0, Y0
	VPXOR Y14, Y1, Y1
	VPXOR Y2, Y0, Y0
	VPXOR Y6, Y1, Y1
	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1
	VAESENC Y5, Y0, Y0; VAESENC Y5, Y1, Y1
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VEXTRACTI128 $1, Y0, 16(DI)
	VMOVDQU X1, 32(DI)
	VEXTRACTI128 $1, Y1, 48(DI)
	VZEROUPPER
	RET
