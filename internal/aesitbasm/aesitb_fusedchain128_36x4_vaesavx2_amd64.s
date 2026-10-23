//go:build amd64 && !purego && !noitbasm

// VAES YMM (two lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 36-byte shape, 4 lanes (3 PKCS#7 blocks, 5 AES rounds per
// cascade round).
// The padded data blocks are staged once in registers, block 0 with
// the key folded in and every later block with the round constant of
// the preceding absorb round folded in so it serves as that round's
// key, and every cascade round runs from registers; see aesitbasm_fused.go for the
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

	VMOVDQU ·pad4Tail(SB), X5
	VPINSRD $0, 0(R8), X5, X2
	VPINSRD $1, 4(R8), X2, X2
	VPINSRQ $1, 8(R8), X2, X2
	VPINSRD $0, 0(R9), X5, X4
	VPINSRD $1, 4(R9), X4, X4
	VPINSRQ $1, 8(R9), X4, X4
	VINSERTI128 $1, X4, Y2, Y2
	VPINSRD $0, 0(R10), X5, X6
	VPINSRD $1, 4(R10), X6, X6
	VPINSRQ $1, 8(R10), X6, X6
	VPINSRD $0, 0(R11), X5, X4
	VPINSRD $1, 4(R11), X4, X4
	VPINSRQ $1, 8(R11), X4, X4
	VINSERTI128 $1, X4, Y6, Y6
	VMOVDQU 16(R8), X7
	VINSERTI128 $1, 16(R9), Y7, Y7
	VMOVDQU 16(R10), X8
	VINSERTI128 $1, 16(R11), Y8, Y8
	VPINSRD $0, 32(R8), X5, X9
	VPINSRD $0, 32(R9), X5, X4
	VINSERTI128 $1, X4, Y9, Y9
	VPINSRD $0, 32(R10), X5, X10
	VPINSRD $0, 32(R11), X5, X4
	VINSERTI128 $1, X4, Y10, Y10

	VBROADCASTI128 0(AX), Y14
	VPXOR Y14, Y2, Y2
	VPXOR Y14, Y6, Y6
	VBROADCASTI128 ·RC+0(SB), Y14
	VPXOR Y14, Y7, Y7
	VPXOR Y14, Y8, Y8
	VBROADCASTI128 ·RC+16(SB), Y14
	VPXOR Y14, Y9, Y9
	VPXOR Y14, Y10, Y10
	VBROADCASTI128 ·RC+32(SB), Y3
	VBROADCASTI128 ·RC+48(SB), Y4
	VBROADCASTI128 ·RC+64(SB), Y5
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1

loop:
	VBROADCASTI128 0(BX), Y14
	VPXOR Y14, Y0, Y0
	VPXOR Y14, Y1, Y1
	VPXOR Y2, Y0, Y0
	VPXOR Y6, Y1, Y1
	VAESENC Y7, Y0, Y0; VAESENC Y8, Y1, Y1
	VAESENC Y9, Y0, Y0; VAESENC Y10, Y1, Y1
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
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1
	VPXOR Y2, Y2, Y2
	VPXOR Y3, Y3, Y3
	VPXOR Y4, Y4, Y4
	VPXOR Y5, Y5, Y5
	VPXOR Y6, Y6, Y6
	VPXOR Y7, Y7, Y7
	VPXOR Y8, Y8, Y8
	VPXOR Y9, Y9, Y9
	VPXOR Y10, Y10, Y10
	VPXOR Y11, Y11, Y11
	VPXOR Y12, Y12, Y12
	VPXOR Y13, Y13, Y13
	VPXOR Y14, Y14, Y14
	VPXOR Y15, Y15, Y15
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
