//go:build amd64 && !purego && !noitbasm

// VAES YMM (two lanes per register) fused ChainHash cascade kernel for AES-ITB-128 at the
// 36-byte shape, 4 lanes (3 PKCS#7 blocks, 5 AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain36x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain36x4VaesAvx2Asm(SB), NOSPLIT, $192-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	VMOVDQU 0(R8), X4
	VMOVDQU X4, 0(SP)
	VMOVDQU 0(R9), X4
	VMOVDQU X4, 16(SP)
	VMOVDQU 0(R10), X4
	VMOVDQU X4, 32(SP)
	VMOVDQU 0(R11), X4
	VMOVDQU X4, 48(SP)
	VMOVDQU 16(R8), X4
	VMOVDQU X4, 64(SP)
	VMOVDQU 16(R9), X4
	VMOVDQU X4, 80(SP)
	VMOVDQU 16(R10), X4
	VMOVDQU X4, 96(SP)
	VMOVDQU 16(R11), X4
	VMOVDQU X4, 112(SP)
	VMOVDQU ·pad4Tail(SB), X13
	VPINSRD $0, 32(R8), X13, X4
	VMOVDQU X4, 128(SP)
	VPINSRD $0, 32(R9), X13, X4
	VMOVDQU X4, 144(SP)
	VPINSRD $0, 32(R10), X13, X4
	VMOVDQU X4, 160(SP)
	VPINSRD $0, 32(R11), X13, X4
	VMOVDQU X4, 176(SP)

	VBROADCASTI128 ·RC+0(SB), Y3
	VBROADCASTI128 ·RC+16(SB), Y4
	VBROADCASTI128 ·RC+32(SB), Y5
	VBROADCASTI128 ·RC+48(SB), Y6
	VBROADCASTI128 ·RC+64(SB), Y7
	VBROADCASTI128 ·RC+80(SB), Y8
	VBROADCASTI128 ·RC+96(SB), Y9
	VBROADCASTI128 ·RC+112(SB), Y10
	VBROADCASTI128 0(AX), Y13
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1

loop:
	VBROADCASTI128 0(BX), Y14
	VPXOR Y13, Y14, Y14
	VPXOR Y14, Y0, Y0
	VPXOR Y14, Y1, Y1
	VPXOR 0(SP), Y0, Y0
	VPXOR 32(SP), Y1, Y1
	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1
	VPXOR 64(SP), Y0, Y0
	VPXOR 96(SP), Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1
	VPXOR 128(SP), Y0, Y0
	VPXOR 160(SP), Y1, Y1
	VAESENC Y5, Y0, Y0; VAESENC Y5, Y1, Y1
	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU Y0, 0(DI)
	VMOVDQU Y1, 32(DI)
	VZEROUPPER
	RET
