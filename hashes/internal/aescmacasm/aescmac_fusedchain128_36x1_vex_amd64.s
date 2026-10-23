//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM fused ChainHash cascade kernel for AES-CMAC at the
// 36-byte shape, 1 lane (3 zero-padded blocks, 3 AES-128
// permutations per cascade round).
// The data blocks are staged once into the frame (block 0 with the
// length tag folded in) and every cascade round runs from those
// 16-byte slots; each lane is carried as state ^ K0 with K10 ^ K0 as
// the last-round key, so the frame holds public block bytes only; see aescmacasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesCMAC128FusedChain36x1VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesCMAC128FusedChain36x1VexAsm(SB), NOSPLIT, $192-40
	MOVQ roundKeys+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	VPXOR X13, X13, X13
	MOVQ $36, R12
	VMOVQ R12, X15
	VPUNPCKLQDQ X15, X15, X15
	VPINSRD $0, 0(R8), X13, X4
	VPINSRD $1, 4(R8), X4, X4
	VPINSRQ $1, 8(R8), X4, X4
	VPXOR X15, X4, X4
	VMOVDQU X4, 0(SP)
	VMOVDQU 16(R8), X4
	VMOVDQU X4, 64(SP)
	VPINSRD $0, 32(R8), X13, X4
	VMOVDQU X4, 128(SP)

	VMOVDQU 16(AX), X6
	VMOVDQU 32(AX), X7
	VMOVDQU 48(AX), X8
	VMOVDQU 64(AX), X9
	VMOVDQU 80(AX), X10
	VMOVDQU 96(AX), X11
	VMOVDQU 112(AX), X12
	VMOVDQU 128(AX), X13
	VMOVDQU 144(AX), X14
	VMOVDQU 160(AX), X15
	VPXOR 0(AX), X15, X15
	VMOVDQU 0(AX), X0

loop:
	VMOVDQU 0(BX), X5
	VPXOR X5, X0, X0
	VPXOR 0(SP), X0, X0
	VAESENC X6, X0, X0
	VAESENC X7, X0, X0
	VAESENC X8, X0, X0
	VAESENC X9, X0, X0
	VAESENC X10, X0, X0
	VAESENC X11, X0, X0
	VAESENC X12, X0, X0
	VAESENC X13, X0, X0
	VAESENC X14, X0, X0
	VAESENCLAST X15, X0, X0
	VPXOR 64(SP), X0, X0
	VAESENC X6, X0, X0
	VAESENC X7, X0, X0
	VAESENC X8, X0, X0
	VAESENC X9, X0, X0
	VAESENC X10, X0, X0
	VAESENC X11, X0, X0
	VAESENC X12, X0, X0
	VAESENC X13, X0, X0
	VAESENC X14, X0, X0
	VAESENCLAST X15, X0, X0
	VPXOR 128(SP), X0, X0
	VAESENC X6, X0, X0
	VAESENC X7, X0, X0
	VAESENC X8, X0, X0
	VAESENC X9, X0, X0
	VAESENC X10, X0, X0
	VAESENC X11, X0, X0
	VAESENC X12, X0, X0
	VAESENC X13, X0, X0
	VAESENC X14, X0, X0
	VAESENCLAST X15, X0, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VPXOR 0(AX), X0, X0
	VMOVDQU X0, 0(DI)
	VPXOR X0, X0, X0
	VPXOR X1, X1, X1
	VPXOR X2, X2, X2
	VPXOR X3, X3, X3
	VPXOR X4, X4, X4
	VPXOR X5, X5, X5
	VPXOR X6, X6, X6
	VPXOR X7, X7, X7
	VPXOR X8, X8, X8
	VPXOR X9, X9, X9
	VPXOR X10, X10, X10
	VPXOR X11, X11, X11
	VPXOR X12, X12, X12
	VPXOR X13, X13, X13
	VPXOR X14, X14, X14
	VPXOR X15, X15, X15
	VMOVDQU X0, 0(SP)
	VMOVDQU X0, 16(SP)
	VMOVDQU X0, 32(SP)
	VMOVDQU X0, 48(SP)
	VMOVDQU X0, 64(SP)
	VMOVDQU X0, 80(SP)
	VMOVDQU X0, 96(SP)
	VMOVDQU X0, 112(SP)
	VMOVDQU X0, 128(SP)
	VMOVDQU X0, 144(SP)
	VMOVDQU X0, 160(SP)
	VMOVDQU X0, 176(SP)
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ DI, DI
	XORQ R8, R8
	XORQ R12, R12
	RET
