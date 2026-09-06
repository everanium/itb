//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 20-byte shape, 4 lanes (2 PKCS#7 blocks, 4 AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain20x4VexAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain20x4VexAsm(SB), NOSPLIT, $128-40
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
	VMOVDQU ·pad4Tail(SB), X13
	VPINSRD $0, 16(R8), X13, X4
	VMOVDQU X4, 64(SP)
	VPINSRD $0, 16(R9), X13, X4
	VMOVDQU X4, 80(SP)
	VPINSRD $0, 16(R10), X13, X4
	VMOVDQU X4, 96(SP)
	VPINSRD $0, 16(R11), X13, X4
	VMOVDQU X4, 112(SP)

	VMOVDQU ·RC+0(SB), X5
	VMOVDQU ·RC+16(SB), X6
	VMOVDQU ·RC+32(SB), X7
	VMOVDQU ·RC+48(SB), X8
	VMOVDQU ·RC+64(SB), X9
	VMOVDQU ·RC+80(SB), X10
	VMOVDQU ·RC+96(SB), X11
	VMOVDQU ·RC+112(SB), X12
	VMOVDQU 0(AX), X13
	VPXOR X0, X0, X0
	VPXOR X1, X1, X1
	VPXOR X2, X2, X2
	VPXOR X3, X3, X3

loop:
	VMOVDQU 0(BX), X14
	VPXOR X13, X14, X14
	VPXOR X14, X0, X0
	VPXOR X14, X1, X1
	VPXOR X14, X2, X2
	VPXOR X14, X3, X3
	VPXOR 0(SP), X0, X0
	VPXOR 16(SP), X1, X1
	VPXOR 32(SP), X2, X2
	VPXOR 48(SP), X3, X3
	VAESENC X5, X0, X0; VAESENC X5, X1, X1; VAESENC X5, X2, X2; VAESENC X5, X3, X3
	VPXOR 64(SP), X0, X0
	VPXOR 80(SP), X1, X1
	VPXOR 96(SP), X2, X2
	VPXOR 112(SP), X3, X3
	VAESENC X6, X0, X0; VAESENC X6, X1, X1; VAESENC X6, X2, X2; VAESENC X6, X3, X3
	VAESENC X5, X0, X0; VAESENC X5, X1, X1; VAESENC X5, X2, X2; VAESENC X5, X3, X3
	VAESENC X6, X0, X0; VAESENC X6, X1, X1; VAESENC X6, X2, X2; VAESENC X6, X3, X3
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VMOVDQU X1, 16(DI)
	VMOVDQU X2, 32(DI)
	VMOVDQU X3, 48(DI)
	RET
