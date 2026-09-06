//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 13-byte shape, 1 lane (1 PKCS#7 block, 3 AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain13x1VexAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesITB128FusedChain13x1VexAsm(SB), NOSPLIT, $64-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	VMOVDQU ·pad13Tail(SB), X13
	VPINSRQ $0, 0(R8), X13, X4
	VPINSRD $2, 8(R8), X4, X4
	VPINSRB $12, 12(R8), X4, X4
	VMOVDQU X4, 0(SP)

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

loop:
	VMOVDQU 0(BX), X14
	VPXOR X13, X14, X14
	VPXOR X14, X0, X0
	VPXOR 0(SP), X0, X0
	VAESENC X5, X0, X0
	VAESENC X5, X0, X0
	VAESENC X6, X0, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	RET
