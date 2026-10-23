//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 68-byte shape, 1 lane (5 PKCS#7 blocks, 7 AES rounds per
// cascade round).
// The padded data blocks are staged once into the frame, every block
// past block 0 with the round constant of the preceding absorb round
// folded in so it serves as that round's key, and every cascade round
// runs from those 16-byte slots; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain68x1VexAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesITB128FusedChain68x1VexAsm(SB), NOSPLIT, $320-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	VMOVDQU ·pad4Tail(SB), X13
	VPINSRD $0, 0(R8), X13, X4
	VPINSRD $1, 4(R8), X4, X4
	VPINSRQ $1, 8(R8), X4, X4
	VMOVDQU X4, 0(SP)
	VMOVDQU ·RC+0(SB), X5
	VMOVDQU 16(R8), X4
	VPXOR X5, X4, X4
	VMOVDQU X4, 64(SP)
	VMOVDQU ·RC+16(SB), X5
	VMOVDQU 32(R8), X4
	VPXOR X5, X4, X4
	VMOVDQU X4, 128(SP)
	VMOVDQU ·RC+32(SB), X5
	VMOVDQU 48(R8), X4
	VPXOR X5, X4, X4
	VMOVDQU X4, 192(SP)
	VMOVDQU ·RC+48(SB), X5
	VPINSRD $0, 64(R8), X13, X4
	VPXOR X5, X4, X4
	VMOVDQU X4, 256(SP)

	VMOVDQU ·RC+64(SB), X5
	VMOVDQU ·RC+80(SB), X6
	VMOVDQU ·RC+96(SB), X7
	VMOVDQU 0(AX), X13
	VPXOR X0, X0, X0

loop:
	VMOVDQU 0(BX), X14
	VPXOR X13, X14, X14
	VPXOR X14, X0, X0
	VPXOR 0(SP), X0, X0
	VAESENC 64(SP), X0, X0
	VAESENC 128(SP), X0, X0
	VAESENC 192(SP), X0, X0
	VAESENC 256(SP), X0, X0
	VAESENC X5, X0, X0
	VAESENC X6, X0, X0
	VAESENC X7, X0, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

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
	VMOVDQU X0, 64(SP)
	VMOVDQU X0, 128(SP)
	VMOVDQU X0, 192(SP)
	VMOVDQU X0, 256(SP)
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ DI, DI
	XORQ R8, R8
	RET
