//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 13-byte shape, 4 lanes (1 PKCS#7 block, 3 AES rounds per
// cascade round).
// The padded data blocks are staged once into the frame, every block
// past block 0 with the round constant of the preceding absorb round
// folded in so it serves as that round's key, and every cascade round
// runs from those 16-byte slots; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain13x4VexAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain13x4VexAsm(SB), NOSPLIT, $64-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	VMOVDQU ·pad13Tail(SB), X13
	VPINSRQ $0, 0(R8), X13, X4
	VPINSRD $2, 8(R8), X4, X4
	VPINSRB $12, 12(R8), X4, X4
	VMOVDQU X4, 0(SP)
	VPINSRQ $0, 0(R9), X13, X4
	VPINSRD $2, 8(R9), X4, X4
	VPINSRB $12, 12(R9), X4, X4
	VMOVDQU X4, 16(SP)
	VPINSRQ $0, 0(R10), X13, X4
	VPINSRD $2, 8(R10), X4, X4
	VPINSRB $12, 12(R10), X4, X4
	VMOVDQU X4, 32(SP)
	VPINSRQ $0, 0(R11), X13, X4
	VPINSRD $2, 8(R11), X4, X4
	VPINSRB $12, 12(R11), X4, X4
	VMOVDQU X4, 48(SP)

	VMOVDQU ·RC+0(SB), X5
	VMOVDQU ·RC+16(SB), X6
	VMOVDQU ·RC+32(SB), X7
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
	VAESENC X6, X0, X0; VAESENC X6, X1, X1; VAESENC X6, X2, X2; VAESENC X6, X3, X3
	VAESENC X7, X0, X0; VAESENC X7, X1, X1; VAESENC X7, X2, X2; VAESENC X7, X3, X3
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	VMOVDQU X0, 0(DI)
	VMOVDQU X1, 16(DI)
	VMOVDQU X2, 32(DI)
	VMOVDQU X3, 48(DI)
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
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ DI, DI
	XORQ R8, R8
	XORQ R9, R9
	XORQ R10, R10
	XORQ R11, R11
	RET
