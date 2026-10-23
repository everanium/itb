//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 68-byte shape, 1 lane (5 PKCS#7 blocks, 7 AES rounds per
// cascade round).
// The padded data blocks are staged once into the frame, every block
// past block 0 with the round constant of the preceding absorb round
// folded in so it serves as that round's key, and every cascade round
// runs from those 16-byte slots; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain68x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesITB128FusedChain68x1AesNiAsm(SB), NOSPLIT, $320-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	MOVOU ·pad4Tail(SB), X13
	MOVOU X13, X4
	PINSRD $0, 0(R8), X4
	PINSRD $1, 4(R8), X4
	PINSRQ $1, 8(R8), X4
	MOVOU X4, 0(SP)
	MOVOU ·RC+0(SB), X5
	MOVOU 16(R8), X4
	PXOR X5, X4
	MOVOU X4, 64(SP)
	MOVOU ·RC+16(SB), X5
	MOVOU 32(R8), X4
	PXOR X5, X4
	MOVOU X4, 128(SP)
	MOVOU ·RC+32(SB), X5
	MOVOU 48(R8), X4
	PXOR X5, X4
	MOVOU X4, 192(SP)
	MOVOU ·RC+48(SB), X5
	MOVOU X13, X4
	PINSRD $0, 64(R8), X4
	PXOR X5, X4
	MOVOU X4, 256(SP)

	MOVOU ·RC+64(SB), X5
	MOVOU ·RC+80(SB), X6
	MOVOU ·RC+96(SB), X7
	MOVOU 0(AX), X13
	PXOR X0, X0

loop:
	MOVOU 0(BX), X14
	PXOR X13, X14
	PXOR X14, X0
	MOVOU 0(SP), X4
	PXOR X4, X0
	MOVOU 64(SP), X8
	AESENC X8, X0
	MOVOU 128(SP), X8
	AESENC X8, X0
	MOVOU 192(SP), X8
	AESENC X8, X0
	MOVOU 256(SP), X8
	AESENC X8, X0
	AESENC X5, X0
	AESENC X6, X0
	AESENC X7, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	MOVOU X0, 0(DI)
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X7, X7
	PXOR X8, X8
	PXOR X9, X9
	PXOR X10, X10
	PXOR X11, X11
	PXOR X12, X12
	PXOR X13, X13
	PXOR X14, X14
	PXOR X15, X15
	MOVOU X0, 0(SP)
	MOVOU X0, 64(SP)
	MOVOU X0, 128(SP)
	MOVOU X0, 192(SP)
	MOVOU X0, 256(SP)
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ DI, DI
	XORQ R8, R8
	RET
