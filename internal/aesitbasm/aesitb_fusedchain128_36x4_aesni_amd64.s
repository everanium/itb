//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 36-byte shape, 4 lanes (3 PKCS#7 blocks, 5 AES rounds per
// cascade round).
// The padded data blocks are staged once into the frame and every
// cascade round runs from those 16-byte slots; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain36x4AesNiAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128FusedChain36x4AesNiAsm(SB), NOSPLIT, $192-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ 0(DX), R8
	MOVQ 8(DX), R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	MOVOU ·pad4Tail(SB), X13
	MOVOU X13, X4
	PINSRD $0, 0(R8), X4
	PINSRD $1, 4(R8), X4
	PINSRQ $1, 8(R8), X4
	MOVOU X4, 0(SP)
	MOVOU X13, X4
	PINSRD $0, 0(R9), X4
	PINSRD $1, 4(R9), X4
	PINSRQ $1, 8(R9), X4
	MOVOU X4, 16(SP)
	MOVOU X13, X4
	PINSRD $0, 0(R10), X4
	PINSRD $1, 4(R10), X4
	PINSRQ $1, 8(R10), X4
	MOVOU X4, 32(SP)
	MOVOU X13, X4
	PINSRD $0, 0(R11), X4
	PINSRD $1, 4(R11), X4
	PINSRQ $1, 8(R11), X4
	MOVOU X4, 48(SP)
	MOVOU 16(R8), X4
	MOVOU X4, 64(SP)
	MOVOU 16(R9), X4
	MOVOU X4, 80(SP)
	MOVOU 16(R10), X4
	MOVOU X4, 96(SP)
	MOVOU 16(R11), X4
	MOVOU X4, 112(SP)
	MOVOU X13, X4
	PINSRD $0, 32(R8), X4
	MOVOU X4, 128(SP)
	MOVOU X13, X4
	PINSRD $0, 32(R9), X4
	MOVOU X4, 144(SP)
	MOVOU X13, X4
	PINSRD $0, 32(R10), X4
	MOVOU X4, 160(SP)
	MOVOU X13, X4
	PINSRD $0, 32(R11), X4
	MOVOU X4, 176(SP)

	MOVOU ·RC+0(SB), X5
	MOVOU ·RC+16(SB), X6
	MOVOU ·RC+32(SB), X7
	MOVOU ·RC+48(SB), X8
	MOVOU ·RC+64(SB), X9
	MOVOU ·RC+80(SB), X10
	MOVOU ·RC+96(SB), X11
	MOVOU ·RC+112(SB), X12
	MOVOU 0(AX), X13
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3

loop:
	MOVOU 0(BX), X14
	PXOR X13, X14
	PXOR X14, X0
	PXOR X14, X1
	PXOR X14, X2
	PXOR X14, X3
	MOVOU 0(SP), X4
	PXOR X4, X0
	MOVOU 16(SP), X4
	PXOR X4, X1
	MOVOU 32(SP), X4
	PXOR X4, X2
	MOVOU 48(SP), X4
	PXOR X4, X3
	AESENC X5, X0; AESENC X5, X1; AESENC X5, X2; AESENC X5, X3
	MOVOU 64(SP), X4
	PXOR X4, X0
	MOVOU 80(SP), X4
	PXOR X4, X1
	MOVOU 96(SP), X4
	PXOR X4, X2
	MOVOU 112(SP), X4
	PXOR X4, X3
	AESENC X6, X0; AESENC X6, X1; AESENC X6, X2; AESENC X6, X3
	MOVOU 128(SP), X4
	PXOR X4, X0
	MOVOU 144(SP), X4
	PXOR X4, X1
	MOVOU 160(SP), X4
	PXOR X4, X2
	MOVOU 176(SP), X4
	PXOR X4, X3
	AESENC X7, X0; AESENC X7, X1; AESENC X7, X2; AESENC X7, X3
	AESENC X5, X0; AESENC X5, X1; AESENC X5, X2; AESENC X5, X3
	AESENC X6, X0; AESENC X6, X1; AESENC X6, X2; AESENC X6, X3
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	RET
