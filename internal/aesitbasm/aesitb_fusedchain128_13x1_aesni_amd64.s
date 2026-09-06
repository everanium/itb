//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 13-byte shape, 1 lane (1 PKCS#7 block, 3 AES rounds per
// cascade round).
// The padded data blocks are staged once into the frame and every
// cascade round runs from those 16-byte slots; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain13x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesITB128FusedChain13x1AesNiAsm(SB), NOSPLIT, $64-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	MOVOU ·pad13Tail(SB), X13
	MOVOU X13, X4
	PINSRQ $0, 0(R8), X4
	PINSRD $2, 8(R8), X4
	PINSRB $12, 12(R8), X4
	MOVOU X4, 0(SP)

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

loop:
	MOVOU 0(BX), X14
	PXOR X13, X14
	PXOR X14, X0
	MOVOU 0(SP), X4
	PXOR X4, X0
	AESENC X5, X0
	AESENC X5, X0
	AESENC X6, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	MOVOU X0, 0(DI)
	RET
