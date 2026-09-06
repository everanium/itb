//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM fused ChainHash cascade kernel for AES-ITB-128 at the
// 36-byte shape, 1 lane (3 PKCS#7 blocks, 5 AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain36x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesITB128FusedChain36x1AesNiAsm(SB), NOSPLIT, $192-40
	MOVQ key+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	MOVOU 0(R8), X4
	MOVOU X4, 0(SP)
	MOVOU 16(R8), X4
	MOVOU X4, 64(SP)
	MOVOU ·pad4Tail(SB), X13
	MOVOU X13, X4
	PINSRD $0, 32(R8), X4
	MOVOU X4, 128(SP)

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
	MOVOU 64(SP), X4
	PXOR X4, X0
	AESENC X6, X0
	MOVOU 128(SP), X4
	PXOR X4, X0
	AESENC X7, X0
	AESENC X5, X0
	AESENC X6, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	MOVOU X0, 0(DI)
	RET
