//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM fused ChainHash cascade kernel for AES-CMAC at the
// 36-byte shape, 1 lane (3 zero-padded blocks, 3 AES-128
// permutations per cascade round).
// The data blocks are staged once into the frame with K0 (and, for
// block 0, the length tag) folded in, and every cascade round runs
// from those 16-byte slots; see aescmacasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesCMAC128FusedChain36x1AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesCMAC128FusedChain36x1AesNiAsm(SB), NOSPLIT, $192-40
	MOVQ roundKeys+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	PXOR X13, X13
	MOVOU 0(AX), X14
	MOVQ $36, R12
	MOVQ R12, X15
	PUNPCKLQDQ X15, X15
	PXOR X14, X15
	MOVOU X13, X4
	PINSRD $0, 0(R8), X4
	PINSRD $1, 4(R8), X4
	PINSRQ $1, 8(R8), X4
	PXOR X15, X4
	MOVOU X4, 0(SP)
	MOVOU 16(R8), X4
	PXOR X14, X4
	MOVOU X4, 64(SP)
	MOVOU X13, X4
	PINSRD $0, 32(R8), X4
	PXOR X14, X4
	MOVOU X4, 128(SP)

	MOVOU 16(AX), X6
	MOVOU 32(AX), X7
	MOVOU 48(AX), X8
	MOVOU 64(AX), X9
	MOVOU 80(AX), X10
	MOVOU 96(AX), X11
	MOVOU 112(AX), X12
	MOVOU 128(AX), X13
	MOVOU 144(AX), X14
	MOVOU 160(AX), X15
	PXOR X0, X0

loop:
	MOVOU 0(BX), X5
	PXOR X5, X0
	MOVOU 0(SP), X4
	PXOR X4, X0
	AESENC X6, X0
	AESENC X7, X0
	AESENC X8, X0
	AESENC X9, X0
	AESENC X10, X0
	AESENC X11, X0
	AESENC X12, X0
	AESENC X13, X0
	AESENC X14, X0
	AESENCLAST X15, X0
	MOVOU 64(SP), X4
	PXOR X4, X0
	AESENC X6, X0
	AESENC X7, X0
	AESENC X8, X0
	AESENC X9, X0
	AESENC X10, X0
	AESENC X11, X0
	AESENC X12, X0
	AESENC X13, X0
	AESENC X14, X0
	AESENCLAST X15, X0
	MOVOU 128(SP), X4
	PXOR X4, X0
	AESENC X6, X0
	AESENC X7, X0
	AESENC X8, X0
	AESENC X9, X0
	AESENC X10, X0
	AESENC X11, X0
	AESENC X12, X0
	AESENC X13, X0
	AESENC X14, X0
	AESENCLAST X15, X0
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	MOVOU X0, 0(DI)
	RET
