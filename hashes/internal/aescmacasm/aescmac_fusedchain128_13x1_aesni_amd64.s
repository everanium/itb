//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM fused ChainHash cascade kernel for AES-CMAC at the
// 13-byte shape, 1 lane (1 zero-padded block, 1 AES-128
// permutation per cascade round).
// The data blocks are staged once into the frame (block 0 with the
// length tag folded in) and every cascade round runs from those
// 16-byte slots; each lane is carried as state ^ K0 with K10 ^ K0 as
// the last-round key, so the frame holds public block bytes only; see aescmacasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesCMAC128FusedChain13x1AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesCMAC128FusedChain13x1AesNiAsm(SB), NOSPLIT, $64-40
	MOVQ roundKeys+0(FP), AX
	MOVQ comps+8(FP), BX
	MOVQ nPairs+16(FP), CX
	MOVQ data+24(FP), DX
	MOVQ out+32(FP), DI
	MOVQ DX, R8

	PXOR X13, X13
	MOVQ $13, R12
	MOVQ R12, X15
	PUNPCKLQDQ X15, X15
	MOVOU X13, X4
	PINSRQ $0, 0(R8), X4
	PINSRD $2, 8(R8), X4
	PINSRB $12, 12(R8), X4
	PXOR X15, X4
	MOVOU X4, 0(SP)

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
	MOVOU 0(AX), X4
	PXOR X4, X15
	MOVOU 0(AX), X0

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
	ADDQ $16, BX
	DECQ CX
	JNZ loop

	MOVOU 0(AX), X4
	PXOR X4, X0
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
	MOVOU X0, 16(SP)
	MOVOU X0, 32(SP)
	MOVOU X0, 48(SP)
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ DI, DI
	XORQ R8, R8
	XORQ R12, R12
	RET
