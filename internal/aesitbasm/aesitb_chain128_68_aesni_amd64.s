//go:build amd64 && !purego && !noitbasm

// Legacy-SSE AES-NI XMM (AESENC xmm, xmm) 4-lane chain-absorb kernel for AES-ITB-128 at the
// 68-byte per-lane shape (5 PKCS#7 blocks, 7 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference by the in-package parity tests. The tail block is
// read with exact-width inserts — no byte past the 68-byte input is
// touched.
// Every load is sized to the store the Go call site leaves in flight
// (seeds copy, pixel-index write) so it forwards from the store buffer
// instead of waiting for the store to commit, and the output is written
// as four 16-byte stores, the width the Go side reads it back with.

#include "textflag.h"

// func aesITB128ChainAbsorb68x4AesNiAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128ChainAbsorb68x4AesNiAsm(SB), NOSPLIT, $0-32
	MOVQ key+0(FP), AX
	MOVQ seeds+8(FP), BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP), DX
	MOVQ 0(CX), R8
	MOVQ 8(CX), R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	MOVOU 0(AX), X13
	MOVOU 0(BX), X0
	MOVOU 16(BX), X1
	MOVOU 32(BX), X2
	MOVOU 48(BX), X3
	PXOR X13, X0
	PXOR X13, X1
	PXOR X13, X2
	PXOR X13, X3

	MOVOU ·RC+0(SB), X5
	MOVOU ·RC+16(SB), X6
	MOVOU ·RC+32(SB), X7
	MOVOU ·RC+48(SB), X8
	MOVOU ·RC+64(SB), X9
	MOVOU ·RC+80(SB), X10
	MOVOU ·RC+96(SB), X11
	MOVOU ·RC+112(SB), X12

	MOVOU ·pad4Tail(SB), X13
	MOVOU X13, X4
	PINSRD $0, 0(R8), X4
	PINSRD $1, 4(R8), X4
	PINSRQ $1, 8(R8), X4
	PXOR X4, X0
	MOVOU X13, X4
	PINSRD $0, 0(R9), X4
	PINSRD $1, 4(R9), X4
	PINSRQ $1, 8(R9), X4
	PXOR X4, X1
	MOVOU X13, X4
	PINSRD $0, 0(R10), X4
	PINSRD $1, 4(R10), X4
	PINSRQ $1, 8(R10), X4
	PXOR X4, X2
	MOVOU X13, X4
	PINSRD $0, 0(R11), X4
	PINSRD $1, 4(R11), X4
	PINSRQ $1, 8(R11), X4
	PXOR X4, X3
	AESENC X5, X0; AESENC X5, X1; AESENC X5, X2; AESENC X5, X3

	MOVOU 16(R8), X4
	PXOR X4, X0
	MOVOU 16(R9), X4
	PXOR X4, X1
	MOVOU 16(R10), X4
	PXOR X4, X2
	MOVOU 16(R11), X4
	PXOR X4, X3
	AESENC X6, X0; AESENC X6, X1; AESENC X6, X2; AESENC X6, X3

	MOVOU 32(R8), X4
	PXOR X4, X0
	MOVOU 32(R9), X4
	PXOR X4, X1
	MOVOU 32(R10), X4
	PXOR X4, X2
	MOVOU 32(R11), X4
	PXOR X4, X3
	AESENC X7, X0; AESENC X7, X1; AESENC X7, X2; AESENC X7, X3

	MOVOU 48(R8), X4
	PXOR X4, X0
	MOVOU 48(R9), X4
	PXOR X4, X1
	MOVOU 48(R10), X4
	PXOR X4, X2
	MOVOU 48(R11), X4
	PXOR X4, X3
	AESENC X8, X0; AESENC X8, X1; AESENC X8, X2; AESENC X8, X3

	MOVOU X13, X4
	PINSRD $0, 64(R8), X4
	PXOR X4, X0
	MOVOU X13, X4
	PINSRD $0, 64(R9), X4
	PXOR X4, X1
	MOVOU X13, X4
	PINSRD $0, 64(R10), X4
	PXOR X4, X2
	MOVOU X13, X4
	PINSRD $0, 64(R11), X4
	PXOR X4, X3
	AESENC X9, X0; AESENC X9, X1; AESENC X9, X2; AESENC X9, X3

	AESENC X5, X0; AESENC X5, X1; AESENC X5, X2; AESENC X5, X3
	AESENC X6, X0; AESENC X6, X1; AESENC X6, X2; AESENC X6, X3

	MOVOU X0, 0(DX)
	MOVOU X1, 16(DX)
	MOVOU X2, 32(DX)
	MOVOU X3, 48(DX)
	RET
