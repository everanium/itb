//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX) 4-lane chain-absorb kernel for AES-ITB-128 at the
// 20-byte per-lane shape (2 PKCS#7 blocks, 4 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference by the in-package parity tests. The tail block is
// read with exact-width inserts — no byte past the 20-byte input is
// touched.

#include "textflag.h"

// func aesITB128ChainAbsorb20x4VexAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128ChainAbsorb20x4VexAsm(SB), NOSPLIT, $0-32
	MOVQ key+0(FP), AX
	MOVQ seeds+8(FP), BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP), DX
	MOVQ 0(CX), R8
	MOVQ 8(CX), R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VMOVDQU 0(AX), X13
	VMOVDQU 0(BX), X0
	VMOVDQU 16(BX), X1
	VMOVDQU 32(BX), X2
	VMOVDQU 48(BX), X3
	VPXOR X13, X0, X0
	VPXOR X13, X1, X1
	VPXOR X13, X2, X2
	VPXOR X13, X3, X3

	VMOVDQU ·RC+0(SB), X5
	VMOVDQU ·RC+16(SB), X6
	VMOVDQU ·RC+32(SB), X7
	VMOVDQU ·RC+48(SB), X8
	VMOVDQU ·RC+64(SB), X9
	VMOVDQU ·RC+80(SB), X10
	VMOVDQU ·RC+96(SB), X11
	VMOVDQU ·RC+112(SB), X12

	VMOVDQU 0(R8), X4
	VPXOR X4, X0, X0
	VMOVDQU 0(R9), X4
	VPXOR X4, X1, X1
	VMOVDQU 0(R10), X4
	VPXOR X4, X2, X2
	VMOVDQU 0(R11), X4
	VPXOR X4, X3, X3
	VAESENC X5, X0, X0; VAESENC X5, X1, X1; VAESENC X5, X2, X2; VAESENC X5, X3, X3

	VMOVDQU ·pad4Tail(SB), X13
	VPINSRD $0, 16(R8), X13, X4
	VPXOR X4, X0, X0
	VPINSRD $0, 16(R9), X13, X4
	VPXOR X4, X1, X1
	VPINSRD $0, 16(R10), X13, X4
	VPXOR X4, X2, X2
	VPINSRD $0, 16(R11), X13, X4
	VPXOR X4, X3, X3
	VAESENC X6, X0, X0; VAESENC X6, X1, X1; VAESENC X6, X2, X2; VAESENC X6, X3, X3

	VAESENC X5, X0, X0; VAESENC X5, X1, X1; VAESENC X5, X2, X2; VAESENC X5, X3, X3
	VAESENC X6, X0, X0; VAESENC X6, X1, X1; VAESENC X6, X2, X2; VAESENC X6, X3, X3

	VMOVDQU X0, 0(DX)
	VMOVDQU X1, 16(DX)
	VMOVDQU X2, 32(DX)
	VMOVDQU X3, 48(DX)
	RET
