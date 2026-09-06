//go:build amd64 && !purego && !noitbasm

// VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX) 4-lane chain-absorb kernel for AES-ITB-128 at the
// 13-byte per-lane shape (1 PKCS#7 block, 3 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference by the in-package parity tests. The tail block is
// read with exact-width inserts — no byte past the 13-byte input is
// touched.
// Every load is sized to the store the Go call site leaves in flight
// (seeds copy, pixel-index write) so it forwards from the store buffer
// instead of waiting for the store to commit, and the output is written
// as four 16-byte stores, the width the Go side reads it back with.

#include "textflag.h"

// func aesITB128ChainAbsorb13x4VexAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128ChainAbsorb13x4VexAsm(SB), NOSPLIT, $0-32
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

	VMOVDQU ·pad13Tail(SB), X13
	VPINSRQ $0, 0(R8), X13, X4
	VPINSRD $2, 8(R8), X4, X4
	VPINSRB $12, 12(R8), X4, X4
	VPXOR X4, X0, X0
	VPINSRQ $0, 0(R9), X13, X4
	VPINSRD $2, 8(R9), X4, X4
	VPINSRB $12, 12(R9), X4, X4
	VPXOR X4, X1, X1
	VPINSRQ $0, 0(R10), X13, X4
	VPINSRD $2, 8(R10), X4, X4
	VPINSRB $12, 12(R10), X4, X4
	VPXOR X4, X2, X2
	VPINSRQ $0, 0(R11), X13, X4
	VPINSRD $2, 8(R11), X4, X4
	VPINSRB $12, 12(R11), X4, X4
	VPXOR X4, X3, X3
	VAESENC X5, X0, X0; VAESENC X5, X1, X1; VAESENC X5, X2, X2; VAESENC X5, X3, X3

	VAESENC X5, X0, X0; VAESENC X5, X1, X1; VAESENC X5, X2, X2; VAESENC X5, X3, X3
	VAESENC X6, X0, X0; VAESENC X6, X1, X1; VAESENC X6, X2, X2; VAESENC X6, X3, X3

	VMOVDQU X0, 0(DX)
	VMOVDQU X1, 16(DX)
	VMOVDQU X2, 32(DX)
	VMOVDQU X3, 48(DX)
	RET
