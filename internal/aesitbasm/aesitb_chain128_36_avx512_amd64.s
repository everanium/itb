//go:build amd64 && !purego && !noitbasm

// VAES ZMM, four lanes per register (needs VAES + AVX-512) 4-lane chain-absorb kernel for AES-ITB-128 at the
// 36-byte per-lane shape (3 PKCS#7 blocks, 5 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference by the in-package parity tests. The tail block is
// read with exact-width inserts — no byte past the 36-byte input is
// touched.

#include "textflag.h"

// func aesITB128ChainAbsorb36x4Avx512Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128ChainAbsorb36x4Avx512Asm(SB), NOSPLIT, $0-32
	MOVQ key+0(FP), AX
	MOVQ seeds+8(FP), BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP), DX
	MOVQ 0(CX), R8
	MOVQ 8(CX), R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VBROADCASTI32X4 0(AX), Z1
	VMOVDQU64 0(BX), Z0
	VPXORD Z1, Z0, Z0

	VBROADCASTI32X4 ·RC+0(SB), Z2
	VBROADCASTI32X4 ·RC+16(SB), Z3
	VBROADCASTI32X4 ·RC+32(SB), Z4
	VBROADCASTI32X4 ·RC+48(SB), Z5
	VBROADCASTI32X4 ·RC+64(SB), Z6
	VBROADCASTI32X4 ·RC+80(SB), Z7
	VBROADCASTI32X4 ·RC+96(SB), Z8
	VBROADCASTI32X4 ·RC+112(SB), Z9

	VMOVDQU 0(R8), X11
	VINSERTI64X2 $1, 0(R9), Z11, Z11
	VINSERTI64X2 $2, 0(R10), Z11, Z11
	VINSERTI64X2 $3, 0(R11), Z11, Z11
	VPXORD Z11, Z0, Z0
	VAESENC Z2, Z0, Z0

	VMOVDQU 16(R8), X11
	VINSERTI64X2 $1, 16(R9), Z11, Z11
	VINSERTI64X2 $2, 16(R10), Z11, Z11
	VINSERTI64X2 $3, 16(R11), Z11, Z11
	VPXORD Z11, Z0, Z0
	VAESENC Z3, Z0, Z0

	VBROADCASTI32X4 ·pad4Tail(SB), Z10
	VPINSRD $0, 32(R8), X10, X11
	VPINSRD $0, 32(R9), X10, X12
	VPINSRD $0, 32(R10), X10, X13
	VPINSRD $0, 32(R11), X10, X14
	VINSERTI64X2 $1, X12, Z11, Z11
	VINSERTI64X2 $2, X13, Z11, Z11
	VINSERTI64X2 $3, X14, Z11, Z11
	VPXORD Z11, Z0, Z0
	VAESENC Z4, Z0, Z0

	VAESENC Z2, Z0, Z0
	VAESENC Z3, Z0, Z0

	VMOVDQU64 Z0, 0(DX)
	VZEROUPPER
	RET
