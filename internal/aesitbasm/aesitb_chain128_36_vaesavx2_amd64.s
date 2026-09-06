//go:build amd64 && !purego && !noitbasm

// VAES YMM, two lanes per register (needs VAES + AVX2) 4-lane chain-absorb kernel for AES-ITB-128 at the
// 36-byte per-lane shape (3 PKCS#7 blocks, 5 AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference by the in-package parity tests. The tail block is
// read with exact-width inserts — no byte past the 36-byte input is
// touched.
// Every load is sized to the store the Go call site leaves in flight
// (seeds copy, pixel-index write) so it forwards from the store buffer
// instead of waiting for the store to commit, and the output is written
// as four 16-byte stores, the width the Go side reads it back with.

#include "textflag.h"

// func aesITB128ChainAbsorb36x4VaesAvx2Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·aesITB128ChainAbsorb36x4VaesAvx2Asm(SB), NOSPLIT, $0-32
	MOVQ key+0(FP), AX
	MOVQ seeds+8(FP), BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP), DX
	MOVQ 0(CX), R8
	MOVQ 8(CX), R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VBROADCASTI128 0(AX), Y2
	VMOVDQU 0(BX), X0
	VINSERTI128 $1, 16(BX), Y0, Y0
	VMOVDQU 32(BX), X1
	VINSERTI128 $1, 48(BX), Y1, Y1
	VPXOR Y2, Y0, Y0
	VPXOR Y2, Y1, Y1

	VBROADCASTI128 ·RC+0(SB), Y3
	VBROADCASTI128 ·RC+16(SB), Y4
	VBROADCASTI128 ·RC+32(SB), Y5
	VBROADCASTI128 ·RC+48(SB), Y6
	VBROADCASTI128 ·RC+64(SB), Y7
	VBROADCASTI128 ·RC+80(SB), Y8
	VBROADCASTI128 ·RC+96(SB), Y9
	VBROADCASTI128 ·RC+112(SB), Y10

	VBROADCASTI128 ·pad4Tail(SB), Y11
	VPINSRD $0, 0(R8), X11, X12
	VPINSRD $1, 4(R8), X12, X12
	VPINSRQ $1, 8(R8), X12, X12
	VPINSRD $0, 0(R9), X11, X14
	VPINSRD $1, 4(R9), X14, X14
	VPINSRQ $1, 8(R9), X14, X14
	VINSERTI128 $1, X14, Y12, Y12
	VPXOR Y12, Y0, Y0
	VPINSRD $0, 0(R10), X11, X13
	VPINSRD $1, 4(R10), X13, X13
	VPINSRQ $1, 8(R10), X13, X13
	VPINSRD $0, 0(R11), X11, X15
	VPINSRD $1, 4(R11), X15, X15
	VPINSRQ $1, 8(R11), X15, X15
	VINSERTI128 $1, X15, Y13, Y13
	VPXOR Y13, Y1, Y1
	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1

	VMOVDQU 16(R8), X12
	VINSERTI128 $1, 16(R9), Y12, Y12
	VPXOR Y12, Y0, Y0
	VMOVDQU 16(R10), X13
	VINSERTI128 $1, 16(R11), Y13, Y13
	VPXOR Y13, Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1

	VPINSRD $0, 32(R8), X11, X12
	VPINSRD $0, 32(R9), X11, X14
	VINSERTI128 $1, X14, Y12, Y12
	VPXOR Y12, Y0, Y0
	VPINSRD $0, 32(R10), X11, X13
	VPINSRD $0, 32(R11), X11, X15
	VINSERTI128 $1, X15, Y13, Y13
	VPXOR Y13, Y1, Y1
	VAESENC Y5, Y0, Y0; VAESENC Y5, Y1, Y1

	VAESENC Y3, Y0, Y0; VAESENC Y3, Y1, Y1
	VAESENC Y4, Y0, Y0; VAESENC Y4, Y1, Y1

	VMOVDQU X0, 0(DX)
	VEXTRACTI128 $1, Y0, 16(DX)
	VMOVDQU X1, 32(DX)
	VEXTRACTI128 $1, Y1, 48(DX)
	VZEROUPPER
	RET
