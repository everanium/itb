//go:build amd64 && !purego

#include "textflag.h"

// func ClobberRegs()
// Zeroes all Go ABIInternal caller-saved general-purpose registers (preserving
// SP, BP, and R14=g) and XMM0..XMM15 vector registers.
TEXT ·ClobberRegs(SB), NOSPLIT, $0-0
	XORQ AX, AX
	XORQ BX, BX
	XORQ CX, CX
	XORQ DX, DX
	XORQ SI, SI
	XORQ DI, DI
	XORQ R8, R8
	XORQ R9, R9
	XORQ R10, R10
	XORQ R11, R11
	XORQ R12, R12
	XORQ R13, R13
	XORQ R15, R15
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
	RET
