//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func chunk168LockBatch(n int, src *byte, masks *[3][3]uint64, p0, p1, p2 *byte)
//
// Batched forward apply: n consecutive 168-bit (21-byte) chunks read from
// src, each permuted under its own mask triple masks[j] = (m0, m1, m2)
// (where each m_i is [3]uint64 = 24 bytes, 72 bytes per chunk), with the
// three 56-bit (7-byte) lane outputs stored little-endian at p0[7j],
// p1[7j], p2[7j].
//
// Frame (ABI0): n +0(FP) src +8(FP) masks +16(FP) p0 +24(FP)
// p1 +32(FP) p2 +40(FP). No SIMD state is touched.
TEXT ·chunk168LockBatch(SB), NOSPLIT, $0-48
	MOVQ  n+0(FP), R15
	MOVQ  src+8(FP), SI
	MOVQ  masks+16(FP), DX
	MOVQ  p0+24(FP), R8
	MOVQ  p1+32(FP), R9
	MOVQ  p2+40(FP), R10
	TESTQ R15, R15
	JLE   lock168Done

lock168Loop:
	MOVQ    0(SI), R11       // x0 = bytes 0..7
	MOVQ    8(SI), R12       // x1 = bytes 8..15
	MOVLQZX 16(SI), R13      // bytes 16..19
	MOVBQZX 20(SI), AX       // byte 20
	SHLQ    $32, AX
	ORQ     AX, R13          // x2 = bytes 16..20 (40 bits)

	// Lane 0: m0 at 0(DX), 8(DX), 16(DX) -> (R8)
	MOVQ    0(DX), BX
	PEXTQ   BX, R11, R14
	POPCNTQ BX, CX
	MOVQ    8(DX), BX
	PEXTQ   BX, R12, DI
	POPCNTQ BX, AX
	SHLQ    CX, DI
	ADDQ    AX, CX
	PEXTQ   16(DX), R13, BX
	SHLQ    CX, BX
	ORQ     DI, R14
	ORQ     BX, R14
	MOVL    R14, 0(R8)
	SHRQ    $32, R14
	MOVW    R14, 4(R8)
	SHRQ    $16, R14
	MOVB    R14, 6(R8)

	// Lane 1: m1 at 24(DX), 32(DX), 40(DX) -> (R9)
	MOVQ    24(DX), BX
	PEXTQ   BX, R11, R14
	POPCNTQ BX, CX
	MOVQ    32(DX), BX
	PEXTQ   BX, R12, DI
	POPCNTQ BX, AX
	SHLQ    CX, DI
	ADDQ    AX, CX
	PEXTQ   40(DX), R13, BX
	SHLQ    CX, BX
	ORQ     DI, R14
	ORQ     BX, R14
	MOVL    R14, 0(R9)
	SHRQ    $32, R14
	MOVW    R14, 4(R9)
	SHRQ    $16, R14
	MOVB    R14, 6(R9)

	// Lane 2: m2 at 48(DX), 56(DX), 64(DX) -> (R10)
	MOVQ    48(DX), BX
	PEXTQ   BX, R11, R14
	POPCNTQ BX, CX
	MOVQ    56(DX), BX
	PEXTQ   BX, R12, DI
	POPCNTQ BX, AX
	SHLQ    CX, DI
	ADDQ    AX, CX
	PEXTQ   64(DX), R13, BX
	SHLQ    CX, BX
	ORQ     DI, R14
	ORQ     BX, R14
	MOVL    R14, 0(R10)
	SHRQ    $32, R14
	MOVW    R14, 4(R10)
	SHRQ    $16, R14
	MOVB    R14, 6(R10)

	ADDQ $21, SI
	ADDQ $72, DX
	ADDQ $7, R8
	ADDQ $7, R9
	ADDQ $7, R10
	DECQ R15
	JNZ  lock168Loop

lock168Done:
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
	XORQ R14, R14
	XORQ R15, R15
	RET

// func unchunk168LockBatch(n int, masks *[3][3]uint64, p0, p1, p2 *byte, dst *byte)
//
// Batched inverse apply: for n consecutive chunks, the three 56-bit
// (7-byte) lane values read little-endian at p0[7j], p1[7j], p2[7j] are
// deposited under masks[j] = (m0, m1, m2) via BMI2 PDEPQ, OR-ed across
// the three lanes, and stored as 21 little-endian bytes at dst[21j].
//
// Frame (ABI0): n +0(FP) masks +8(FP) p0 +16(FP) p1 +24(FP)
// p2 +32(FP) dst +40(FP). No SIMD state is touched.
TEXT ·unchunk168LockBatch(SB), NOSPLIT, $0-48
	MOVQ  n+0(FP), R15
	MOVQ  masks+8(FP), DX
	MOVQ  p0+16(FP), R8
	MOVQ  p1+24(FP), R9
	MOVQ  p2+32(FP), R10
	MOVQ  dst+40(FP), DI
	TESTQ R15, R15
	JLE   unlock168Done

unlock168Loop:
	// Lane 0: (R8) under m0 -> initialize (R11, R12, R13)
	MOVLQZX 0(R8), R14
	MOVWQZX 4(R8), AX
	SHLQ    $32, AX
	ORQ     AX, R14
	MOVBQZX 6(R8), AX
	SHLQ    $48, AX
	ORQ     AX, R14

	MOVQ    0(DX), BX
	PDEPQ   BX, R14, R11
	POPCNTQ BX, CX
	SHRQ    CX, R14
	MOVQ    8(DX), BX
	PDEPQ   BX, R14, R12
	POPCNTQ BX, CX
	SHRQ    CX, R14
	PDEPQ   16(DX), R14, R13

	// Lane 1: (R9) under m1 -> OR into (R11, R12, R13)
	MOVLQZX 0(R9), R14
	MOVWQZX 4(R9), AX
	SHLQ    $32, AX
	ORQ     AX, R14
	MOVBQZX 6(R9), AX
	SHLQ    $48, AX
	ORQ     AX, R14

	MOVQ    24(DX), BX
	PDEPQ   BX, R14, SI
	ORQ     SI, R11
	POPCNTQ BX, CX
	SHRQ    CX, R14
	MOVQ    32(DX), BX
	PDEPQ   BX, R14, SI
	ORQ     SI, R12
	POPCNTQ BX, CX
	SHRQ    CX, R14
	PDEPQ   40(DX), R14, SI
	ORQ     SI, R13

	// Lane 2: (R10) under m2 -> OR into (R11, R12, R13)
	MOVLQZX 0(R10), R14
	MOVWQZX 4(R10), AX
	SHLQ    $32, AX
	ORQ     AX, R14
	MOVBQZX 6(R10), AX
	SHLQ    $48, AX
	ORQ     AX, R14

	MOVQ    48(DX), BX
	PDEPQ   BX, R14, SI
	ORQ     SI, R11
	POPCNTQ BX, CX
	SHRQ    CX, R14
	MOVQ    56(DX), BX
	PDEPQ   BX, R14, SI
	ORQ     SI, R12
	POPCNTQ BX, CX
	SHRQ    CX, R14
	PDEPQ   64(DX), R14, SI
	ORQ     SI, R13

	// Store 21-byte chunk (R11, R12, R13) to (DI)
	MOVQ R11, 0(DI)
	MOVQ R12, 8(DI)
	MOVL R13, 16(DI)
	SHRQ $32, R13
	MOVB R13, 20(DI)

	ADDQ $72, DX
	ADDQ $7, R8
	ADDQ $7, R9
	ADDQ $7, R10
	ADDQ $21, DI
	DECQ R15
	JNZ  unlock168Loop

unlock168Done:
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
	XORQ R14, R14
	XORQ R15, R15
	RET
