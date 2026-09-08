//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func chunk48LockBatch(n int, src *byte, masks *[3]uint64, p0, p1, p2 *byte)
//
// Batched forward apply: n consecutive 48-bit chunks read from src
// (six little-endian bytes each, contiguous), each permuted under its
// own mask triple masks[j] = (m0, m1, m2), with the three 16-bit lane
// outputs stored little-endian at p0[2j], p1[2j], p2[2j].
//
// Per chunk the body is the same three BMI2 PEXTQ instructions as the
// per-chunk kernel Chunk48Lock, with the mask taken directly as a
// memory operand and the chunk bytes loaded / lane bytes stored in
// place. The batch amortises one ABI0 call (argument spill, CALL /
// RET, result reload) over n chunks and folds the byte packing that
// the Go caller would otherwise perform per chunk into two loads and
// three word stores. Throughput is bounded by PEXTQ issue (one port
// on Intel Haswell+ and AMD Zen 3+): ~3 cycles per chunk.
//
// The chunk is assembled from a 4-byte and a 2-byte load so the kernel
// never reads past src[6n]; the lane stores are exact 2-byte MOVW so
// nothing is written past p_i[2n]. Bits 48..63 of the assembled chunk
// are zero; PEXTQ under a mask confined to the 48-bit domain ignores
// them regardless.
//
// Constant-time: the trip count n is public; PEXTQ is data-oblivious
// (fixed latency) on the microarchitectural floor the per-chunk
// kernels already assume; no secret-indexed memory access.
//
// Frame (ABI0): n +0(FP) src +8(FP) masks +16(FP) p0 +24(FP)
// p1 +32(FP) p2 +40(FP). No SIMD state is touched.
TEXT ·chunk48LockBatch(SB), NOSPLIT, $0-48
	MOVQ n+0(FP), CX
	MOVQ src+8(FP), SI
	MOVQ masks+16(FP), DX
	MOVQ p0+24(FP), R8
	MOVQ p1+32(FP), R9
	MOVQ p2+40(FP), R10
	TESTQ CX, CX
	JLE  lockDone

lockLoop:
	MOVL    (SI), AX         // bytes 0..3 (zero-extended)
	MOVWQZX 4(SI), BX        // bytes 4..5
	SHLQ    $32, BX
	ORQ     BX, AX           // x = 48-bit chunk
	PEXTQ   (DX), AX, R11    // l0 = PEXT(x, m0)
	MOVW    R11, (R8)
	PEXTQ   8(DX), AX, R11   // l1 = PEXT(x, m1)
	MOVW    R11, (R9)
	PEXTQ   16(DX), AX, R11  // l2 = PEXT(x, m2)
	MOVW    R11, (R10)
	ADDQ    $6, SI
	ADDQ    $24, DX
	ADDQ    $2, R8
	ADDQ    $2, R9
	ADDQ    $2, R10
	DECQ    CX
	JNZ     lockLoop

lockDone:
	RET

// func unchunk48LockBatch(n int, masks *[3]uint64, p0, p1, p2 *byte, dst *byte)
//
// Batched inverse apply: for n consecutive chunks, the three 16-bit
// lane values read little-endian at p0[2j], p1[2j], p2[2j] are
// deposited under masks[j] = (m0, m1, m2) via three BMI2 PDEPQ
// instructions (mask as memory operand), OR-ed (the three deposits
// land in disjoint positions), and the resulting 48-bit chunk is
// stored as six little-endian bytes at dst[6j]. Exact 4-byte + 2-byte
// stores: nothing is written past dst[6n].
//
// Same amortisation, throughput bound and constant-time argument as
// chunk48LockBatch above.
//
// Frame (ABI0): n +0(FP) masks +8(FP) p0 +16(FP) p1 +24(FP)
// p2 +32(FP) dst +40(FP). No SIMD state is touched.
TEXT ·unchunk48LockBatch(SB), NOSPLIT, $0-48
	MOVQ n+0(FP), CX
	MOVQ masks+8(FP), DX
	MOVQ p0+16(FP), R8
	MOVQ p1+24(FP), R9
	MOVQ p2+32(FP), R10
	MOVQ dst+40(FP), DI
	TESTQ CX, CX
	JLE  unlockDone

unlockLoop:
	MOVWQZX (R8), AX
	PDEPQ   (DX), AX, R11    // PDEP(l0, m0)
	MOVWQZX (R9), AX
	PDEPQ   8(DX), AX, R12   // PDEP(l1, m1)
	ORQ     R12, R11
	MOVWQZX (R10), AX
	PDEPQ   16(DX), AX, R12  // PDEP(l2, m2)
	ORQ     R12, R11         // x = 48-bit chunk
	MOVL    R11, (DI)        // bytes 0..3
	SHRQ    $32, R11
	MOVW    R11, 4(DI)       // bytes 4..5
	ADDQ    $24, DX
	ADDQ    $2, R8
	ADDQ    $2, R9
	ADDQ    $2, R10
	ADDQ    $6, DI
	DECQ    CX
	JNZ     unlockLoop

unlockDone:
	RET
