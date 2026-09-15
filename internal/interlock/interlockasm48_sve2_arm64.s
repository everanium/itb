//go:build arm64 && !purego && !noitbasm

#include "textflag.h"

// SVE2 batched chunk-apply kernels for the 48-bit interlock — the arm64
// counterpart of the amd64 BMI2 chunk48LockBatch / unchunk48LockBatch.
// SVE2 BEXT / BDEP are the vector forms of PEXT / PDEP: one instruction
// extracts (deposits) the bits of every 64-bit lane under the
// corresponding lane of a mask vector. Two chunks are processed per
// step in the low 128 bits of the Z registers (lanes 0 and 1, which
// alias V0..V31), so the kernels are independent of the implemented
// vector length: on a wider VL the upper lanes compute on stale data
// that is never read. The instructions are unpredicated, so no
// predicate register is touched.
//
// The Go arm64 assembler carries the SVE2 mnemonics (ZBEXT / ZBDEP)
// but accepts them only under GOEXPERIMENT=simd, so the six BEXT /
// BDEP instructions are emitted as raw words (WORD) — the same shape
// used elsewhere for instructions the default assembler does not
// accept. Encoding (Arm ARM, SVE2 bit-permute, .D elements):
//
//	BEXT Zd.D, Zn.D, Zm.D = 0x45C0B000 | Zm<<16 | Zn<<5 | Zd
//	BDEP Zd.D, Zn.D, Zm.D = 0x45C0B400 | Zm<<16 | Zn<<5 | Zd
//
// Each word below is annotated with the mnemonic it encodes; the
// package parity tests pin the kernels bit-exactly to the bit-serial
// reference, and a fixed-vector test pins the data / mask operand
// order.
//
// Chunk packing: per chunk the 48-bit word is assembled from a 4-byte
// and a 2-byte load (never reading past src[6n]) and inserted into a
// lane with a GPR->vector move; the three mask triples of two
// consecutive chunks are de-interleaved from the [n][3]uint64 array by
// one LD3 structure load (exactly 48 bytes, never past masks[n]). Lane
// results leave the vector file through GPR moves and exact 2-byte /
// 4-byte + 2-byte stores. An odd trailing chunk runs the same body on
// lane 0 with scalar mask loads (24 bytes, never past masks[n]).
//
// Constant-time: the trip count n is public; BEXT / BDEP are
// data-oblivious with fixed latency; no secret-indexed memory access.

// BEXT Z4.D, Z0.D, Z1.D — l0 lanes = BEXT(x, m0)
#define BEXT_Z4_Z0_Z1 WORD $0x45C1B004
// BEXT Z5.D, Z0.D, Z2.D — l1 lanes = BEXT(x, m1)
#define BEXT_Z5_Z0_Z2 WORD $0x45C2B005
// BEXT Z6.D, Z0.D, Z3.D — l2 lanes = BEXT(x, m2)
#define BEXT_Z6_Z0_Z3 WORD $0x45C3B006
// BDEP Z7.D, Z4.D, Z1.D — BDEP(l0, m0)
#define BDEP_Z7_Z4_Z1 WORD $0x45C1B487
// BDEP Z8.D, Z5.D, Z2.D — BDEP(l1, m1)
#define BDEP_Z8_Z5_Z2 WORD $0x45C2B4A8
// BDEP Z9.D, Z6.D, Z3.D — BDEP(l2, m2)
#define BDEP_Z9_Z6_Z3 WORD $0x45C3B4C9

// func chunk48LockBatchSVE2(n int, src *byte, masks *[3]uint64, p0, p1, p2 *byte)
//
// Frame (ABI0): n +0(FP) src +8(FP) masks +16(FP) p0 +24(FP)
// p1 +32(FP) p2 +40(FP).
TEXT ·chunk48LockBatchSVE2(SB), NOSPLIT, $0-48
	MOVD n+0(FP), R0
	MOVD src+8(FP), R1
	MOVD masks+16(FP), R2
	MOVD p0+24(FP), R3
	MOVD p1+32(FP), R4
	MOVD p2+40(FP), R5
	CMP $2, R0
	BLT lockTail

lockPair:
	VLD3.P 48(R2), [V1.D2, V2.D2, V3.D2]  // V1 = (m0, m0'), V2 = (m1, m1'), V3 = (m2, m2')
	MOVWU (R1), R6
	MOVHU 4(R1), R7
	ORR R7<<32, R6, R6                    // x  = chunk j
	MOVWU 6(R1), R7
	MOVHU 10(R1), R8
	ORR R8<<32, R7, R7                    // x' = chunk j+1
	ADD $12, R1, R1
	VMOV R6, V0.D[0]
	VMOV R7, V0.D[1]
	BEXT_Z4_Z0_Z1
	BEXT_Z5_Z0_Z2
	BEXT_Z6_Z0_Z3
	VMOV V4.D[0], R6
	MOVH R6, (R3)
	VMOV V4.D[1], R6
	MOVH R6, 2(R3)
	VMOV V5.D[0], R6
	MOVH R6, (R4)
	VMOV V5.D[1], R6
	MOVH R6, 2(R4)
	VMOV V6.D[0], R6
	MOVH R6, (R5)
	VMOV V6.D[1], R6
	MOVH R6, 2(R5)
	ADD $4, R3, R3
	ADD $4, R4, R4
	ADD $4, R5, R5
	SUB $2, R0, R0
	CMP $2, R0
	BGE lockPair

lockTail:
	CBZ R0, lockDone
	MOVD (R2), R6
	VMOV R6, V1.D[0]
	MOVD 8(R2), R6
	VMOV R6, V2.D[0]
	MOVD 16(R2), R6
	VMOV R6, V3.D[0]
	MOVWU (R1), R6
	MOVHU 4(R1), R7
	ORR R7<<32, R6, R6
	VMOV R6, V0.D[0]
	BEXT_Z4_Z0_Z1
	BEXT_Z5_Z0_Z2
	BEXT_Z6_Z0_Z3
	VMOV V4.D[0], R6
	MOVH R6, (R3)
	VMOV V5.D[0], R6
	MOVH R6, (R4)
	VMOV V6.D[0], R6
	MOVH R6, (R5)

lockDone:
	RET

// func unchunk48LockBatchSVE2(n int, masks *[3]uint64, p0, p1, p2 *byte, dst *byte)
//
// Frame (ABI0): n +0(FP) masks +8(FP) p0 +16(FP) p1 +24(FP)
// p2 +32(FP) dst +40(FP).
TEXT ·unchunk48LockBatchSVE2(SB), NOSPLIT, $0-48
	MOVD n+0(FP), R0
	MOVD masks+8(FP), R2
	MOVD p0+16(FP), R3
	MOVD p1+24(FP), R4
	MOVD p2+32(FP), R5
	MOVD dst+40(FP), R1
	CMP $2, R0
	BLT unlockTail

unlockPair:
	VLD3.P 48(R2), [V1.D2, V2.D2, V3.D2]
	MOVHU (R3), R6
	MOVHU 2(R3), R7
	VMOV R6, V4.D[0]
	VMOV R7, V4.D[1]
	MOVHU (R4), R6
	MOVHU 2(R4), R7
	VMOV R6, V5.D[0]
	VMOV R7, V5.D[1]
	MOVHU (R5), R6
	MOVHU 2(R5), R7
	VMOV R6, V6.D[0]
	VMOV R7, V6.D[1]
	BDEP_Z7_Z4_Z1
	BDEP_Z8_Z5_Z2
	BDEP_Z9_Z6_Z3
	VORR V8.B16, V7.B16, V7.B16
	VORR V9.B16, V7.B16, V7.B16           // x lanes
	VMOV V7.D[0], R6
	MOVW R6, (R1)
	LSR $32, R6, R6
	MOVH R6, 4(R1)
	VMOV V7.D[1], R6
	MOVW R6, 6(R1)
	LSR $32, R6, R6
	MOVH R6, 10(R1)
	ADD $12, R1, R1
	ADD $4, R3, R3
	ADD $4, R4, R4
	ADD $4, R5, R5
	SUB $2, R0, R0
	CMP $2, R0
	BGE unlockPair

unlockTail:
	CBZ R0, unlockDone
	MOVD (R2), R6
	VMOV R6, V1.D[0]
	MOVD 8(R2), R6
	VMOV R6, V2.D[0]
	MOVD 16(R2), R6
	VMOV R6, V3.D[0]
	MOVHU (R3), R6
	VMOV R6, V4.D[0]
	MOVHU (R4), R6
	VMOV R6, V5.D[0]
	MOVHU (R5), R6
	VMOV R6, V6.D[0]
	BDEP_Z7_Z4_Z1
	BDEP_Z8_Z5_Z2
	BDEP_Z9_Z6_Z3
	VORR V8.B16, V7.B16, V7.B16
	VORR V9.B16, V7.B16, V7.B16
	VMOV V7.D[0], R6
	MOVW R6, (R1)
	LSR $32, R6, R6
	MOVH R6, 4(R1)

unlockDone:
	RET
