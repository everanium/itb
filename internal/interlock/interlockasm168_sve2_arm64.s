//go:build arm64 && !purego && !noitbasm

#include "textflag.h"

// SVE2 batched chunk-apply kernels for the 168-bit interlock — the arm64
// counterpart of the amd64 BMI2 chunk168LockBatch / unchunk168LockBatch.
// Uses SVE2 BEXT / BDEP across the three 64-bit words of each 21-byte
// chunk (words 0..1 in lanes 0..1 of Z0/Z2, word 2 in lane 0 of Z1/Z3)
// and per-byte NEON VCNT + 0x0101010101010101 multiply-shift for the
// cross-word stitch shift counts c0 = popcnt(m[0]), c1 = popcnt(m[1]).
//
// Encoding (Arm ARM, SVE2 bit-permute, .D elements):
//   BEXT Zd.D, Zn.D, Zm.D = 0x45C0B000 | Zm<<16 | Zn<<5 | Zd
//   BDEP Zd.D, Zn.D, Zm.D = 0x45C0B400 | Zm<<16 | Zn<<5 | Zd

// BEXT Z4.D, Z0.D, Z2.D — part0, part1 = BEXT((x0, x1), (m0, m1))
#define BEXT_Z4_Z0_Z2 WORD $0x45C2B004
// BEXT Z5.D, Z1.D, Z3.D — part2 = BEXT(x2, m2)
#define BEXT_Z5_Z1_Z3 WORD $0x45C3B025
// BDEP Z4.D, Z0.D, Z2.D — d0, d1 = BDEP((l, l>>c0), (m0, m1))
#define BDEP_Z4_Z0_Z2 WORD $0x45C2B404
// BDEP Z5.D, Z1.D, Z3.D — d2 = BDEP(l>>(c0+c1), m2)
#define BDEP_Z5_Z1_Z3 WORD $0x45C3B425

// EXTRACT_LANE168_SVE2(MPTR, LPTR): extracts one 56-bit (7-byte) lane
// from (V0={x0,x1}, V1={x2,0}) under mask words at MPTR (advanced by 24)
// and stores 7 bytes at LPTR (advanced by 7).
#define EXTRACT_LANE168_SVE2(LPTR) \
	VLD1.P 16(R2), [V2.D2]; \
	MOVD   (R2), R6; \
	ADD    $8, R2, R2; \
	VMOV   R6, V3.D[0]; \
	BEXT_Z4_Z0_Z2; \
	BEXT_Z5_Z1_Z3; \
	VCNT   V2.B16, V6.B16; \
	VMOV   V6.D[0], R6; \
	MUL    R11, R6, R6; \
	LSR    $56, R6, R6; \
	VMOV   V6.D[1], R7; \
	MUL    R11, R7, R7; \
	LSR    $56, R7, R7; \
	VMOV   V4.D[0], R8; \
	VMOV   V4.D[1], R9; \
	VMOV   V5.D[0], R10; \
	LSL    R6, R9, R9; \
	ADD    R6, R7, R7; \
	LSL    R7, R10, R10; \
	ORR    R9, R8, R8; \
	ORR    R10, R8, R8; \
	MOVW   R8, (LPTR); \
	LSR    $32, R8, R9; \
	MOVH   R9, 4(LPTR); \
	LSR    $48, R8, R9; \
	MOVB   R9, 6(LPTR); \
	ADD    $7, LPTR, LPTR

// DEPOSIT_LANE168_SVE2(LPTR): reads one 56-bit (7-byte) lane from LPTR
// (advanced by 7), deposits under mask words at R2 (advanced by 24)
// into V4={d0,d1} and V5={d2,0}, and ORs into accumulators V7 and V8.
#define DEPOSIT_LANE168_SVE2(LPTR) \
	MOVWU  (LPTR), R8; \
	MOVHU  4(LPTR), R9; \
	ORR    R9<<32, R8, R8; \
	MOVBU  6(LPTR), R9; \
	ORR    R9<<48, R8, R8; \
	ADD    $7, LPTR, LPTR; \
	VLD1.P 16(R2), [V2.D2]; \
	MOVD   (R2), R6; \
	ADD    $8, R2, R2; \
	VMOV   R6, V3.D[0]; \
	VCNT   V2.B16, V6.B16; \
	VMOV   V6.D[0], R6; \
	MUL    R11, R6, R6; \
	LSR    $56, R6, R6; \
	VMOV   V6.D[1], R7; \
	MUL    R11, R7, R7; \
	LSR    $56, R7, R7; \
	VMOV   R8, V0.D[0]; \
	LSR    R6, R8, R9; \
	VMOV   R9, V0.D[1]; \
	LSR    R7, R9, R9; \
	VMOV   R9, V1.D[0]; \
	BDEP_Z4_Z0_Z2; \
	BDEP_Z5_Z1_Z3; \
	VORR   V4.B16, V7.B16, V7.B16; \
	VORR   V5.B16, V8.B16, V8.B16

// func chunk168LockBatchSVE2(n int, src *byte, masks *[3][3]uint64, p0, p1, p2 *byte)
TEXT ·chunk168LockBatchSVE2(SB), NOSPLIT, $0-48
	MOVD n+0(FP), R0
	MOVD src+8(FP), R1
	MOVD masks+16(FP), R2
	MOVD p0+24(FP), R3
	MOVD p1+32(FP), R4
	MOVD p2+40(FP), R5
	CMP  $0, R0
	BLE  lock168SVE2Done

	MOVD $0x0101010101010101, R11
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V3.B16, V3.B16, V3.B16

lock168SVE2Loop:
	MOVD  0(R1), R6
	MOVD  8(R1), R7
	VMOV  R6, V0.D[0]
	VMOV  R7, V0.D[1]
	MOVWU 16(R1), R6
	MOVBU 20(R1), R7
	ORR   R7<<32, R6, R6
	VMOV  R6, V1.D[0]
	ADD   $21, R1, R1

	EXTRACT_LANE168_SVE2(R3)
	EXTRACT_LANE168_SVE2(R4)
	EXTRACT_LANE168_SVE2(R5)

	SUBS $1, R0, R0
	BNE  lock168SVE2Loop

lock168SVE2Done:
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	MOVD ZR, R0
	MOVD ZR, R1
	MOVD ZR, R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD ZR, R5
	MOVD ZR, R6
	MOVD ZR, R7
	MOVD ZR, R8
	MOVD ZR, R9
	MOVD ZR, R10
	MOVD ZR, R11
	RET

// func unchunk168LockBatchSVE2(n int, masks *[3][3]uint64, p0, p1, p2 *byte, dst *byte)
TEXT ·unchunk168LockBatchSVE2(SB), NOSPLIT, $0-48
	MOVD n+0(FP), R0
	MOVD masks+8(FP), R2
	MOVD p0+16(FP), R3
	MOVD p1+24(FP), R4
	MOVD p2+32(FP), R5
	MOVD dst+40(FP), R1
	CMP  $0, R0
	BLE  unlock168SVE2Done

	MOVD $0x0101010101010101, R11
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V3.B16, V3.B16, V3.B16

unlock168SVE2Loop:
	VEOR V7.B16, V7.B16, V7.B16
	VEOR V8.B16, V8.B16, V8.B16

	DEPOSIT_LANE168_SVE2(R3)
	DEPOSIT_LANE168_SVE2(R4)
	DEPOSIT_LANE168_SVE2(R5)

	VMOV V7.D[0], R6
	VMOV V7.D[1], R7
	VMOV V8.D[0], R8
	MOVD R6, 0(R1)
	MOVD R7, 8(R1)
	MOVW R8, 16(R1)
	LSR  $32, R8, R8
	MOVB R8, 20(R1)
	ADD  $21, R1, R1

	SUBS $1, R0, R0
	BNE  unlock168SVE2Loop

unlock168SVE2Done:
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	VEOR V8.B16, V8.B16, V8.B16
	MOVD ZR, R0
	MOVD ZR, R1
	MOVD ZR, R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD ZR, R5
	MOVD ZR, R6
	MOVD ZR, R7
	MOVD ZR, R8
	MOVD ZR, R9
	MOVD ZR, R11
	RET
