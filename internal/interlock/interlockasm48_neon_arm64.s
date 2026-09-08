//go:build arm64 && !purego && !noitbasm

#include "textflag.h"

// NEON 8-lane batched combinadic unrank for the 48-bit interlock mask
// derivation — the arm64 counterpart of the amd64 AVX-512 / AVX2
// kernels. A NEON register holds 2 qword lanes, so the 8 logical lanes
// live in four registers per state vector and every position step is
// issued four times; all eight lanes share one binomial-row load. The
// out layout is identical to the amd64 kernels' ([3][8]uint64).
//
// AVX2 -> NEON construct mapping:
//   VPERMD row gather       -> two TBX byte-table lookups over the
//                              128-byte row held in eight registers
//                              (4-register windows, 64 bytes each). The
//                              per-lane index vector is the byte pattern
//                              8*npick + {0..7}, npick = positions
//                              picked so far, so the row is laid out by
//                              npick (slot s = C(p, 16 - s), see
//                              crow48PackedNEON). npick = 16 indexes
//                              past both windows: TBX leaves the
//                              all-ones seed in place, and the unsigned
//                              compare rank >= 0xFFFF... fails, which is
//                              the krem != 0 predicate of the amd64
//                              kernels folded into the gather.
//   K-mask / VPANDN pred    -> all-ones / zero lanes from CMHS (unsigned
//                              rank >= c), AND-masked ORR / SUB / ADD.
//   scalar PDEPQ remap tail -> fixed 48-step vector deposit walk: per
//                              domain bit the next m1Local bit is
//                              selected with a per-lane variable shift
//                              (USHL by a negative count) and placed
//                              with a variable left shift; a per-lane
//                              counter advances on the remaining-mask
//                              bit.
//
// Constant-time: the crow row address depends only on the loop counter
// (public). The secret per-lane pick count never addresses memory — it
// is consumed by register-only operations (TBX register permute, CMHS
// predicates, USHL variable shifts), all data-oblivious with fixed
// latency. Trip counts are fixed (48, 32, 48).
//
// The unsigned vector compare (CMHS) and the register-count shifts
// (USHL) are assembled by the Go 1.27 arm64 assembler, the module's
// minimum toolchain.
//
// Register plan (unrank loops):
//   V0-V3    rank lanes (pairs 0..3)
//   V4-V7    per-lane byte index vectors kidx = 8*npick + {0..7}
//   V8-V11   mask accumulators
//   V12-V19  current binomial row: slots 0..7 in V12-V15, 8..15 in V16-V19
//   V20      pbit = 1 << p (broadcast qword)
//   V21      bytes 64   V22 bytes 8
//   V24-V27  gathered c per pair   V28-V31 pick predicate per pair
// Register plan (remap walk):
//   V0-V3    remaining (shifted right per step)   V4-V7 -pos counters
//   V8-V11   m1Local   V12-V15 m1 accumulators    V16 bit position
//   V20      qword 1   V24-V27 r   V28-V31 v
//
// Frame: 4 pointer args = 32 bytes, no locals; the remaining lanes are
// parked in out[2] between the m0 unrank and the remap (out[2] is
// overwritten with m2 at the end).
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)

// UNRANK_PAIR(rank, kidx, mask, c, pick): one position step for one
// lane pair. c is seeded with all-ones, then the two TBX windows fill
// the in-range lanes; pick = rank >= c; the three AND-masked updates
// apply the pick to rank, mask and kidx.
#define UNRANK_PAIR(RK, KI, MK, C, PK) \
	VMOVI $255, C.B16; \
	VTBX KI.B16, [V12.B16, V13.B16, V14.B16, V15.B16], C.B16; \
	VSUB V21.B16, KI.B16, PK.B16; \
	VTBX PK.B16, [V16.B16, V17.B16, V18.B16, V19.B16], C.B16; \
	VCMHS C.D2, RK.D2, PK.D2; \
	VAND PK.B16, C.B16, C.B16; \
	VSUB C.D2, RK.D2, RK.D2; \
	VAND PK.B16, V20.B16, C.B16; \
	VORR C.B16, MK.B16, MK.B16; \
	VAND PK.B16, V22.B16, C.B16; \
	VADD C.B16, KI.B16, KI.B16

// UNRANK_POS: load the row at R4 (128 bytes), step R4 to the previous
// row, run all four lane pairs, advance pbit.
#define UNRANK_POS \
	VLD1.P 64(R4), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VLD1 (R4), [V16.B16, V17.B16, V18.B16, V19.B16]; \
	SUB $192, R4, R4; \
	UNRANK_PAIR(V0, V4, V8, V24, V28); \
	UNRANK_PAIR(V1, V5, V9, V25, V29); \
	UNRANK_PAIR(V2, V6, V10, V26, V30); \
	UNRANK_PAIR(V3, V7, V11, V27, V31); \
	VUSHR $1, V20.D2, V20.D2

// REMAP_PAIR(rem, npos, ml, acc, r, v): one domain-bit step for one
// lane pair: r = rem & 1; v = (ml >> pos) & r; acc |= v << bit;
// pos += r (kept negated for USHL); rem >>= 1.
#define REMAP_PAIR(RM, NP, ML, AC, R, V) \
	VAND V20.B16, RM.B16, R.B16; \
	VUSHR $1, RM.D2, RM.D2; \
	VUSHL NP.D2, ML.D2, V.D2; \
	VAND R.B16, V.B16, V.B16; \
	VUSHL V16.D2, V.D2, V.D2; \
	VORR V.B16, AC.B16, AC.B16; \
	VSUB R.D2, NP.D2, NP.D2

// func rankToMaskTripleUnrank48NEON(idx0 *[8]uint64, idx1 *[8]uint32,
//                                  crow *[49][16]uint64, out *[3][8]uint64)
TEXT ·rankToMaskTripleUnrank48NEON(SB), NOSPLIT, $0-32
	MOVD idx0+0(FP), R0
	MOVD idx1+8(FP), R1
	MOVD crow+16(FP), R2
	MOVD out+24(FP), R3

	VMOVI $64, V21.B16
	VMOVI $8, V22.B16

	// ---- m0 unrank: rank = idx0, n = 48, k = 16 ----
	VLD1 (R0), [V0.D2, V1.D2, V2.D2, V3.D2]
	VMOVQ $0x0706050403020100, $0x0706050403020100, V4
	VMOV V4.B16, V5.B16
	VMOV V4.B16, V6.B16
	VMOV V4.B16, V7.B16
	VEOR V8.B16, V8.B16, V8.B16
	VEOR V9.B16, V9.B16, V9.B16
	VEOR V10.B16, V10.B16, V10.B16
	VEOR V11.B16, V11.B16, V11.B16
	VMOVI $255, V20.B16
	VUSHR $63, V20.D2, V20.D2
	VSHL $47, V20.D2, V20.D2        // pbit = 1 << 47
	ADD $47*128, R2, R4             // &crow[47][0]
	MOVD $48, R5

m0Loop:
	UNRANK_POS
	SUBS $1, R5, R5
	BNE m0Loop

	// out[0] = m0; park remaining = (~m0) & domain in out[2].
	VST1 [V8.D2, V9.D2, V10.D2, V11.D2], (R3)
	VMOVI $255, V23.B16
	VUSHR $16, V23.D2, V23.D2       // domain = 0x0000_FFFF_FFFF_FFFF
	VBIC V8.B16, V23.B16, V8.B16
	VBIC V9.B16, V23.B16, V9.B16
	VBIC V10.B16, V23.B16, V10.B16
	VBIC V11.B16, V23.B16, V11.B16
	ADD $128, R3, R6
	VST1 [V8.D2, V9.D2, V10.D2, V11.D2], (R6)

	// ---- m1Local unrank: rank = idx1 (zero-extended), n = 32, k = 16 ----
	VLD1 (R1), [V0.S4, V1.S4]
	VUSHLL2 $0, V1.S4, V3.D2
	VUSHLL $0, V1.S2, V2.D2
	VUSHLL2 $0, V0.S4, V1.D2
	VUSHLL $0, V0.S2, V0.D2
	VMOVQ $0x0706050403020100, $0x0706050403020100, V4
	VMOV V4.B16, V5.B16
	VMOV V4.B16, V6.B16
	VMOV V4.B16, V7.B16
	VEOR V8.B16, V8.B16, V8.B16
	VEOR V9.B16, V9.B16, V9.B16
	VEOR V10.B16, V10.B16, V10.B16
	VEOR V11.B16, V11.B16, V11.B16
	VMOVI $255, V20.B16
	VUSHR $63, V20.D2, V20.D2
	VSHL $31, V20.D2, V20.D2        // pbit = 1 << 31
	ADD $31*128, R2, R4             // &crow[31][0]
	MOVD $32, R5

m1Loop:
	UNRANK_POS
	SUBS $1, R5, R5
	BNE m1Loop

	// ---- remap: m1 = deposit(m1Local, remaining), m2 = remaining ^ m1 ----
	// V8-V11 = m1Local. Reload remaining from out[2] into V0-V3.
	VLD1 (R6), [V0.D2, V1.D2, V2.D2, V3.D2]
	VEOR V4.B16, V4.B16, V4.B16     // -pos counters = 0
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	VEOR V12.B16, V12.B16, V12.B16  // m1 accumulators = 0
	VEOR V13.B16, V13.B16, V13.B16
	VEOR V14.B16, V14.B16, V14.B16
	VEOR V15.B16, V15.B16, V15.B16
	VEOR V16.B16, V16.B16, V16.B16  // bit position = 0
	VMOVI $255, V20.B16
	VUSHR $63, V20.D2, V20.D2       // qword 1
	MOVD $48, R5

remapLoop:
	REMAP_PAIR(V0, V4, V8, V12, V24, V28)
	REMAP_PAIR(V1, V5, V9, V13, V25, V29)
	REMAP_PAIR(V2, V6, V10, V14, V26, V30)
	REMAP_PAIR(V3, V7, V11, V15, V27, V31)
	VADD V20.D2, V16.D2, V16.D2     // bit position += 1
	SUBS $1, R5, R5
	BNE remapLoop

	// out[1] = m1; out[2] = remaining ^ m1 (m1 is a subset of remaining).
	ADD $64, R3, R7
	VST1 [V12.D2, V13.D2, V14.D2, V15.D2], (R7)
	VLD1 (R6), [V0.D2, V1.D2, V2.D2, V3.D2]
	VEOR V12.B16, V0.B16, V0.B16
	VEOR V13.B16, V1.B16, V1.B16
	VEOR V14.B16, V2.B16, V2.B16
	VEOR V15.B16, V3.B16, V3.B16
	VST1 [V0.D2, V1.D2, V2.D2, V3.D2], (R6)
	RET
