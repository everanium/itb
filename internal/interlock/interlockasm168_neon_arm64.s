//go:build arm64 && !purego && !noitbasm

#include "textflag.h"

// NEON 8-lane batched combinadic unrank for the 168-bit interlock mask
// derivation — the arm64 counterpart of rankToMaskTripleUnrank168AVX512
// and rankToMaskTripleUnrank168AVX2. Processes the 8 logical lanes in
// 4 passes of 2-lane .D2 vectors with a zero-byte stack frame ($0-32).
//
// Two-half VTBX row gather (448 active bytes = 56 slots per limb row):
//   Each limb row is indexed by picked = 56 - krem in [0..56]:
//   - First half W0..W3 (slots 0..31, 256 bytes): gathered via 4 VTBX
//     instructions into DST (C_lo) using byte index V3 = (8*picked +
//     {0..7}) mod 256.
//   - Second half W4..W6 (slots 32..55, 192 bytes): because 8*32 = 256
//     === 0 (mod 256), V3 already holds 8*(picked - 32) + {0..7} for
//     picked in 32..56. Pre-filling V11 (C_hi) with 0xFF and running 3
//     VTBX instructions over W4..W6 gathers slots 32..55 and leaves
//     0xFFFFFFFFFFFFFFFF (UINT64_MAX) in V11 when picked == 56
//     (krem == 0, byte index 192..199 >= 64 on all three windows).
//   - A 64-bit VCMHS compare (picked >= 32) selects between C_hi (V11)
//     and C_lo (DST).

// GATHER_LIMB_NEON168(DST) loads 7 64-byte windows from R5 (448 bytes)
// and advances R5 by 512 bytes (1 full 64-qword limb row), gathering
// C(p, 56 - picked) into DST.
#define GATHER_LIMB_NEON168(DST) \
	VMOVI  $255, DST.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V3.B16, [V12.B16, V13.B16, V14.B16, V15.B16], DST.B16; \
	VSUB   V21.B16, V3.B16, V10.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V10.B16, [V12.B16, V13.B16, V14.B16, V15.B16], DST.B16; \
	VSUB   V21.B16, V10.B16, V10.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V10.B16, [V12.B16, V13.B16, V14.B16, V15.B16], DST.B16; \
	VSUB   V21.B16, V10.B16, V10.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V10.B16, [V12.B16, V13.B16, V14.B16, V15.B16], DST.B16; \
	VMOVI  $255, V11.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V3.B16, [V12.B16, V13.B16, V14.B16, V15.B16], V11.B16; \
	VSUB   V21.B16, V3.B16, V10.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V10.B16, [V12.B16, V13.B16, V14.B16, V15.B16], V11.B16; \
	VSUB   V21.B16, V10.B16, V10.B16; \
	VLD1.P 64(R5), [V12.B16, V13.B16, V14.B16, V15.B16]; \
	VTBX   V10.B16, [V12.B16, V13.B16, V14.B16, V15.B16], V11.B16; \
	ADD    $64, R5; \
	VCMHS  V23.D2, V4.D2, V10.D2; \
	VBIC   V10.B16, DST.B16, DST.B16; \
	VAND   V10.B16, V11.B16, V11.B16; \
	VORR   V11.B16, DST.B16, DST.B16

// REMAP_STEP_NEON168(U, ACC): one domain-bit step for a 2-lane pair.
// Extracts r = U & 1; deposits (s0 & r) << bit into ACC; shifts the
// 112-bit (s1:s0) in (V9:V8) right by r (1 bit when r == 1, 0 when r == 0);
// advances U >>= 1 and bit += 1.
#define REMAP_STEP_NEON168(U, ACC) \
	VAND  V20.B16, U.B16, V24.B16; \
	VUSHR $1, U.D2, U.D2; \
	VAND  V24.B16, V8.B16, V25.B16; \
	VUSHL V16.D2, V25.D2, V25.D2; \
	VORR  V25.B16, ACC.B16, ACC.B16; \
	VCMHS V20.D2, V24.D2, V26.D2; \
	VUSHR $1, V8.D2, V28.D2; \
	VSHL  $63, V9.D2, V29.D2; \
	VORR  V29.B16, V28.B16, V28.B16; \
	VBIC  V26.B16, V8.B16, V8.B16; \
	VAND  V26.B16, V28.B16, V28.B16; \
	VORR  V28.B16, V8.B16, V8.B16; \
	VUSHR $1, V9.D2, V29.D2; \
	VBIC  V26.B16, V9.B16, V9.B16; \
	VAND  V26.B16, V29.B16, V29.B16; \
	VORR  V29.B16, V9.B16, V9.B16; \
	VADD  V20.D2, V16.D2, V16.D2

// func rankToMaskTripleUnrank168NEON(idx0 *[3][8]uint64, idx1 *[2][8]uint64,
//                                    crow *[303][64]uint64, out *[3][3][8]uint64)
TEXT ·rankToMaskTripleUnrank168NEON(SB), NOSPLIT, $0-32
	MOVD idx0+0(FP), R0
	MOVD idx1+8(FP), R1
	MOVD crow+16(FP), R2
	MOVD out+24(FP), R3

	// Global vector constants:
	//   V20.D2  = 1
	//   V21.B16 = 64
	//   V22.B16 = 8
	//   V23.D2  = 32
	VMOVI $255, V20.B16
	VUSHR $63, V20.D2, V20.D2        // V20 = 1 (per qword)
	VMOVI $64, V21.B16
	VMOVI $8, V22.B16
	VSHL  $5, V20.D2, V23.D2         // V23 = 32 (per qword)

	MOVD $0, R10                     // pair byte offset: 0, 16, 32, 48

neonPairLoop:
	// ---- 1. Unrank m0 (p = 167..0, k = 56) for this 2-lane pair ----
	ADD  R10, R0, R6
	VLD1 (R6), [V0.D2]               // rem[0] = idx0[0][pair]
	ADD  $64, R6, R6
	VLD1 (R6), [V1.D2]               // rem[1] = idx0[1][pair]
	ADD  $64, R6, R6
	VLD1 (R6), [V2.D2]               // rem[2] = idx0[2][pair]

	VMOVQ $0x0706050403020100, $0x0706050403020100, V3 // kidx = {0..7}
	VEOR  V4.B16, V4.B16, V4.B16     // picked = 0
	VEOR  V5.B16, V5.B16, V5.B16     // m0_2 = 0
	VSHL  $39, V20.D2, V6.D2         // pbit = 1 << 39
	MOVD  R2, R5                     // R5 = &crow168PackedNEON[0][0] (p = 167)
	MOVD  $34, R4                    // 34 steps: p = 167..134 (3 limbs)

neonM0Loop2a:
	GATHER_LIMB_NEON168(V7)
	GATHER_LIMB_NEON168(V8)
	GATHER_LIMB_NEON168(V9)

	// 2-limb GE10 = ((rem[1]:rem[0]) >= (c[1]:c[0])) -> V28
	VCMHS V7.D2, V0.D2, V24.D2       // V24 = GE0 = (rem[0] >= c[0])
	VCMHS V8.D2, V1.D2, V25.D2       // V25 = GE1 = (rem[1] >= c[1])
	VCMHS V1.D2, V8.D2, V26.D2       // V26 = LE1 = (c[1] >= rem[1])
	VBIC  V26.B16, V25.B16, V27.B16  // V27 = GT1 = (rem[1] > c[1])
	VAND  V24.B16, V25.B16, V28.B16  // V28 = GE1 & GE0
	VORR  V27.B16, V28.B16, V28.B16  // V28 = GE10

	// 3-limb pick = ((rem[2]:rem[1]:rem[0]) >= (c[2]:c[1]:c[0])) -> V29
	VCMHS V9.D2, V2.D2, V25.D2       // V25 = GE2 = (rem[2] >= c[2])
	VCMHS V2.D2, V9.D2, V26.D2       // V26 = LE2 = (c[2] >= rem[2])
	VBIC  V26.B16, V25.B16, V27.B16  // V27 = GT2 = (rem[2] > c[2])
	VAND  V28.B16, V25.B16, V29.B16  // V29 = GE2 & GE10
	VORR  V27.B16, V29.B16, V29.B16  // V29 = pick

	// 3-limb masked borrow-subtract under V29
	VBIC  V24.B16, V29.B16, V30.B16  // V30 = (pick & ~GE0) ? -1 : 0
	VBIC  V28.B16, V29.B16, V31.B16  // V31 = (pick & ~GE10) ? -1 : 0
	VAND  V29.B16, V7.B16, V24.B16
	VSUB  V24.D2, V0.D2, V0.D2       // rem[0] -= (pick ? c[0] : 0)
	VAND  V29.B16, V8.B16, V24.B16
	VSUB  V24.D2, V1.D2, V1.D2       // rem[1] -= (pick ? c[1] : 0)
	VADD  V30.D2, V1.D2, V1.D2       // rem[1] -= borrow0
	VAND  V29.B16, V9.B16, V24.B16
	VSUB  V24.D2, V2.D2, V2.D2       // rem[2] -= (pick ? c[2] : 0)
	VADD  V31.D2, V2.D2, V2.D2       // rem[2] -= borrow1

	VAND  V29.B16, V6.B16, V24.B16
	VORR  V24.B16, V5.B16, V5.B16    // m0_2 |= (pick ? pbit : 0)
	VAND  V29.B16, V22.B16, V24.B16
	VADD  V24.B16, V3.B16, V3.B16    // kidx += (pick ? 8 : 0)
	VSUB  V29.D2, V4.D2, V4.D2       // picked += (pick ? 1 : 0)
	VUSHR $1, V6.D2, V6.D2           // pbit >>= 1
	SUBS  $1, R4, R4
	BNE   neonM0Loop2a

	// Sub-loop 2b: p = 133..128 (6 steps, 2 limbs -> m0_2 bits 5..0)
	MOVD $6, R4

neonM0Loop2b:
	GATHER_LIMB_NEON168(V7)
	GATHER_LIMB_NEON168(V8)

	VCMHS V7.D2, V0.D2, V24.D2
	VCMHS V8.D2, V1.D2, V25.D2
	VCMHS V1.D2, V8.D2, V26.D2
	VBIC  V26.B16, V25.B16, V27.B16
	VAND  V24.B16, V25.B16, V28.B16
	VORR  V27.B16, V28.B16, V28.B16  // V28 = pick

	VBIC  V24.B16, V28.B16, V30.B16  // V30 = (pick & ~GE0) ? -1 : 0
	VAND  V28.B16, V7.B16, V24.B16
	VSUB  V24.D2, V0.D2, V0.D2
	VAND  V28.B16, V8.B16, V24.B16
	VSUB  V24.D2, V1.D2, V1.D2
	VADD  V30.D2, V1.D2, V1.D2

	VAND  V28.B16, V6.B16, V24.B16
	VORR  V24.B16, V5.B16, V5.B16
	VAND  V28.B16, V22.B16, V24.B16
	VADD  V24.B16, V3.B16, V3.B16
	VSUB  V28.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM0Loop2b

	ADD  R10, R3, R6
	ADD  $128, R6, R6
	VST1 [V5.D2], (R6)               // out[0][2][pair] = m0_2

	// Sub-loop 1a: p = 127..67 (61 steps, 2 limbs -> m0_1 bits 63..3)
	VEOR V5.B16, V5.B16, V5.B16      // m0_1 = 0
	VSHL $63, V20.D2, V6.D2          // pbit = 1 << 63
	MOVD $61, R4

neonM0Loop1a:
	GATHER_LIMB_NEON168(V7)
	GATHER_LIMB_NEON168(V8)

	VCMHS V7.D2, V0.D2, V24.D2
	VCMHS V8.D2, V1.D2, V25.D2
	VCMHS V1.D2, V8.D2, V26.D2
	VBIC  V26.B16, V25.B16, V27.B16
	VAND  V24.B16, V25.B16, V28.B16
	VORR  V27.B16, V28.B16, V28.B16

	VBIC  V24.B16, V28.B16, V30.B16
	VAND  V28.B16, V7.B16, V24.B16
	VSUB  V24.D2, V0.D2, V0.D2
	VAND  V28.B16, V8.B16, V24.B16
	VSUB  V24.D2, V1.D2, V1.D2
	VADD  V30.D2, V1.D2, V1.D2

	VAND  V28.B16, V6.B16, V24.B16
	VORR  V24.B16, V5.B16, V5.B16
	VAND  V28.B16, V22.B16, V24.B16
	VADD  V24.B16, V3.B16, V3.B16
	VSUB  V28.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM0Loop1a

	// Sub-loop 1b: p = 66..64 (3 steps, 1 limb -> m0_1 bits 2..0)
	MOVD $3, R4

neonM0Loop1b:
	GATHER_LIMB_NEON168(V7)

	VCMHS V7.D2, V0.D2, V24.D2
	VAND  V24.B16, V7.B16, V25.B16
	VSUB  V25.D2, V0.D2, V0.D2
	VAND  V24.B16, V6.B16, V25.B16
	VORR  V25.B16, V5.B16, V5.B16
	VAND  V24.B16, V22.B16, V25.B16
	VADD  V25.B16, V3.B16, V3.B16
	VSUB  V24.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM0Loop1b

	ADD  R10, R3, R6
	ADD  $64, R6, R6
	VST1 [V5.D2], (R6)               // out[0][1][pair] = m0_1

	// Sub-loop 0: p = 63..0 (64 steps, 1 limb -> m0_0 bits 63..0)
	VEOR V5.B16, V5.B16, V5.B16      // m0_0 = 0
	VSHL $63, V20.D2, V6.D2          // pbit = 1 << 63
	MOVD $64, R4

neonM0Loop0:
	GATHER_LIMB_NEON168(V7)

	VCMHS V7.D2, V0.D2, V24.D2
	VAND  V24.B16, V7.B16, V25.B16
	VSUB  V25.D2, V0.D2, V0.D2
	VAND  V24.B16, V6.B16, V25.B16
	VORR  V25.B16, V5.B16, V5.B16
	VAND  V24.B16, V22.B16, V25.B16
	VADD  V25.B16, V3.B16, V3.B16
	VSUB  V24.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM0Loop0

	ADD  R10, R3, R6
	VST1 [V5.D2], (R6)               // out[0][0][pair] = m0_0

	// ---- 2. Unrank m1Local (p = 111..0, k = 56) for this 2-lane pair ----
	ADD  R10, R1, R6
	VLD1 (R6), [V0.D2]               // rem1[0] = idx1[0][pair]
	ADD  $64, R6, R6
	VLD1 (R6), [V1.D2]               // rem1[1] = idx1[1][pair]

	VMOVQ $0x0706050403020100, $0x0706050403020100, V3
	VEOR  V4.B16, V4.B16, V4.B16     // picked1 = 0
	VEOR  V5.B16, V5.B16, V5.B16     // s1 = 0
	VSHL  $47, V20.D2, V6.D2         // pbit = 1 << 47
	MOVD  $74752, R4
	ADD   R4, R2, R5                 // R5 = &crow168PackedNEON[146][0] (p = 111)
	MOVD  $45, R4                    // 45 steps: p = 111..67 (2 limbs)

neonM1Loop1a:
	GATHER_LIMB_NEON168(V7)
	GATHER_LIMB_NEON168(V8)

	VCMHS V7.D2, V0.D2, V24.D2
	VCMHS V8.D2, V1.D2, V25.D2
	VCMHS V1.D2, V8.D2, V26.D2
	VBIC  V26.B16, V25.B16, V27.B16
	VAND  V24.B16, V25.B16, V28.B16
	VORR  V27.B16, V28.B16, V28.B16

	VBIC  V24.B16, V28.B16, V30.B16
	VAND  V28.B16, V7.B16, V24.B16
	VSUB  V24.D2, V0.D2, V0.D2
	VAND  V28.B16, V8.B16, V24.B16
	VSUB  V24.D2, V1.D2, V1.D2
	VADD  V30.D2, V1.D2, V1.D2

	VAND  V28.B16, V6.B16, V24.B16
	VORR  V24.B16, V5.B16, V5.B16
	VAND  V28.B16, V22.B16, V24.B16
	VADD  V24.B16, V3.B16, V3.B16
	VSUB  V28.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM1Loop1a

	// Sub-loop 1b for m1Local: p = 66..64 (3 steps, 1 limb -> s1 bits 2..0)
	MOVD $3, R4

neonM1Loop1b:
	GATHER_LIMB_NEON168(V7)

	VCMHS V7.D2, V0.D2, V24.D2
	VAND  V24.B16, V7.B16, V25.B16
	VSUB  V25.D2, V0.D2, V0.D2
	VAND  V24.B16, V6.B16, V25.B16
	VORR  V25.B16, V5.B16, V5.B16
	VAND  V24.B16, V22.B16, V25.B16
	VADD  V25.B16, V3.B16, V3.B16
	VSUB  V24.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM1Loop1b

	VMOV V5.B16, V9.B16              // V9 = s1 (keep in register for remap!)

	// Sub-loop 0 for m1Local: p = 63..0 (64 steps, 1 limb -> s0 bits 63..0)
	VEOR V5.B16, V5.B16, V5.B16      // s0 = 0
	VSHL $63, V20.D2, V6.D2          // pbit = 1 << 63
	MOVD $64, R4

neonM1Loop0:
	GATHER_LIMB_NEON168(V7)

	VCMHS V7.D2, V0.D2, V24.D2
	VAND  V24.B16, V7.B16, V25.B16
	VSUB  V25.D2, V0.D2, V0.D2
	VAND  V24.B16, V6.B16, V25.B16
	VORR  V25.B16, V5.B16, V5.B16
	VAND  V24.B16, V22.B16, V25.B16
	VADD  V25.B16, V3.B16, V3.B16
	VSUB  V24.D2, V4.D2, V4.D2
	VUSHR $1, V6.D2, V6.D2
	SUBS  $1, R4, R4
	BNE   neonM1Loop0

	VMOV V5.B16, V8.B16              // V8 = s0 (with V9 = s1)

	// ---- 3. Remap (V9:V8) = (s1:s0) onto u = (~m0) & domain168 ----
	ADD   R10, R3, R6
	VLD1  (R6), [V0.D2]              // m0_0
	ADD   $64, R6, R6
	VLD1  (R6), [V1.D2]              // m0_1
	ADD   $64, R6, R6
	VLD1  (R6), [V2.D2]              // m0_2
	VMOVI $255, V17.B16              // V17 = all-ones (64-bit domain)
	VBIC  V0.B16, V17.B16, V0.B16    // V0 = u0 = ~m0_0
	VBIC  V1.B16, V17.B16, V1.B16    // V1 = u1 = ~m0_1
	VUSHR $24, V17.D2, V17.D2        // V17 = 0x000000FFFFFFFFFF (40-bit domain)
	VBIC  V2.B16, V17.B16, V2.B16    // V2 = u2 = (~m0_2) & domain40
	VMOV  V0.B16, V17.B16            // save u0 in V17
	VMOV  V1.B16, V18.B16            // save u1 in V18
	VMOV  V2.B16, V19.B16            // save u2 in V19

	// Word 0 remap (64 steps over u0 in V0 -> m1_0 in V12)
	VEOR V12.B16, V12.B16, V12.B16
	VEOR V16.B16, V16.B16, V16.B16   // bit = 0
	MOVD $64, R4

neonRemap0:
	REMAP_STEP_NEON168(V0, V12)
	SUBS $1, R4, R4
	BNE  neonRemap0

	// Word 1 remap (64 steps over u1 in V1 -> m1_1 in V13)
	VEOR V13.B16, V13.B16, V13.B16
	VEOR V16.B16, V16.B16, V16.B16   // bit = 0
	MOVD $64, R4

neonRemap1:
	REMAP_STEP_NEON168(V1, V13)
	SUBS $1, R4, R4
	BNE  neonRemap1

	// Word 2 remap (40 steps over u2 in V2 -> m1_2 in V14)
	VEOR V14.B16, V14.B16, V14.B16
	VEOR V16.B16, V16.B16, V16.B16   // bit = 0
	MOVD $40, R4

neonRemap2:
	REMAP_STEP_NEON168(V2, V14)
	SUBS $1, R4, R4
	BNE  neonRemap2

	// Store m1_0, m1_1, m1_2 and m2_0 = u0 ^ m1_0, m2_1 = u1 ^ m1_1, m2_2 = u2 ^ m1_2
	ADD  R10, R3, R6
	ADD  $192, R6, R6
	VST1 [V12.D2], (R6)              // out[1][0][pair] = m1_0
	ADD  $64, R6, R6
	VST1 [V13.D2], (R6)              // out[1][1][pair] = m1_1
	ADD  $64, R6, R6
	VST1 [V14.D2], (R6)              // out[1][2][pair] = m1_2

	VEOR V12.B16, V17.B16, V17.B16   // m2_0 = u0 ^ m1_0
	VEOR V13.B16, V18.B16, V18.B16   // m2_1 = u1 ^ m1_1
	VEOR V14.B16, V19.B16, V19.B16   // m2_2 = u2 ^ m1_2
	ADD  $64, R6, R6
	VST1 [V17.D2], (R6)              // out[2][0][pair] = m2_0
	ADD  $64, R6, R6
	VST1 [V18.D2], (R6)              // out[2][1][pair] = m2_1
	ADD  $64, R6, R6
	VST1 [V19.D2], (R6)              // out[2][2][pair] = m2_2

	ADD  $16, R10, R10
	CMP  $64, R10
	BLT  neonPairLoop

	// Epilogue: zero all V0..V31 and touched GPRs.
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	VEOR V8.B16, V8.B16, V8.B16
	VEOR V9.B16, V9.B16, V9.B16
	VEOR V10.B16, V10.B16, V10.B16
	VEOR V11.B16, V11.B16, V11.B16
	VEOR V12.B16, V12.B16, V12.B16
	VEOR V13.B16, V13.B16, V13.B16
	VEOR V14.B16, V14.B16, V14.B16
	VEOR V15.B16, V15.B16, V15.B16
	VEOR V16.B16, V16.B16, V16.B16
	VEOR V17.B16, V17.B16, V17.B16
	VEOR V18.B16, V18.B16, V18.B16
	VEOR V19.B16, V19.B16, V19.B16
	VEOR V20.B16, V20.B16, V20.B16
	VEOR V21.B16, V21.B16, V21.B16
	VEOR V22.B16, V22.B16, V22.B16
	VEOR V23.B16, V23.B16, V23.B16
	VEOR V24.B16, V24.B16, V24.B16
	VEOR V25.B16, V25.B16, V25.B16
	VEOR V26.B16, V26.B16, V26.B16
	VEOR V27.B16, V27.B16, V27.B16
	VEOR V28.B16, V28.B16, V28.B16
	VEOR V29.B16, V29.B16, V29.B16
	VEOR V30.B16, V30.B16, V30.B16
	VEOR V31.B16, V31.B16, V31.B16
	MOVD ZR, R0
	MOVD ZR, R1
	MOVD ZR, R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD ZR, R5
	MOVD ZR, R6
	MOVD ZR, R10
	RET
