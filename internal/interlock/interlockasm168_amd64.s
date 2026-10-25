//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func Chunk168Lock(src *[21]byte, m0, m1, m2 [3]uint64, out *[3][7]byte)
//
// Frame layout (ABI0, 88 bytes):
//   src    at FP+0   (*[21]byte)
//   m0[0]  at FP+8   (uint64)
//   m0[1]  at FP+16  (uint64)
//   m0[2]  at FP+24  (uint64)
//   m1[0]  at FP+32  (uint64)
//   m1[1]  at FP+40  (uint64)
//   m1[2]  at FP+48  (uint64)
//   m2[0]  at FP+56  (uint64)
//   m2[1]  at FP+64  (uint64)
//   m2[2]  at FP+72  (uint64)
//   out    at FP+80  (*[3][7]byte)
//
// Extracts three 56-bit (7-byte) lanes from the 21-byte chunk (x0, x1, x2)
// under the three 3-word masks (m0, m1, m2) via three BMI2 PEXTQ calls and
// two POPCNTQ shifts per lane. Because popcnt(m_i[0]) + popcnt(m_i[1]) +
// popcnt(m_i[2]) == 56 < 64, the shift counts c0 and c0 + c1 are strictly
// less than 64.
TEXT ·Chunk168Lock(SB), NOSPLIT, $0-88
	MOVQ    src+0(FP), SI
	MOVQ    out+80(FP), DI
	MOVQ    0(SI), R8        // x0 (bits 0..63)
	MOVQ    8(SI), R9        // x1 (bits 64..127)
	MOVLQZX 16(SI), R10      // bytes 16..19
	MOVBQZX 20(SI), AX       // byte 20
	SHLQ    $32, AX
	ORQ     AX, R10          // x2 (bits 128..167, 40 bits)

	// Lane 0: m0 -> out[0] (bytes 0..6)
	MOVQ    m0_0+8(FP), BX
	PEXTQ   BX, R8, R11      // part0 = PEXT(x0, m0[0])
	POPCNTQ BX, CX           // c0 = popcnt(m0[0])
	MOVQ    m0_1+16(FP), DX
	PEXTQ   DX, R9, R12      // part1 = PEXT(x1, m0[1])
	POPCNTQ DX, AX           // c1 = popcnt(m0[1])
	SHLQ    CX, R12          // part1 << c0
	ADDQ    AX, CX           // c0 + c1
	MOVQ    m0_2+24(FP), BX
	PEXTQ   BX, R10, R13     // part2 = PEXT(x2, m0[2])
	SHLQ    CX, R13          // part2 << (c0 + c1)
	ORQ     R12, R11
	ORQ     R13, R11         // l0 (56 bits)
	MOVL    R11, 0(DI)
	SHRQ    $32, R11
	MOVW    R11, 4(DI)
	SHRQ    $16, R11
	MOVB    R11, 6(DI)

	// Lane 1: m1 -> out[1] (bytes 7..13)
	MOVQ    m1_0+32(FP), BX
	PEXTQ   BX, R8, R11
	POPCNTQ BX, CX
	MOVQ    m1_1+40(FP), DX
	PEXTQ   DX, R9, R12
	POPCNTQ DX, AX
	SHLQ    CX, R12
	ADDQ    AX, CX
	MOVQ    m1_2+48(FP), BX
	PEXTQ   BX, R10, R13
	SHLQ    CX, R13
	ORQ     R12, R11
	ORQ     R13, R11         // l1 (56 bits)
	MOVL    R11, 7(DI)
	SHRQ    $32, R11
	MOVW    R11, 11(DI)
	SHRQ    $16, R11
	MOVB    R11, 13(DI)

	// Lane 2: m2 -> out[2] (bytes 14..20)
	MOVQ    m2_0+56(FP), BX
	PEXTQ   BX, R8, R11
	POPCNTQ BX, CX
	MOVQ    m2_1+64(FP), DX
	PEXTQ   DX, R9, R12
	POPCNTQ DX, AX
	SHLQ    CX, R12
	ADDQ    AX, CX
	MOVQ    m2_2+72(FP), BX
	PEXTQ   BX, R10, R13
	SHLQ    CX, R13
	ORQ     R12, R11
	ORQ     R13, R11         // l2 (56 bits)
	MOVL    R11, 14(DI)
	SHRQ    $32, R11
	MOVW    R11, 18(DI)
	SHRQ    $16, R11
	MOVB    R11, 20(DI)

	XORQ AX, AX
	MOVQ AX, m0_0+8(FP)
	MOVQ AX, m0_1+16(FP)
	MOVQ AX, m0_2+24(FP)
	MOVQ AX, m1_0+32(FP)
	MOVQ AX, m1_1+40(FP)
	MOVQ AX, m1_2+48(FP)
	MOVQ AX, m2_0+56(FP)
	MOVQ AX, m2_1+64(FP)
	MOVQ AX, m2_2+72(FP)
	PXOR X14, X14
	PXOR X15, X15
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
	RET

// func Unchunk168Lock(p0, p1, p2 *[7]byte, m0, m1, m2 [3]uint64, dst *[21]byte)
//
// Frame layout (ABI0, 104 bytes):
//   p0     at FP+0   (*[7]byte)
//   p1     at FP+8   (*[7]byte)
//   p2     at FP+16  (*[7]byte)
//   m0[0]  at FP+24  (uint64)
//   m0[1]  at FP+32  (uint64)
//   m0[2]  at FP+40  (uint64)
//   m1[0]  at FP+48  (uint64)
//   m1[1]  at FP+56  (uint64)
//   m1[2]  at FP+64  (uint64)
//   m2[0]  at FP+72  (uint64)
//   m2[1]  at FP+80  (uint64)
//   m2[2]  at FP+88  (uint64)
//   dst    at FP+96  (*[21]byte)
//
// Reconstructs the 21-byte chunk (x0, x1, x2) from three 56-bit (7-byte)
// lanes (p0, p1, p2) under the three 3-word masks (m0, m1, m2) via three
// BMI2 PDEPQ calls and two POPCNTQ shifts per lane.
TEXT ·Unchunk168Lock(SB), NOSPLIT, $0-104
	// Lane 0: p0 under m0 -> initialize (R8, R9, R10)
	MOVQ    p0+0(FP), SI
	MOVLQZX 0(SI), R11
	MOVWQZX 4(SI), AX
	SHLQ    $32, AX
	ORQ     AX, R11
	MOVBQZX 6(SI), AX
	SHLQ    $48, AX
	ORQ     AX, R11          // l0 (56 bits)

	MOVQ    m0_0+24(FP), BX
	PDEPQ   BX, R11, R8      // x0 = PDEP(l0, m0[0])
	POPCNTQ BX, CX
	SHRQ    CX, R11          // l0 >> c0
	MOVQ    m0_1+32(FP), DX
	PDEPQ   DX, R11, R9      // x1 = PDEP(l0 >> c0, m0[1])
	POPCNTQ DX, CX
	SHRQ    CX, R11          // l0 >> (c0 + c1)
	MOVQ    m0_2+40(FP), BX
	PDEPQ   BX, R11, R10     // x2 = PDEP(l0 >> (c0 + c1), m0[2])

	// Lane 1: p1 under m1 -> OR into (R8, R9, R10)
	MOVQ    p1+8(FP), SI
	MOVLQZX 0(SI), R11
	MOVWQZX 4(SI), AX
	SHLQ    $32, AX
	ORQ     AX, R11
	MOVBQZX 6(SI), AX
	SHLQ    $48, AX
	ORQ     AX, R11          // l1 (56 bits)

	MOVQ    m1_0+48(FP), BX
	PDEPQ   BX, R11, R12
	ORQ     R12, R8
	POPCNTQ BX, CX
	SHRQ    CX, R11
	MOVQ    m1_1+56(FP), DX
	PDEPQ   DX, R11, R12
	ORQ     R12, R9
	POPCNTQ DX, CX
	SHRQ    CX, R11
	MOVQ    m1_2+64(FP), BX
	PDEPQ   BX, R11, R12
	ORQ     R12, R10

	// Lane 2: p2 under m2 -> OR into (R8, R9, R10)
	MOVQ    p2+16(FP), SI
	MOVLQZX 0(SI), R11
	MOVWQZX 4(SI), AX
	SHLQ    $32, AX
	ORQ     AX, R11
	MOVBQZX 6(SI), AX
	SHLQ    $48, AX
	ORQ     AX, R11          // l2 (56 bits)

	MOVQ    m2_0+72(FP), BX
	PDEPQ   BX, R11, R12
	ORQ     R12, R8
	POPCNTQ BX, CX
	SHRQ    CX, R11
	MOVQ    m2_1+80(FP), DX
	PDEPQ   DX, R11, R12
	ORQ     R12, R9
	POPCNTQ DX, CX
	SHRQ    CX, R11
	MOVQ    m2_2+88(FP), BX
	PDEPQ   BX, R11, R12
	ORQ     R12, R10

	// Store 21-byte chunk (R8, R9, R10) to dst
	MOVQ    dst+96(FP), DI
	MOVQ    R8, 0(DI)
	MOVQ    R9, 8(DI)
	MOVL    R10, 16(DI)
	SHRQ    $32, R10
	MOVB    R10, 20(DI)

	XORQ AX, AX
	MOVQ AX, m0_0+24(FP)
	MOVQ AX, m0_1+32(FP)
	MOVQ AX, m0_2+40(FP)
	MOVQ AX, m1_0+48(FP)
	MOVQ AX, m1_1+56(FP)
	MOVQ AX, m1_2+64(FP)
	MOVQ AX, m2_0+72(FP)
	MOVQ AX, m2_1+80(FP)
	MOVQ AX, m2_2+88(FP)
	PXOR X14, X14
	PXOR X15, X15
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
	RET

// GATHER_LIMB_AVX512(OFF, DST) loads one 64-qword (512-byte) limb row at
// OFF(R12) into Z16..Z23 and selects slot krem (in Z1) across the 4
// 16-qword windows using VPERMT2Q and VPBLENDMQ under window selector
// masks K3 = ((krem & 0x10) != 0) and K4 = ((krem & 0x20) != 0).
#define GATHER_LIMB_AVX512(OFF, DST) \
	VMOVDQA64 (OFF+0)(R12), Z16; \
	VMOVDQA64 (OFF+64)(R12), Z17; \
	VMOVDQA64 (OFF+128)(R12), Z18; \
	VMOVDQA64 (OFF+192)(R12), Z19; \
	VMOVDQA64 (OFF+256)(R12), Z20; \
	VMOVDQA64 (OFF+320)(R12), Z21; \
	VMOVDQA64 (OFF+384)(R12), Z22; \
	VMOVDQA64 (OFF+448)(R12), Z23; \
	VPERMT2Q  Z17, Z1, Z16; \
	VPERMT2Q  Z19, Z1, Z18; \
	VPERMT2Q  Z21, Z1, Z20; \
	VPERMT2Q  Z23, Z1, Z22; \
	VPBLENDMQ Z18, Z16, K3, Z16; \
	VPBLENDMQ Z22, Z20, K3, Z20; \
	VPBLENDMQ Z20, Z16, K4, DST

// func rankToMaskTripleUnrank168AVX512(idx0 *[3][8]uint64, idx1 *[2][8]uint64,
//                                      crow *[303][64]uint64, out *[3][3][8]uint64)
//
// 8-lane ZMM combinadic unrank for the 168-bit interlock mask derivation:
//   1. Unrank m0 (56-of-168 from idx0) across descending positions p = 167..0:
//      - p = 167..134 (34 steps, 3-limb compare & subtract -> m0_2 bits 39..6)
//      - p = 133..128 ( 6 steps, 2-limb compare & subtract -> m0_2 bits 5..0)
//      - p = 127..67  (61 steps, 2-limb compare & subtract -> m0_1 bits 63..3)
//      - p = 66..64   ( 3 steps, 1-limb compare & subtract -> m0_1 bits 2..0)
//      - p = 63..0    (64 steps, 1-limb compare & subtract -> m0_0 bits 63..0)
//   2. Unrank m1Local (56-of-112 from idx1) across descending positions p = 111..0:
//      - p = 111..67  (45 steps, 2-limb compare & subtract -> s1 bits 47..3)
//      - p = 66..64   ( 3 steps, 1-limb compare & subtract -> s1 bits 2..0)
//      - p = 63..0    (64 steps, 1-limb compare & subtract -> s0 bits 63..0)
//   3. Remap (s1:s0) onto u = (~m0) & domain168 across all 8 lanes via
//      three scalar BMI2 PDEPQ instructions per lane.
//
// Register allocation:
//   Z0, Z2, Z3 : running remainder rem[0] (lo), rem[1] (mid), rem[2] (hi)
//   Z1         : remaining count krem (initialized to 56)
//   Z4         : current output mask word accumulator
//   Z5         : current position bit 1 << (p & 63)
//   Z6, Z7, Z8 : gathered C(p, krem) limbs lo, mid, hi
//   Z16..Z23   : 4-window row load & VPERMT2Q scratch
//   Z27        : domain mask scratch in remap setup
//   Z28        : broadcast constant 1
//   Z29        : broadcast constant 16 (0x10)
//   Z30        : broadcast constant 32 (0x20)
//   Z31        : broadcast constant 56 (initial krem)
TEXT ·rankToMaskTripleUnrank168AVX512(SB), NOSPLIT, $0-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	// Synthesize constants in Z28..Z31 using EVEX-only instructions
	// (no legacy-SSE GPR->XMM bridges).
	VPTERNLOGQ $0xFF, Z28, Z28, Z28  // Z28 = all-ones
	VPSRLQ     $63, Z28, Z28         // Z28 = 1
	VPSLLQ     $4, Z28, Z29          // Z29 = 16 (0x10)
	VPSLLQ     $5, Z28, Z30          // Z30 = 32 (0x20)
	VPSLLQ     $3, Z28, Z31          // Z31 = 8
	VPORQ      Z29, Z31, Z31         // Z31 = 24
	VPORQ      Z30, Z31, Z31         // Z31 = 56

	// ---- 1. Unrank m0 (p = 167..0, krem = 56) ----
	VMOVDQU64 0(AX), Z0              // rem[0] = idx0[0]
	VMOVDQU64 64(AX), Z2             // rem[1] = idx0[1]
	VMOVDQU64 128(AX), Z3            // rem[2] = idx0[2]
	VMOVDQA64 Z31, Z1                // krem = 56
	VPXORQ    Z4, Z4, Z4             // m0_2 = 0
	VPSLLQ    $39, Z28, Z5           // bit = 1 << 39 (p = 167 -> bit 39 of m0_2)
	MOVQ      R14, R12               // R12 = &crow168Packed[0][0] (p = 167)
	MOVQ      $34, R10               // 34 steps: p = 167..134 (3 limbs)

m0Loop2a:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)
	GATHER_LIMB_AVX512(512, Z7)
	GATHER_LIMB_AVX512(1024, Z8)

	// 3-limb unsigned compare: (Z3:Z2:Z0) >= (Z8:Z7:Z6) -> K1
	VPCMPUQ $6, Z8, Z3, K1           // rem[2] > c[2]
	VPCMPUQ $0, Z8, Z3, K2           // rem[2] == c[2]
	VPCMPUQ $6, Z7, Z2, K2, K3       // (rem[2] == c[2]) & (rem[1] > c[1])
	VPCMPUQ $0, Z7, Z2, K2, K2       // (rem[2] == c[2]) & (rem[1] == c[1])
	VPCMPUQ $5, Z6, Z0, K2, K4       // (rem[2] == c[2]) & (rem[1] == c[1]) & (rem[0] >= c[0])
	KORW    K1, K3, K1
	KORW    K1, K4, K1               // K1 = pick

	// 3-limb masked borrow-subtract under K1
	VPCMPUQ $1, Z6, Z0, K1, K5       // K5 = borrow0: (rem[0] < c[0]) & K1
	VPSUBQ  Z6, Z0, K1, Z0           // rem[0] -= c[0]
	VPCMPUQ $1, Z7, Z2, K1, K6       // (rem[1] < c[1]) & K1
	VPCMPUQ $0, Z7, Z2, K5, K7       // (rem[1] == c[1]) & borrow0
	KORW    K6, K7, K6               // K6 = borrow1
	VPSUBQ  Z7, Z2, K1, Z2           // rem[1] -= c[1]
	VPSUBQ  Z28, Z2, K5, Z2          // rem[1] -= borrow0
	VPSUBQ  Z8, Z3, K1, Z3           // rem[2] -= c[2]
	VPSUBQ  Z28, Z3, K6, Z3          // rem[2] -= borrow1

	VPORQ   Z5, Z4, K1, Z4           // m0_2 |= bit
	VPSUBQ  Z28, Z1, K1, Z1          // krem -= 1
	VPSRLQ  $1, Z5, Z5               // bit >>= 1
	ADDQ    $1536, R12               // advance 3 limb-rows
	DECQ    R10
	JNZ     m0Loop2a

	// Sub-loop 2b: p = 133..128 (6 steps, 2 limbs -> m0_2 bits 5..0)
	MOVQ $6, R10

m0Loop2b:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)
	GATHER_LIMB_AVX512(512, Z7)

	VPCMPUQ $6, Z7, Z2, K1           // rem[1] > c[1]
	VPCMPUQ $0, Z7, Z2, K2           // rem[1] == c[1]
	VPCMPUQ $5, Z6, Z0, K2, K3       // (rem[1] == c[1]) & (rem[0] >= c[0])
	KORW    K1, K3, K1               // K1 = pick

	VPCMPUQ $1, Z6, Z0, K1, K5       // K5 = borrow0: (rem[0] < c[0]) & K1
	VPSUBQ  Z6, Z0, K1, Z0           // rem[0] -= c[0]
	VPSUBQ  Z7, Z2, K1, Z2           // rem[1] -= c[1]
	VPSUBQ  Z28, Z2, K5, Z2          // rem[1] -= borrow0

	VPORQ   Z5, Z4, K1, Z4           // m0_2 |= bit
	VPSUBQ  Z28, Z1, K1, Z1          // krem -= 1
	VPSRLQ  $1, Z5, Z5               // bit >>= 1
	ADDQ    $1024, R12               // advance 2 limb-rows
	DECQ    R10
	JNZ     m0Loop2b

	VMOVDQU64 Z4, 128(DI)            // out[0][2] = m0_2

	// Sub-loop 1a: p = 127..67 (61 steps, 2 limbs -> m0_1 bits 63..3)
	VPXORQ Z4, Z4, Z4                // m0_1 = 0
	VPSLLQ $63, Z28, Z5              // bit = 1 << 63
	MOVQ   $61, R10

m0Loop1a:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)
	GATHER_LIMB_AVX512(512, Z7)

	VPCMPUQ $6, Z7, Z2, K1
	VPCMPUQ $0, Z7, Z2, K2
	VPCMPUQ $5, Z6, Z0, K2, K3
	KORW    K1, K3, K1

	VPCMPUQ $1, Z6, Z0, K1, K5
	VPSUBQ  Z6, Z0, K1, Z0
	VPSUBQ  Z7, Z2, K1, Z2
	VPSUBQ  Z28, Z2, K5, Z2

	VPORQ   Z5, Z4, K1, Z4
	VPSUBQ  Z28, Z1, K1, Z1
	VPSRLQ  $1, Z5, Z5
	ADDQ    $1024, R12
	DECQ    R10
	JNZ     m0Loop1a

	// Sub-loop 1b: p = 66..64 (3 steps, 1 limb -> m0_1 bits 2..0)
	MOVQ $3, R10

m0Loop1b:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)

	VPCMPUQ $5, Z6, Z0, K1           // rem[0] >= c[0] (slot 0 == UINT64_MAX guards krem == 0)
	VPORQ   Z5, Z4, K1, Z4
	VPSUBQ  Z6, Z0, K1, Z0
	VPSUBQ  Z28, Z1, K1, Z1
	VPSRLQ  $1, Z5, Z5
	ADDQ    $512, R12
	DECQ    R10
	JNZ     m0Loop1b

	VMOVDQU64 Z4, 64(DI)             // out[0][1] = m0_1

	// Sub-loop 0: p = 63..0 (64 steps, 1 limb -> m0_0 bits 63..0)
	VPXORQ Z4, Z4, Z4                // m0_0 = 0
	VPSLLQ $63, Z28, Z5              // bit = 1 << 63
	MOVQ   $64, R10

m0Loop0:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)

	VPCMPUQ $5, Z6, Z0, K1
	VPORQ   Z5, Z4, K1, Z4
	VPSUBQ  Z6, Z0, K1, Z0
	VPSUBQ  Z28, Z1, K1, Z1
	VPSRLQ  $1, Z5, Z5
	ADDQ    $512, R12
	DECQ    R10
	JNZ     m0Loop0

	VMOVDQU64 Z4, 0(DI)              // out[0][0] = m0_0

	// ---- 2. Unrank m1Local (p = 111..0, krem = 56) ----
	VMOVDQU64 0(BX), Z0              // rem1[0] = idx1[0]
	VMOVDQU64 64(BX), Z2             // rem1[1] = idx1[1]
	VMOVDQA64 Z31, Z1                // krem1 = 56
	VPXORQ    Z4, Z4, Z4             // s1 = 0
	VPSLLQ    $47, Z28, Z5           // bit = 1 << 47 (p = 111 -> bit 47 of s1)
	LEAQ      74752(R14), R12        // R12 = &crow168Packed[146][0] (p = 111)
	MOVQ      $45, R10               // 45 steps: p = 111..67 (2 limbs)

m1Loop1a:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)
	GATHER_LIMB_AVX512(512, Z7)

	VPCMPUQ $6, Z7, Z2, K1
	VPCMPUQ $0, Z7, Z2, K2
	VPCMPUQ $5, Z6, Z0, K2, K3
	KORW    K1, K3, K1

	VPCMPUQ $1, Z6, Z0, K1, K5
	VPSUBQ  Z6, Z0, K1, Z0
	VPSUBQ  Z7, Z2, K1, Z2
	VPSUBQ  Z28, Z2, K5, Z2

	VPORQ   Z5, Z4, K1, Z4
	VPSUBQ  Z28, Z1, K1, Z1
	VPSRLQ  $1, Z5, Z5
	ADDQ    $1024, R12
	DECQ    R10
	JNZ     m1Loop1a

	// Sub-loop 1b for m1Local: p = 66..64 (3 steps, 1 limb -> s1 bits 2..0)
	MOVQ $3, R10

m1Loop1b:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)

	VPCMPUQ $5, Z6, Z0, K1
	VPORQ   Z5, Z4, K1, Z4
	VPSUBQ  Z6, Z0, K1, Z0
	VPSUBQ  Z28, Z1, K1, Z1
	VPSRLQ  $1, Z5, Z5
	ADDQ    $512, R12
	DECQ    R10
	JNZ     m1Loop1b

	VMOVDQU64 Z4, 256(DI)            // park s1 in out[1][1]

	// Sub-loop 0 for m1Local: p = 63..0 (64 steps, 1 limb -> s0 bits 63..0)
	VPXORQ Z4, Z4, Z4                // s0 = 0
	VPSLLQ $63, Z28, Z5              // bit = 1 << 63
	MOVQ   $64, R10

m1Loop0:
	VPTESTMQ Z29, Z1, K3
	VPTESTMQ Z30, Z1, K4
	GATHER_LIMB_AVX512(0, Z6)

	VPCMPUQ $5, Z6, Z0, K1
	VPORQ   Z5, Z4, K1, Z4
	VPSUBQ  Z6, Z0, K1, Z0
	VPSUBQ  Z28, Z1, K1, Z1
	VPSRLQ  $1, Z5, Z5
	ADDQ    $512, R12
	DECQ    R10
	JNZ     m1Loop0

	VMOVDQU64 Z4, 192(DI)            // park s0 in out[1][0]

	// ---- 3. Compute u = (~m0) & domain168 and park in out[2] ----
	VPTERNLOGQ $0xFF, Z27, Z27, Z27  // Z27 = all-ones (64-bit domain)
	VMOVDQU64  0(DI), Z0
	VPANDNQ    Z27, Z0, Z0           // u0 = ~m0_0
	VMOVDQU64  Z0, 384(DI)           // park u0 in out[2][0]

	VMOVDQU64  64(DI), Z2
	VPANDNQ    Z27, Z2, Z2           // u1 = ~m0_1
	VMOVDQU64  Z2, 448(DI)           // park u1 in out[2][1]

	VPSRLQ     $24, Z27, Z27         // Z27 = 0x000000FFFFFFFFFF (40-bit domain)
	VMOVDQU64  128(DI), Z3
	VPANDNQ    Z27, Z3, Z3           // u2 = (~m0_2) & 0xFFFFFFFFFF
	VMOVDQU64  Z3, 512(DI)           // park u2 in out[2][2]

	// ---- 4. 3-Word Scalar PDEPQ Remap Tail Across 8 Lanes ----
	XORQ SI, SI

remapLoop:
	MOVQ 384(DI)(SI*1), R8           // R8  = u0
	MOVQ 448(DI)(SI*1), R9           // R9  = u1
	MOVQ 512(DI)(SI*1), R10          // R10 = u2
	MOVQ 192(DI)(SI*1), R11          // R11 = s0
	MOVQ 256(DI)(SI*1), R12          // R12 = s1 (preserved until Word 2)

	// Word 0: m1_0 = PDEP(s0, u0), m2_0 = u0 ^ m1_0
	POPCNTQ R8, R14                  // R14 = z0 = popcnt(u0) in [8..64]
	PDEPQ   R8, R11, R13             // R13 = m1_0
	MOVQ    R13, 192(DI)(SI*1)       // out[1][0][j] = m1_0
	XORQ    R13, R8                  // R8  = m2_0
	MOVQ    R8, 384(DI)(SI*1)        // out[2][0][j] = m2_0

	// Word 1: shift (s1:s0) right by z0 in [8..64] via
	// ((s0 >> 1) >> (z0 - 1)) | (s1 << (64 - z0)), where both shift
	// counts (z0 - 1 in [7..63] and 64 - z0 in [0..56]) stay strictly below 64.
	MOVQ  R11, AX                    // AX = s0
	SHRQ  $1, AX                     // AX = s0 >> 1
	LEAQ  -1(R14), CX                // CX = z0 - 1 in [7..63]
	SHRQ  CX, AX                     // AX = (s0 >> 1) >> (z0 - 1)
	MOVQ  $64, CX
	SUBQ  R14, CX                    // CX = 64 - z0 in [0..56]
	MOVQ  R12, DX                    // DX = s1
	SHLQ  CX, DX                     // DX = s1 << (64 - z0)
	ORQ   DX, AX                     // AX = (s1:s0) >> z0
	PDEPQ R9, AX, R13                // R13 = m1_1
	MOVQ  R13, 256(DI)(SI*1)         // out[1][1][j] = m1_1
	XORQ  R13, R9                    // R9  = m2_1
	MOVQ  R9, 448(DI)(SI*1)          // out[2][1][j] = m2_1

	// Word 2: top z2 bits of (s1:s0) start at bit offset 48 - z2 in [8..48] of s1.
	POPCNTQ R10, R14                 // R14 = z2 = popcnt(u2) in [0..40]
	MOVQ    $48, CX
	SUBQ    R14, CX                  // CX = 48 - z2 in [8..48]
	MOVQ    R12, AX                  // AX = s1
	SHRQ    CX, AX                   // AX = s1 >> (48 - z2)
	PDEPQ   R10, AX, R13             // R13 = m1_2
	MOVQ    R13, 320(DI)(SI*1)       // out[1][2][j] = m1_2
	XORQ    R13, R10                 // R10 = m2_2
	MOVQ    R10, 512(DI)(SI*1)       // out[2][2][j] = m2_2

	ADDQ $8, SI
	CMPQ SI, $64
	JLT  remapLoop

	// Epilogue: zero all touched ZMM, K-mask, and GPR registers.
	VPXORD X0, X0, X0
	VPXORD X1, X1, X1
	VPXORD X2, X2, X2
	VPXORD X3, X3, X3
	VPXORD X4, X4, X4
	VPXORD X5, X5, X5
	VPXORD X6, X6, X6
	VPXORD X7, X7, X7
	VPXORD X8, X8, X8
	VPXORD X16, X16, X16
	VPXORD X17, X17, X17
	VPXORD X18, X18, X18
	VPXORD X19, X19, X19
	VPXORD X20, X20, X20
	VPXORD X21, X21, X21
	VPXORD X22, X22, X22
	VPXORD X23, X23, X23
	VPXORD X27, X27, X27
	VPXORD X28, X28, X28
	VPXORD X29, X29, X29
	VPXORD X30, X30, X30
	VPXORD X31, X31, X31
	KXORW  K1, K1, K1
	KXORW  K2, K2, K2
	KXORW  K3, K3, K3
	KXORW  K4, K4, K4
	KXORW  K5, K5, K5
	KXORW  K6, K6, K6
	KXORW  K7, K7, K7
	XORQ   AX, AX
	XORQ   BX, BX
	XORQ   CX, CX
	XORQ   DX, DX
	XORQ   SI, SI
	XORQ   DI, DI
	XORQ   R8, R8
	XORQ   R9, R9
	XORQ   R10, R10
	XORQ   R11, R11
	XORQ   R12, R12
	XORQ   R13, R13
	XORQ   R14, R14
	VZEROUPPER
	RET
