//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// AVX2 4-lane batched combinadic unrank for the 168-bit interlock mask
// derivation — the AVX2 counterpart of rankToMaskTripleUnrank168AVX512
// (interlockasm168_amd64.s). Each YMM register holds 4 qword lanes, so
// the 8-lane batch executes as two 4-lane passes (half = 0, 1) reading
// the shared crow168Packed table ([303][64]uint64), followed by the
// 8-lane 3-word BMI2 PDEPQ remap tail.
//
// Constant-time: row addresses depend only on the public descending
// position p; the secret per-lane krem index in [0..56] is consumed by
// register-only VPERMD within-group gathers and VPCMPEQQ group-equality
// merges across the 15 active 4-qword groups (slots 0..59, where slot 0
// holds 0xFFFFFFFFFFFFFFFF and slots 1..56 hold C(p, 1..56)). Unsigned
// 64-bit comparisons use sign-flipped VPCMPGTQ (XOR with 1<<63).

// il168qrow: rows 0..14 (broadcast qword g for group comparison hi == g)
// plus row 15 (broadcast qword 56, initial krem value).
DATA il168qrow<>+0x000(SB)/8, $0
DATA il168qrow<>+0x008(SB)/8, $0
DATA il168qrow<>+0x010(SB)/8, $0
DATA il168qrow<>+0x018(SB)/8, $0
DATA il168qrow<>+0x020(SB)/8, $1
DATA il168qrow<>+0x028(SB)/8, $1
DATA il168qrow<>+0x030(SB)/8, $1
DATA il168qrow<>+0x038(SB)/8, $1
DATA il168qrow<>+0x040(SB)/8, $2
DATA il168qrow<>+0x048(SB)/8, $2
DATA il168qrow<>+0x050(SB)/8, $2
DATA il168qrow<>+0x058(SB)/8, $2
DATA il168qrow<>+0x060(SB)/8, $3
DATA il168qrow<>+0x068(SB)/8, $3
DATA il168qrow<>+0x070(SB)/8, $3
DATA il168qrow<>+0x078(SB)/8, $3
DATA il168qrow<>+0x080(SB)/8, $4
DATA il168qrow<>+0x088(SB)/8, $4
DATA il168qrow<>+0x090(SB)/8, $4
DATA il168qrow<>+0x098(SB)/8, $4
DATA il168qrow<>+0x0a0(SB)/8, $5
DATA il168qrow<>+0x0a8(SB)/8, $5
DATA il168qrow<>+0x0b0(SB)/8, $5
DATA il168qrow<>+0x0b8(SB)/8, $5
DATA il168qrow<>+0x0c0(SB)/8, $6
DATA il168qrow<>+0x0c8(SB)/8, $6
DATA il168qrow<>+0x0d0(SB)/8, $6
DATA il168qrow<>+0x0d8(SB)/8, $6
DATA il168qrow<>+0x0e0(SB)/8, $7
DATA il168qrow<>+0x0e8(SB)/8, $7
DATA il168qrow<>+0x0f0(SB)/8, $7
DATA il168qrow<>+0x0f8(SB)/8, $7
DATA il168qrow<>+0x100(SB)/8, $8
DATA il168qrow<>+0x108(SB)/8, $8
DATA il168qrow<>+0x110(SB)/8, $8
DATA il168qrow<>+0x118(SB)/8, $8
DATA il168qrow<>+0x120(SB)/8, $9
DATA il168qrow<>+0x128(SB)/8, $9
DATA il168qrow<>+0x130(SB)/8, $9
DATA il168qrow<>+0x138(SB)/8, $9
DATA il168qrow<>+0x140(SB)/8, $10
DATA il168qrow<>+0x148(SB)/8, $10
DATA il168qrow<>+0x150(SB)/8, $10
DATA il168qrow<>+0x158(SB)/8, $10
DATA il168qrow<>+0x160(SB)/8, $11
DATA il168qrow<>+0x168(SB)/8, $11
DATA il168qrow<>+0x170(SB)/8, $11
DATA il168qrow<>+0x178(SB)/8, $11
DATA il168qrow<>+0x180(SB)/8, $12
DATA il168qrow<>+0x188(SB)/8, $12
DATA il168qrow<>+0x190(SB)/8, $12
DATA il168qrow<>+0x198(SB)/8, $12
DATA il168qrow<>+0x1a0(SB)/8, $13
DATA il168qrow<>+0x1a8(SB)/8, $13
DATA il168qrow<>+0x1b0(SB)/8, $13
DATA il168qrow<>+0x1b8(SB)/8, $13
DATA il168qrow<>+0x1c0(SB)/8, $14
DATA il168qrow<>+0x1c8(SB)/8, $14
DATA il168qrow<>+0x1d0(SB)/8, $14
DATA il168qrow<>+0x1d8(SB)/8, $14
DATA il168qrow<>+0x1e0(SB)/8, $56
DATA il168qrow<>+0x1e8(SB)/8, $56
DATA il168qrow<>+0x1f0(SB)/8, $56
DATA il168qrow<>+0x1f8(SB)/8, $56
GLOBL il168qrow<>(SB), RODATA|NOPTR, $512

// il168dadd01: per-qword dword pair [0, 1] used to build VPERMD control
// [2*(krem&3), 2*(krem&3)+1].
DATA il168dadd01<>+0x000(SB)/8, $0x0000000100000000
DATA il168dadd01<>+0x008(SB)/8, $0x0000000100000000
DATA il168dadd01<>+0x010(SB)/8, $0x0000000100000000
DATA il168dadd01<>+0x018(SB)/8, $0x0000000100000000
GLOBL il168dadd01<>(SB), RODATA|NOPTR, $32

// il168qdomain40: broadcast 40-bit top-word domain mask.
DATA il168qdomain40<>+0x000(SB)/8, $0x000000FFFFFFFFFF
DATA il168qdomain40<>+0x008(SB)/8, $0x000000FFFFFFFFFF
DATA il168qdomain40<>+0x010(SB)/8, $0x000000FFFFFFFFFF
DATA il168qdomain40<>+0x018(SB)/8, $0x000000FFFFFFFFFF
GLOBL il168qdomain40<>(SB), RODATA|NOPTR, $32

// PREP_INDEX_AVX2 computes VPERMD control Y3 = [2*(krem&3), 2*(krem&3)+1]
// and 4-qword group index Y9 = krem >> 2 (in 0..14) from Y1 (krem).
#define PREP_INDEX_AVX2 \
	VPAND   il168qrow<>+0x060(SB), Y1, Y3; \
	VPSLLQ  $1, Y3, Y3; \
	VPSHUFD $0xA0, Y3, Y3; \
	VPADDD  il168dadd01<>(SB), Y3, Y3; \
	VPSRLQ  $2, Y1, Y9

// GATHER_LIMB_AVX2(OFF, DST) gathers C(p, krem) from the 64-qword limb
// row at OFF(R12) into DST using Y3 (within-group VPERMD control) and
// Y9 (group index hi = krem >> 2 in 0..14), with Y10 and Y11 as scratch.
#define GATHER_LIMB_AVX2(OFF, DST) \
	VPCMPEQQ il168qrow<>+0x000(SB), Y9, Y11; \
	VPERMD   (OFF+0)(R12), Y3, Y10; \
	VPAND    Y10, Y11, DST; \
	VPCMPEQQ il168qrow<>+0x020(SB), Y9, Y11; \
	VPERMD   (OFF+32)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x040(SB), Y9, Y11; \
	VPERMD   (OFF+64)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x060(SB), Y9, Y11; \
	VPERMD   (OFF+96)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x080(SB), Y9, Y11; \
	VPERMD   (OFF+128)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x0a0(SB), Y9, Y11; \
	VPERMD   (OFF+160)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x0c0(SB), Y9, Y11; \
	VPERMD   (OFF+192)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x0e0(SB), Y9, Y11; \
	VPERMD   (OFF+224)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x100(SB), Y9, Y11; \
	VPERMD   (OFF+256)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x120(SB), Y9, Y11; \
	VPERMD   (OFF+288)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x140(SB), Y9, Y11; \
	VPERMD   (OFF+320)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x160(SB), Y9, Y11; \
	VPERMD   (OFF+352)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x180(SB), Y9, Y11; \
	VPERMD   (OFF+384)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x1a0(SB), Y9, Y11; \
	VPERMD   (OFF+416)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST; \
	VPCMPEQQ il168qrow<>+0x1c0(SB), Y9, Y11; \
	VPERMD   (OFF+448)(R12), Y3, Y10; \
	VPAND    Y10, Y11, Y11; \
	VPOR     Y11, DST, DST

// func rankToMaskTripleUnrank168AVX2(idx0 *[3][8]uint64, idx1 *[2][8]uint64,
//                                    crow *[303][64]uint64, out *[3][3][8]uint64)
//
// Register allocation per 4-lane half:
//   Y0, Y2, Y8 : running remainder rem[0] (lo), rem[1] (mid), rem[2] (hi)
//   Y1         : remaining count krem (initialized to 56)
//   Y4         : current output mask word accumulator
//   Y5         : current position bit 1 << (p & 63)
//   Y6, Y7, Y14: gathered C(p, krem) limbs lo, mid, hi
//   Y3, Y9..Y13: gather & unsigned-compare/borrow scratch
//   Y15        : broadcast sign bit 0x8000000000000000 for unsigned VPCMPGTQ
TEXT ·rankToMaskTripleUnrank168AVX2(SB), NOSPLIT, $0-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	XORQ     SI, SI                  // half byte offset: 0, then 32
	VPCMPEQD Y15, Y15, Y15           // Y15 = all-ones
	VPSLLQ   $63, Y15, Y15           // Y15 = 0x8000000000000000 (1 << 63)

avx2HalfLoop:
	// ---- 1. Unrank m0 (p = 167..0, krem = 56) ----
	VMOVDQU 0(AX)(SI*1), Y0          // rem[0] = idx0[0][half]
	VMOVDQU 64(AX)(SI*1), Y2         // rem[1] = idx0[1][half]
	VMOVDQU 128(AX)(SI*1), Y8        // rem[2] = idx0[2][half]
	VMOVDQA il168qrow<>+0x1e0(SB), Y1 // krem = 56
	VPXOR   Y4, Y4, Y4               // m0_2 = 0
	VPSRLQ  $24, Y15, Y5             // bit = 1 << 39 (from 1 << 63 >> 24)
	MOVQ    R14, R12                 // R12 = &crow168Packed[0][0] (p = 167)
	MOVQ    $34, R10                 // 34 steps: p = 167..134 (3 limbs)

avx2M0Loop2a:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)
	GATHER_LIMB_AVX2(512, Y7)
	GATHER_LIMB_AVX2(1024, Y14)

	// Limb 0 borrow: Y10 = (c[0] >_u rem[0])
	VPXOR    Y15, Y0, Y9
	VPXOR    Y15, Y6, Y10
	VPCMPGTQ Y9, Y10, Y10

	// Limb 1 borrow: Y11 = (c[1] >_u rem[1]) | ((c[1] == rem[1]) & Y10)
	VPXOR    Y15, Y2, Y9
	VPXOR    Y15, Y7, Y11
	VPCMPEQQ Y9, Y11, Y12
	VPCMPGTQ Y9, Y11, Y11
	VPAND    Y12, Y10, Y12
	VPOR     Y12, Y11, Y11

	// Limb 2 notpick: Y9 = (c[2] >_u rem[2]) | ((c[2] == rem[2]) & Y11)
	VPXOR    Y15, Y8, Y9
	VPXOR    Y15, Y14, Y12
	VPCMPEQQ Y9, Y12, Y13
	VPCMPGTQ Y9, Y12, Y9
	VPAND    Y13, Y11, Y13
	VPOR     Y13, Y9, Y9             // Y9 = notpick

	// Masked 3-limb update (pick = ~Y9)
	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4             // m0_2 |= (pick ? bit : 0)
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0             // rem[0] -= (pick ? c[0] : 0)
	VPANDN   Y7, Y9, Y13
	VPSUBQ   Y13, Y2, Y2             // rem[1] -= (pick ? c[1] : 0)
	VPANDN   Y10, Y9, Y13            // (pick & borrow0) ? -1 : 0
	VPADDQ   Y13, Y2, Y2             // rem[1] -= (pick & borrow0)
	VPANDN   Y14, Y9, Y13
	VPSUBQ   Y13, Y8, Y8             // rem[2] -= (pick ? c[2] : 0)
	VPANDN   Y11, Y9, Y13            // (pick & borrow1) ? -1 : 0
	VPADDQ   Y13, Y8, Y8             // rem[2] -= (pick & borrow1)
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1             // krem -= (pick ? 1 : 0)
	VPSRLQ   $1, Y5, Y5
	ADDQ     $1536, R12
	DECQ     R10
	JNZ      avx2M0Loop2a

	// Sub-loop 2b: p = 133..128 (6 steps, 2 limbs -> m0_2 bits 5..0)
	MOVQ $6, R10

avx2M0Loop2b:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)
	GATHER_LIMB_AVX2(512, Y7)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y10             // Y10 = borrow0 = (c[0] >_u rem[0])

	VPXOR    Y15, Y2, Y8
	VPXOR    Y15, Y7, Y9
	VPCMPEQQ Y8, Y9, Y12
	VPCMPGTQ Y8, Y9, Y11
	VPAND    Y12, Y10, Y12
	VPOR     Y12, Y11, Y9            // Y9 = notpick

	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   Y7, Y9, Y13
	VPSUBQ   Y13, Y2, Y2
	VPANDN   Y10, Y9, Y13
	VPADDQ   Y13, Y2, Y2
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $1024, R12
	DECQ     R10
	JNZ      avx2M0Loop2b

	VMOVDQU Y4, 128(DI)(SI*1)        // out[0][2][half] = m0_2

	// Sub-loop 1a: p = 127..67 (61 steps, 2 limbs -> m0_1 bits 63..3)
	VPXOR   Y4, Y4, Y4               // m0_1 = 0
	VMOVDQA Y15, Y5                  // bit = 1 << 63
	MOVQ    $61, R10

avx2M0Loop1a:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)
	GATHER_LIMB_AVX2(512, Y7)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y10

	VPXOR    Y15, Y2, Y8
	VPXOR    Y15, Y7, Y9
	VPCMPEQQ Y8, Y9, Y12
	VPCMPGTQ Y8, Y9, Y11
	VPAND    Y12, Y10, Y12
	VPOR     Y12, Y11, Y9

	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   Y7, Y9, Y13
	VPSUBQ   Y13, Y2, Y2
	VPANDN   Y10, Y9, Y13
	VPADDQ   Y13, Y2, Y2
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $1024, R12
	DECQ     R10
	JNZ      avx2M0Loop1a

	// Sub-loop 1b: p = 66..64 (3 steps, 1 limb -> m0_1 bits 2..0)
	MOVQ $3, R10

avx2M0Loop1b:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y9              // Y9 = notpick = (c[0] >_u rem[0])
	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $512, R12
	DECQ     R10
	JNZ      avx2M0Loop1b

	VMOVDQU Y4, 64(DI)(SI*1)         // out[0][1][half] = m0_1

	// Sub-loop 0: p = 63..0 (64 steps, 1 limb -> m0_0 bits 63..0)
	VPXOR   Y4, Y4, Y4               // m0_0 = 0
	VMOVDQA Y15, Y5                  // bit = 1 << 63
	MOVQ    $64, R10

avx2M0Loop0:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y9
	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $512, R12
	DECQ     R10
	JNZ      avx2M0Loop0

	VMOVDQU Y4, 0(DI)(SI*1)          // out[0][0][half] = m0_0

	// ---- 2. Unrank m1Local (p = 111..0, krem = 56) ----
	VMOVDQU 0(BX)(SI*1), Y0          // rem1[0] = idx1[0][half]
	VMOVDQU 64(BX)(SI*1), Y2         // rem1[1] = idx1[1][half]
	VMOVDQA il168qrow<>+0x1e0(SB), Y1 // krem1 = 56
	VPXOR   Y4, Y4, Y4               // s1 = 0
	VPSRLQ  $16, Y15, Y5             // bit = 1 << 47 (from 1 << 63 >> 16)
	LEAQ    74752(R14), R12          // R12 = &crow168Packed[146][0] (p = 111)
	MOVQ    $45, R10                 // 45 steps: p = 111..67 (2 limbs)

avx2M1Loop1a:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)
	GATHER_LIMB_AVX2(512, Y7)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y10

	VPXOR    Y15, Y2, Y8
	VPXOR    Y15, Y7, Y9
	VPCMPEQQ Y8, Y9, Y12
	VPCMPGTQ Y8, Y9, Y11
	VPAND    Y12, Y10, Y12
	VPOR     Y12, Y11, Y9

	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   Y7, Y9, Y13
	VPSUBQ   Y13, Y2, Y2
	VPANDN   Y10, Y9, Y13
	VPADDQ   Y13, Y2, Y2
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $1024, R12
	DECQ     R10
	JNZ      avx2M1Loop1a

	// Sub-loop 1b for m1Local: p = 66..64 (3 steps, 1 limb -> s1 bits 2..0)
	MOVQ $3, R10

avx2M1Loop1b:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y9
	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $512, R12
	DECQ     R10
	JNZ      avx2M1Loop1b

	VMOVDQU Y4, 256(DI)(SI*1)        // park s1 in out[1][1][half]

	// Sub-loop 0 for m1Local: p = 63..0 (64 steps, 1 limb -> s0 bits 63..0)
	VPXOR   Y4, Y4, Y4               // s0 = 0
	VMOVDQA Y15, Y5                  // bit = 1 << 63
	MOVQ    $64, R10

avx2M1Loop0:
	PREP_INDEX_AVX2
	GATHER_LIMB_AVX2(0, Y6)

	VPXOR    Y15, Y0, Y8
	VPXOR    Y15, Y6, Y9
	VPCMPGTQ Y8, Y9, Y9
	VPANDN   Y5, Y9, Y13
	VPOR     Y13, Y4, Y4
	VPANDN   Y6, Y9, Y13
	VPSUBQ   Y13, Y0, Y0
	VPANDN   il168qrow<>+0x020(SB), Y9, Y13
	VPSUBQ   Y13, Y1, Y1
	VPSRLQ   $1, Y5, Y5
	ADDQ     $512, R12
	DECQ     R10
	JNZ      avx2M1Loop0

	VMOVDQU Y4, 192(DI)(SI*1)        // park s0 in out[1][0][half]

	// ---- 3. Compute u = (~m0) & domain168 for this half and park in out[2] ----
	VPCMPEQD Y13, Y13, Y13           // Y13 = all-ones (64-bit domain)
	VMOVDQU  0(DI)(SI*1), Y0
	VPANDN   Y13, Y0, Y0             // u0 = ~m0_0
	VMOVDQU  Y0, 384(DI)(SI*1)       // park u0 in out[2][0][half]

	VMOVDQU  64(DI)(SI*1), Y2
	VPANDN   Y13, Y2, Y2             // u1 = ~m0_1
	VMOVDQU  Y2, 448(DI)(SI*1)       // park u1 in out[2][1][half]

	VMOVDQU  128(DI)(SI*1), Y8
	VPANDN   il168qdomain40<>(SB), Y8, Y8 // u2 = (~m0_2) & 0xFFFFFFFFFF
	VMOVDQU  Y8, 512(DI)(SI*1)       // park u2 in out[2][2][half]

	ADDQ $32, SI
	CMPQ SI, $64
	JLT  avx2HalfLoop

	// ---- 4. 3-Word Scalar PDEPQ Remap Tail Across 8 Lanes ----
	XORQ SI, SI

avx2RemapLoop:
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
	JLT  avx2RemapLoop

	// Epilogue: zero all Y0..Y15 and touched GPR registers.
	VPXOR X0, X0, X0
	VPXOR X1, X1, X1
	VPXOR X2, X2, X2
	VPXOR X3, X3, X3
	VPXOR X4, X4, X4
	VPXOR X5, X5, X5
	VPXOR X6, X6, X6
	VPXOR X7, X7, X7
	VPXOR X8, X8, X8
	VPXOR X9, X9, X9
	VPXOR X10, X10, X10
	VPXOR X11, X11, X11
	VPXOR X12, X12, X12
	VPXOR X13, X13, X13
	VPXOR X14, X14, X14
	VPXOR X15, X15, X15
	XORQ  AX, AX
	XORQ  BX, BX
	XORQ  CX, CX
	XORQ  DX, DX
	XORQ  SI, SI
	XORQ  DI, DI
	XORQ  R8, R8
	XORQ  R9, R9
	XORQ  R10, R10
	XORQ  R11, R11
	XORQ  R12, R12
	XORQ  R13, R13
	XORQ  R14, R14
	VZEROUPPER
	RET
