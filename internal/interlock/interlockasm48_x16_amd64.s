//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func rankToMaskTripleUnrank48x16AVX512(idx0 *[16]uint64, idx1 *[16]uint32,
//                                        crow *[49][16]uint64, out *[3][16]uint64)
//
// 16-lane combinatorial-number-system unrank: the 8-lane kernel in
// interlockasm48_amd64.s run as two batches (a = lanes 0..7, b = lanes
// 8..15) through one pass over the 48 positions. The 8-lane kernel is
// latency-bound on its per-position chain (krem -> row permute ->
// compare -> masked update, two chains in flight in the joint phase and
// one in the solo phase); interleaving a second batch puts four chains
// in flight in the joint phase and two in the solo phase, sharing every
// binomial-row load, which moves the loop from latency-bound to
// port-throughput-bound. Bit-exact with two invocations of the 8-lane
// kernel over the same lanes.
//
// Row lookup: both batches read the same packed row for position p
// (slot 0 = C(p, 16), slot i = C(p, i) for i = 1..15), loaded once into
// a two-ZMM window. Batch a selects C(p, krem) with VPERMI2Q (overwriting
// a copy of its krem while preserving the two table registers for batch
// b); batch b then selects C(p, krem) directly with VPERMT2Q (overwriting
// the first table register and preserving batch b's krem in-place). The
// permutes consume the low 4 bits of the index, so krem = 16 wraps to
// slot 0 = C(p, 16) and krem = 0 also reads slot 0.
//
// The krem != 0 predicate (VPTESTMQ) is load-bearing and must stay:
// krem = 16 is a legal state at row 15 (rank 0 selects the bottom 16
// positions, and C(15, 16) = 0 must be picked there), so slot 0 of row
// 15 cannot double as a sentinel for krem = 0 — both states index the
// same slot and only the predicate tells them apart.
//
// Constant-time: the row address depends only on the public loop
// counter; the secret krem is consumed by a register permute and the
// per-position pick is applied through mask registers, so neither the
// memory-access pattern nor the control flow depends on the secret
// indices; the remap tail is scalar BMI2 PDEPQ (fixed latency on the
// microarchitectural floor the chunk kernels already assume). The loops
// contain no scalar-to-SIMD bridge and no legacy-SSE instruction; every
// constant is produced by EVEX-only instructions.
//
// Register plan:
//   a.m0  rank Z0  krem Z1  mask Z2  c Z7   predicate K2
//   b.m0  rank Z8  krem Z9  mask Z10 c Z3   predicate K1
//   a.m1  rank Z16 krem Z17 mask Z18 c Z22  predicate K5
//   b.m1  rank Z24 krem Z25 mask Z26 c Z20  predicate K4
//   rows  Z3/Z4 (m0 row window), Z20/Z21 (m1 row window)
//   bits  Z5 (m0 position bit), Z19 (m1 position bit); Z6 = 1; Z27 = domain
//   R12 / R13 row pointers (public); R10 loop counter
//
// Frame: 4 pointer args = 32 bytes, no locals; m1Local and remaining
// lane vectors of both batches are parked in out[1] and out[2] and
// overwritten in place by the PDEPQ remap.
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)
// out layout: out[0][0..15] = m0, out[1][0..15] = m1, out[2][0..15] = m2
// (batch a in lanes 0..7, batch b in lanes 8..15).
TEXT ·rankToMaskTripleUnrank48x16AVX512(SB), NOSPLIT, $0-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	VPTERNLOGQ $0xFF, Z6, Z6, Z6    // Z6 = all-ones
	VPSRLQ $63, Z6, Z6              // Z6 = 1 (per qword lane)
	VPSLLQ $4, Z6, Z28              // Z28 = 16 (krem initial value)

	VMOVDQU64 (AX), Z0              // a.m0 rank = idx0[0..7]
	VMOVDQU64 64(AX), Z8            // b.m0 rank = idx0[8..15]
	VPMOVZXDQ (BX), Z16             // a.m1 rank = idx1[0..7]
	VPMOVZXDQ 32(BX), Z24           // b.m1 rank = idx1[8..15]
	VMOVDQA64 Z28, Z1
	VMOVDQA64 Z28, Z9
	VMOVDQA64 Z28, Z17
	VMOVDQA64 Z28, Z25
	VPXORQ Z2, Z2, Z2
	VPXORQ Z10, Z10, Z10
	VPXORQ Z18, Z18, Z18
	VPXORQ Z26, Z26, Z26
	VPSLLQ $47, Z6, Z5              // m0 bit = 1 << 47
	VPSLLQ $31, Z6, Z19             // m1 bit = 1 << 31
	LEAQ 47*128(R14), R12           // &crow[47][0] (m0 row)
	LEAQ 31*128(R14), R13           // &crow[31][0] (m1 row)
	MOVQ $31, R10                   // joint loop counter (public)

jointLoop:
	VMOVDQU64 (R12), Z3             // m0 row: slots 0..7
	VMOVDQU64 64(R12), Z4           // m0 row: slots 8..15
	VMOVDQU64 (R13), Z20            // m1 row: slots 0..7
	VMOVDQU64 64(R13), Z21          // m1 row: slots 8..15
	VMOVDQA64 Z1, Z7
	VMOVDQA64 Z17, Z22
	VPERMI2Q Z4, Z3, Z7             // a.m0: c = C(p0, krem)
	VPERMT2Q Z4, Z9, Z3             // b.m0: c in Z3 (Z9 preserved)
	VPERMI2Q Z21, Z20, Z22          // a.m1: c = C(p1, krem)
	VPERMT2Q Z21, Z25, Z20          // b.m1: c in Z20 (Z25 preserved)
	VPTESTMQ Z1, Z1, K2             // krem != 0 (see header)
	VPTESTMQ Z9, Z9, K1
	VPTESTMQ Z17, Z17, K5
	VPTESTMQ Z25, Z25, K4
	VPCMPUQ $5, Z7, Z0, K2, K2      // pick = (rank >= c) & (krem != 0)
	VPCMPUQ $5, Z3, Z8, K1, K1
	VPCMPUQ $5, Z22, Z16, K5, K5
	VPCMPUQ $5, Z20, Z24, K4, K4
	VPORQ Z5, Z2, K2, Z2            // mask |= bit
	VPORQ Z5, Z10, K1, Z10
	VPORQ Z19, Z18, K5, Z18
	VPORQ Z19, Z26, K4, Z26
	VPSUBQ Z7, Z0, K2, Z0           // rank -= c
	VPSUBQ Z3, Z8, K1, Z8
	VPSUBQ Z22, Z16, K5, Z16
	VPSUBQ Z20, Z24, K4, Z24
	VPSUBQ Z6, Z1, K2, Z1           // krem -= 1
	VPSUBQ Z6, Z9, K1, Z9
	VPSUBQ Z6, Z17, K5, Z17
	VPSUBQ Z6, Z25, K4, Z25
	VPSRLQ $1, Z5, Z5
	VPSRLQ $1, Z19, Z19
	SUBQ $128, R12
	SUBQ $128, R13
	SUBQ $1, R10
	JGE jointLoop

	MOVQ $15, R10                   // m0 solo positions 15..0

m0Solo:
	VMOVDQU64 (R12), Z3
	VMOVDQU64 64(R12), Z4
	VMOVDQA64 Z1, Z7
	VPERMI2Q Z4, Z3, Z7
	VPERMT2Q Z4, Z9, Z3
	VPTESTMQ Z1, Z1, K2
	VPTESTMQ Z9, Z9, K1
	VPCMPUQ $5, Z7, Z0, K2, K2
	VPCMPUQ $5, Z3, Z8, K1, K1
	VPORQ Z5, Z2, K2, Z2
	VPORQ Z5, Z10, K1, Z10
	VPSUBQ Z7, Z0, K2, Z0
	VPSUBQ Z3, Z8, K1, Z8
	VPSUBQ Z6, Z1, K2, Z1
	VPSUBQ Z6, Z9, K1, Z9
	VPSRLQ $1, Z5, Z5
	SUBQ $128, R12
	SUBQ $1, R10
	JGE m0Solo

	// ---- remap: m1 = PDEP(m1Local, remaining), m2 = remaining ^ m1 ----
	VPTERNLOGQ $0xFF, Z27, Z27, Z27
	VPSRLQ $16, Z27, Z27            // Z27 = 0xFFFF_FFFF_FFFF (48-bit domain)
	VPANDNQ Z27, Z2, Z0             // a remaining = (~m0) & domain
	VPANDNQ Z27, Z10, Z8            // b remaining
	VMOVDQU64 Z2, (DI)              // out[0][0..7]  = a.m0
	VMOVDQU64 Z10, 64(DI)           // out[0][8..15] = b.m0
	VMOVDQU64 Z18, 128(DI)          // park mla in out[1][0..7]
	VMOVDQU64 Z26, 192(DI)          // park mlb in out[1][8..15]
	VMOVDQU64 Z0, 256(DI)           // park rema in out[2][0..7]
	VMOVDQU64 Z8, 320(DI)           // park remb in out[2][8..15]

// REMAP: one lane — R8 = remaining (from out[2][lane]), R9 = m1Local
// (from out[1][lane]); m1 = PDEP(m1Local, remaining) to out[1][lane];
// m2 = remaining ^ m1 to out[2][lane].
#define REMAP(m1off, m2off) \
	MOVQ m2off(DI), R8; \
	MOVQ m1off(DI), R9; \
	PDEPQ R8, R9, R10; \
	XORQ R10, R8; \
	MOVQ R10, m1off(DI); \
	MOVQ R8, m2off(DI)

	// batch a: out[1][j] at 128+8j, out[2][j] at 256+8j
	REMAP(128, 256)
	REMAP(136, 264)
	REMAP(144, 272)
	REMAP(152, 280)
	REMAP(160, 288)
	REMAP(168, 296)
	REMAP(176, 304)
	REMAP(184, 312)
	// batch b: out[1][8+j] at 192+8j, out[2][8+j] at 320+8j
	REMAP(192, 320)
	REMAP(200, 328)
	REMAP(208, 336)
	REMAP(216, 344)
	REMAP(224, 352)
	REMAP(232, 360)
	REMAP(240, 368)
	REMAP(248, 376)

	VPXORD Z0, Z0, Z0
	VPXORD Z1, Z1, Z1
	VPXORD Z2, Z2, Z2
	VPXORD Z3, Z3, Z3
	VPXORD Z4, Z4, Z4
	VPXORD Z5, Z5, Z5
	VPXORD Z6, Z6, Z6
	VPXORD Z7, Z7, Z7
	VPXORD Z8, Z8, Z8
	VPXORD Z9, Z9, Z9
	VPXORD Z10, Z10, Z10
	VPXORD Z16, Z16, Z16
	VPXORD Z17, Z17, Z17
	VPXORD Z18, Z18, Z18
	VPXORD Z19, Z19, Z19
	VPXORD Z20, Z20, Z20
	VPXORD Z21, Z21, Z21
	VPXORD Z22, Z22, Z22
	VPXORD Z24, Z24, Z24
	VPXORD Z25, Z25, Z25
	VPXORD Z26, Z26, Z26
	VPXORD Z27, Z27, Z27
	VPXORD Z28, Z28, Z28
	KXORW K1, K1, K1
	KXORW K2, K2, K2
	KXORW K4, K4, K4
	KXORW K5, K5, K5
	XORQ R8, R8
	XORQ R9, R9
	XORQ R10, R10
	VZEROUPPER
	RET
