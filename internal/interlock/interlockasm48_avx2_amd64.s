//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// AVX2 4-lane batched combinadic unrank for the 48-bit interlock mask
// derivation — the AVX2-only-CPU counterpart of
// rankToMaskTripleUnrank48AVX512 (interlockasm48_amd64.s). YMM holds
// 4 qword lanes, so the 8-lane logical batch runs as two 4-lane halves
// under an outer half loop; the out layout is identical to the AVX-512
// kernel's ([3][8]uint64).
//
// AVX-512 -> AVX2 construct mapping:
//   VPERMI2Q row lookup  -> per-4-group VPERMD qword-gather + hi-group
//                           compare/AND/OR merge; the C(p,16) spillover
//                           enters via the same compare/AND/OR path.
//   K-mask predication   -> all-ones/zero YMM predicates from VPCMPEQQ /
//                           VPCMPGTQ; masked VPORQ/VPSUBQ become
//                           VPANDN(pred, operand) + VPOR / VPSUBQ.
//   VPCMPUQ $5 (>=, uns) -> VPCMPGTQ (signed) with inverted-operand
//                           logic: rank and C(p, krem) are both bounded
//                           by C(48,16) < 2^42, so bit 63 is always 0
//                           and signed / unsigned compares agree.
//
// Constant-time: the crow row address depends only on the loop counter
// p (public). The secret per-lane index krem never addresses memory —
// it is consumed by register-only operations (VPERMD register permute /
// VPCMPEQQ predicates), which are data-oblivious with fixed latency,
// the same invariant the AVX-512 kernel establishes for VPERMI2Q. The
// remap tail is scalar BMI2 PDEPQ, identical to the AVX-512 kernel and
// under the same microarchitectural floor (fixed-latency PDEP on Intel
// Haswell+ / AMD Zen 3+).

// il48qrow: rows 0..16, row i = broadcast qword i. Serves as the
// hi-group comparator rows (0..4), the krem init vector (row 16), the
// krem == 0 predicate row (row 0) and the masked krem decrement
// constant (row 1).
DATA il48qrow<>+0x000(SB)/8, $0
DATA il48qrow<>+0x008(SB)/8, $0
DATA il48qrow<>+0x010(SB)/8, $0
DATA il48qrow<>+0x018(SB)/8, $0
DATA il48qrow<>+0x020(SB)/8, $1
DATA il48qrow<>+0x028(SB)/8, $1
DATA il48qrow<>+0x030(SB)/8, $1
DATA il48qrow<>+0x038(SB)/8, $1
DATA il48qrow<>+0x040(SB)/8, $2
DATA il48qrow<>+0x048(SB)/8, $2
DATA il48qrow<>+0x050(SB)/8, $2
DATA il48qrow<>+0x058(SB)/8, $2
DATA il48qrow<>+0x060(SB)/8, $3
DATA il48qrow<>+0x068(SB)/8, $3
DATA il48qrow<>+0x070(SB)/8, $3
DATA il48qrow<>+0x078(SB)/8, $3
DATA il48qrow<>+0x080(SB)/8, $4
DATA il48qrow<>+0x088(SB)/8, $4
DATA il48qrow<>+0x090(SB)/8, $4
DATA il48qrow<>+0x098(SB)/8, $4
DATA il48qrow<>+0x0a0(SB)/8, $5
DATA il48qrow<>+0x0a8(SB)/8, $5
DATA il48qrow<>+0x0b0(SB)/8, $5
DATA il48qrow<>+0x0b8(SB)/8, $5
DATA il48qrow<>+0x0c0(SB)/8, $6
DATA il48qrow<>+0x0c8(SB)/8, $6
DATA il48qrow<>+0x0d0(SB)/8, $6
DATA il48qrow<>+0x0d8(SB)/8, $6
DATA il48qrow<>+0x0e0(SB)/8, $7
DATA il48qrow<>+0x0e8(SB)/8, $7
DATA il48qrow<>+0x0f0(SB)/8, $7
DATA il48qrow<>+0x0f8(SB)/8, $7
DATA il48qrow<>+0x100(SB)/8, $8
DATA il48qrow<>+0x108(SB)/8, $8
DATA il48qrow<>+0x110(SB)/8, $8
DATA il48qrow<>+0x118(SB)/8, $8
DATA il48qrow<>+0x120(SB)/8, $9
DATA il48qrow<>+0x128(SB)/8, $9
DATA il48qrow<>+0x130(SB)/8, $9
DATA il48qrow<>+0x138(SB)/8, $9
DATA il48qrow<>+0x140(SB)/8, $10
DATA il48qrow<>+0x148(SB)/8, $10
DATA il48qrow<>+0x150(SB)/8, $10
DATA il48qrow<>+0x158(SB)/8, $10
DATA il48qrow<>+0x160(SB)/8, $11
DATA il48qrow<>+0x168(SB)/8, $11
DATA il48qrow<>+0x170(SB)/8, $11
DATA il48qrow<>+0x178(SB)/8, $11
DATA il48qrow<>+0x180(SB)/8, $12
DATA il48qrow<>+0x188(SB)/8, $12
DATA il48qrow<>+0x190(SB)/8, $12
DATA il48qrow<>+0x198(SB)/8, $12
DATA il48qrow<>+0x1a0(SB)/8, $13
DATA il48qrow<>+0x1a8(SB)/8, $13
DATA il48qrow<>+0x1b0(SB)/8, $13
DATA il48qrow<>+0x1b8(SB)/8, $13
DATA il48qrow<>+0x1c0(SB)/8, $14
DATA il48qrow<>+0x1c8(SB)/8, $14
DATA il48qrow<>+0x1d0(SB)/8, $14
DATA il48qrow<>+0x1d8(SB)/8, $14
DATA il48qrow<>+0x1e0(SB)/8, $15
DATA il48qrow<>+0x1e8(SB)/8, $15
DATA il48qrow<>+0x1f0(SB)/8, $15
DATA il48qrow<>+0x1f8(SB)/8, $15
DATA il48qrow<>+0x200(SB)/8, $16
DATA il48qrow<>+0x208(SB)/8, $16
DATA il48qrow<>+0x210(SB)/8, $16
DATA il48qrow<>+0x218(SB)/8, $16
GLOBL il48qrow<>(SB), RODATA|NOPTR, $544

// il48dadd01: per-qword dword pair [0, 1] — the +[0,1] pattern that
// turns a duplicated dword index t into the VPERMD pair [t, t+1].
DATA il48dadd01<>+0x000(SB)/8, $0x0000000100000000
DATA il48dadd01<>+0x008(SB)/8, $0x0000000100000000
DATA il48dadd01<>+0x010(SB)/8, $0x0000000100000000
DATA il48dadd01<>+0x018(SB)/8, $0x0000000100000000
GLOBL il48dadd01<>(SB), RODATA|NOPTR, $32

// il48qdomain: broadcast 48-bit domain mask.
DATA il48qdomain<>+0x000(SB)/8, $0x0000FFFFFFFFFFFF
DATA il48qdomain<>+0x008(SB)/8, $0x0000FFFFFFFFFFFF
DATA il48qdomain<>+0x010(SB)/8, $0x0000FFFFFFFFFFFF
DATA il48qdomain<>+0x018(SB)/8, $0x0000FFFFFFFFFFFF
GLOBL il48qdomain<>(SB), RODATA|NOPTR, $32

// func rankToMaskTripleUnrank48AVX2(idx0 *[8]uint64, idx1 *[8]uint32,
//                                  crow *[49][17]uint64, out *[3][8]uint64)
//
// Lane-parallel combinatorial-number-system unrank for 4 qword lanes
// per YMM pass, two passes per invocation (lanes 0..3 then 4..7).
// Mirrors the bit-exact Go reference in the parent package: two unranks
// (16-of-48 from idx0, 16-of-32 from idx1) plus the remap onto the bits
// m0 leaves free.
//
// Row lookup: per descending position p, c = C(p, krem) is selected by
// four VPERMD qword-gathers (one per 4-qword group of the 16-entry row
// window) merged under hi-group equality predicates, with the C(p, 16)
// spillover entering through the same predicate path.
//
// Frame: 4 pointer args = 32 bytes; 128 bytes of locals spill the
// remaining / m1Local lane vectors (both halves, contiguous — same
// layout as the AVX-512 kernel) for the scalar-PDEPQ remap tail.
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)
TEXT ·rankToMaskTripleUnrank48AVX2(SB), NOSPLIT, $128-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	XORQ SI, SI                     // half byte offset: 0, then 32

avx2HalfLoop:
	// ---- unrank m0: rank = idx0[half], n = 48, k = 16 ----
	VMOVDQU (AX)(SI*1), Y0          // Y0 = rank lanes
	VMOVDQU il48qrow<>+512(SB), Y1  // Y1 = krem = 16
	VPXOR Y2, Y2, Y2                // Y2 = mask = 0
	MOVQ $0x800000000000, R8        // 1 << 47
	MOVQ R8, X8
	VPBROADCASTQ X8, Y8             // Y8 = pbit = 1 << p
	MOVQ $47, R10                   // p = 47

avx2M0Loop:
	// Row byte offset: p * 136 = p * 128 + p * 8.
	MOVQ R10, R11
	SHLQ $7, R11
	LEAQ (R11)(R10*8), R11
	LEAQ (R14)(R11*1), R12          // R12 = &crow[p][0]

	// ctrl: per-qword dword pair [2*(krem&3), 2*(krem&3)+1] — VPERMD
	// qword-gather control for the within-group index. hi = krem >> 2
	// picks the 4-qword group (0..3) or the C(p,16) spillover (4).
	VPAND il48qrow<>+96(SB), Y1, Y3 // krem & 3
	VPSLLQ $1, Y3, Y3               // 2 * (krem & 3)
	VPSHUFD $0xA0, Y3, Y3           // duplicate low dword per qword
	VPADDD il48dadd01<>(SB), Y3, Y3 // ctrl = [2t, 2t+1] per qword
	VPSRLQ $2, Y1, Y4               // hi = krem >> 2, in {0..4}

	// c = concat(crow[p][0..15], C(p,16))[krem]: per group g, gather
	// the within-group qword via VPERMD, keep it only on lanes with
	// hi == g, OR-merge. Secret krem stays register-resident.
	VPCMPEQQ il48qrow<>+0(SB), Y4, Y7
	VPERMD (R12), Y3, Y6            // crow[p][0..3][krem&3]
	VPAND Y6, Y7, Y5
	VPCMPEQQ il48qrow<>+32(SB), Y4, Y7
	VPERMD 32(R12), Y3, Y6          // crow[p][4..7][krem&3]
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5
	VPCMPEQQ il48qrow<>+64(SB), Y4, Y7
	VPERMD 64(R12), Y3, Y6          // crow[p][8..11][krem&3]
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5
	VPCMPEQQ il48qrow<>+96(SB), Y4, Y7
	VPERMD 96(R12), Y3, Y6          // crow[p][12..15][krem&3]
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5
	VPCMPEQQ il48qrow<>+128(SB), Y4, Y7
	VPBROADCASTQ 128(R12), Y6       // C(p, 16) spillover
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5                 // Y5 = C(p, krem)

	// pick = (rank >= c) && (krem != 0). Signed VPCMPGTQ is safe:
	// both operands < 2^42 (see file header).
	VPCMPGTQ Y0, Y5, Y9             // c > rank  (== !(rank >= c))
	VPCMPEQQ il48qrow<>+0(SB), Y1, Y10 // krem == 0
	VPOR Y10, Y9, Y9                // notpick
	VPANDN Y8, Y9, Y10              // pick ? (1 << p) : 0
	VPOR Y10, Y2, Y2                // mask |= (1<<p) on picked lanes
	VPANDN Y5, Y9, Y10              // pick ? c : 0
	VPSUBQ Y10, Y0, Y0              // rank -= c on picked lanes
	VPANDN il48qrow<>+32(SB), Y9, Y10 // pick ? 1 : 0
	VPSUBQ Y10, Y1, Y1              // krem -= 1 on picked lanes

	VPSRLQ $1, Y8, Y8               // pbit >>= 1
	SUBQ $1, R10
	JGE avx2M0Loop

	VMOVDQU Y2, (DI)(SI*1)          // out[0][half] = m0
	VPANDN il48qdomain<>(SB), Y2, Y3 // remaining = (~m0) & domain
	LEAQ rem-128(SP), R11
	VMOVDQU Y3, (R11)(SI*1)         // spill remaining lanes

	// ---- unrank m1Local: rank = idx1[half], n = 32, k = 16 ----
	MOVQ SI, DX
	SHRQ $1, DX                     // idx1 is [8]uint32: half stride 16
	VPMOVZXDQ (BX)(DX*1), Y0        // zero-extend 4 dwords to qwords
	VMOVDQU il48qrow<>+512(SB), Y1  // krem = 16
	VPXOR Y2, Y2, Y2
	MOVQ $0x80000000, R8            // 1 << 31
	MOVQ R8, X8
	VPBROADCASTQ X8, Y8
	MOVQ $31, R10                   // p = 31

avx2M1Loop:
	// Row byte offset: p * 136 = p * 128 + p * 8.
	MOVQ R10, R11
	SHLQ $7, R11
	LEAQ (R11)(R10*8), R11
	LEAQ (R14)(R11*1), R12          // R12 = &crow[p][0]

	// ctrl: per-qword dword pair [2*(krem&3), 2*(krem&3)+1] — VPERMD
	// qword-gather control for the within-group index. hi = krem >> 2
	// picks the 4-qword group (0..3) or the C(p,16) spillover (4).
	VPAND il48qrow<>+96(SB), Y1, Y3 // krem & 3
	VPSLLQ $1, Y3, Y3               // 2 * (krem & 3)
	VPSHUFD $0xA0, Y3, Y3           // duplicate low dword per qword
	VPADDD il48dadd01<>(SB), Y3, Y3 // ctrl = [2t, 2t+1] per qword
	VPSRLQ $2, Y1, Y4               // hi = krem >> 2, in {0..4}

	// c = concat(crow[p][0..15], C(p,16))[krem]: per group g, gather
	// the within-group qword via VPERMD, keep it only on lanes with
	// hi == g, OR-merge. Secret krem stays register-resident.
	VPCMPEQQ il48qrow<>+0(SB), Y4, Y7
	VPERMD (R12), Y3, Y6            // crow[p][0..3][krem&3]
	VPAND Y6, Y7, Y5
	VPCMPEQQ il48qrow<>+32(SB), Y4, Y7
	VPERMD 32(R12), Y3, Y6          // crow[p][4..7][krem&3]
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5
	VPCMPEQQ il48qrow<>+64(SB), Y4, Y7
	VPERMD 64(R12), Y3, Y6          // crow[p][8..11][krem&3]
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5
	VPCMPEQQ il48qrow<>+96(SB), Y4, Y7
	VPERMD 96(R12), Y3, Y6          // crow[p][12..15][krem&3]
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5
	VPCMPEQQ il48qrow<>+128(SB), Y4, Y7
	VPBROADCASTQ 128(R12), Y6       // C(p, 16) spillover
	VPAND Y6, Y7, Y7
	VPOR Y7, Y5, Y5                 // Y5 = C(p, krem)

	// pick = (rank >= c) && (krem != 0). Signed VPCMPGTQ is safe:
	// both operands < 2^42 (see file header).
	VPCMPGTQ Y0, Y5, Y9             // c > rank  (== !(rank >= c))
	VPCMPEQQ il48qrow<>+0(SB), Y1, Y10 // krem == 0
	VPOR Y10, Y9, Y9                // notpick
	VPANDN Y8, Y9, Y10              // pick ? (1 << p) : 0
	VPOR Y10, Y2, Y2                // mask |= (1<<p) on picked lanes
	VPANDN Y5, Y9, Y10              // pick ? c : 0
	VPSUBQ Y10, Y0, Y0              // rank -= c on picked lanes
	VPANDN il48qrow<>+32(SB), Y9, Y10 // pick ? 1 : 0
	VPSUBQ Y10, Y1, Y1              // krem -= 1 on picked lanes

	VPSRLQ $1, Y8, Y8               // pbit >>= 1
	SUBQ $1, R10
	JGE avx2M1Loop

	LEAQ ml-64(SP), R11
	VMOVDQU Y2, (R11)(SI*1)         // spill m1Local lanes

	ADDQ $32, SI
	CMPQ SI, $64
	JLT avx2HalfLoop

	// ---- remap: m1 = PDEP(m1Local, remaining) — 8 scalar PDEPQ ----
	// Identical to the AVX-512 kernel's tail: per lane j, deposit
	// m1Local's bits onto the positions m0 leaves free (mask =
	// remaining), then m2 = remaining ^ m1. Both halves were spilled
	// contiguously, so the 8-lane walk below matches the AVX-512
	// kernel's spill layout byte for byte.
	MOVQ rem-128(SP), R8
	MOVQ ml-64(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 64(DI)                // out[1][0] = m1
	MOVQ R8, 128(DI)                // out[2][0] = m2

	MOVQ rem-120(SP), R8
	MOVQ ml-56(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 72(DI)
	MOVQ R8, 136(DI)

	MOVQ rem-112(SP), R8
	MOVQ ml-48(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 80(DI)
	MOVQ R8, 144(DI)

	MOVQ rem-104(SP), R8
	MOVQ ml-40(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 88(DI)
	MOVQ R8, 152(DI)

	MOVQ rem-96(SP), R8
	MOVQ ml-32(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 96(DI)
	MOVQ R8, 160(DI)

	MOVQ rem-88(SP), R8
	MOVQ ml-24(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 104(DI)
	MOVQ R8, 168(DI)

	MOVQ rem-80(SP), R8
	MOVQ ml-16(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 112(DI)
	MOVQ R8, 176(DI)

	MOVQ rem-72(SP), R8
	MOVQ ml-8(SP), R9
	PDEPQ R8, R9, R10
	XORQ R10, R8
	MOVQ R10, 120(DI)
	MOVQ R8, 184(DI)

	VZEROUPPER
	RET
