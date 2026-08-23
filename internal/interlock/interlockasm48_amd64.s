//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func Chunk48Lock(x, m0, m1, m2 uint64) (l0, l1, l2 uint64)
//
// Frame layout (ABI0, all uint64 = 8 bytes):
//   x   at FP+0
//   m0  at FP+8
//   m1  at FP+16
//   m2  at FP+24
//   l0  at FP+32  (return)
//   l1  at FP+40  (return)
//   l2  at FP+48  (return)
//
// Three BMI2 PEXTQ instructions extract the lane values by mask. Each
// PEXT compresses x's bits selected by mask_i into a contiguous low
// segment. Since each mask has popcount 16, the result fits in 16 bits;
// the upper bits of the 64-bit output are zero. Caller takes uint16().
TEXT ·Chunk48Lock(SB),NOSPLIT,$0-56
	MOVQ x+0(FP), AX
	MOVQ m0+8(FP), BX
	PEXTQ BX, AX, CX
	MOVQ CX, l0+32(FP)
	MOVQ m1+16(FP), BX
	PEXTQ BX, AX, CX
	MOVQ CX, l1+40(FP)
	MOVQ m2+24(FP), BX
	PEXTQ BX, AX, CX
	MOVQ CX, l2+48(FP)
	RET

// func Unchunk48Lock(l0, l1, l2, m0, m1, m2 uint64) (x uint64)
//
// Frame layout (ABI0, all uint64 = 8 bytes):
//   l0  at FP+0
//   l1  at FP+8
//   l2  at FP+16
//   m0  at FP+24
//   m1  at FP+32
//   m2  at FP+40
//   x   at FP+48  (return)
//
// Three PDEPQ instructions expand each 16-bit lane value's bits into
// the 48-bit positions selected by mask_i; the three results are
// disjoint (m0|m1|m2 covers all 48 bits with no overlap), so OR-ing
// them reconstructs x. Upper 16 bits of the returned uint64 are zero.
TEXT ·Unchunk48Lock(SB),NOSPLIT,$0-56
	MOVQ l0+0(FP), AX
	MOVQ m0+24(FP), BX
	PDEPQ BX, AX, R8
	MOVQ l1+8(FP), AX
	MOVQ m1+32(FP), BX
	PDEPQ BX, AX, R9
	ORQ R9, R8
	MOVQ l2+16(FP), AX
	MOVQ m2+40(FP), BX
	PDEPQ BX, AX, R9
	ORQ R9, R8
	MOVQ R8, x+48(FP)
	RET

// func rankToMaskTripleUnrank48AVX512(idx0 *[8]uint64, idx1 *[8]uint32,
//                                     crow *[49][17]uint64, out *[3][8]uint64)
//
// Lane-parallel combinatorial-number-system unrank for 8 lanes on qwords
// (all 8 ZMM qword lanes carry payload). Mirrors the bit-exact Go
// reference in the parent package: two unranks (16-of-48 from idx0,
// 16-of-32 from idx1) plus the remap onto the bits m0 leaves free.
//
// Row lookup: per descending position p, c = C(p, krem) is selected by
// loading two ZMM halves of the 17-entry row (Z3 = C(p, 0..7), Z4 =
// C(p, 8..15)) and combining via VPERMI2Q with per-lane index krem & 15.
// The 17-th entry C(p, 16) is fetched as a scalar and broadcast into
// lanes where krem == 16 via a masked VPBROADCASTQ. The pick is applied
// via mask registers throughout — neither memory access nor control flow
// depends on secret indices — constant-time.
//
// Frame: 4 pointer args = 32 bytes; 128 bytes of locals spill the
// remaining / m1Local lane vectors for the scalar-PDEPQ remap tail.
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)
TEXT ·rankToMaskTripleUnrank48AVX512(SB), NOSPLIT, $128-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	// Global broadcast constants.
	MOVQ $1, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z6            // Z6 = 1 (per qword lane)
	MOVQ $16, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z28           // Z28 = 16 (krem == 16 comparator)
	MOVQ $15, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z29           // Z29 = 15 (VPERMI2Q index mask)

	// ---- unrank m0: rank = idx0, n = 48, k = 16 ----
	VMOVDQU64 (AX), Z0              // Z0 = idx0[0..7]
	VMOVDQA64 Z28, Z1               // Z1 = krem = 16
	VPXORQ Z2, Z2, Z2               // Z2 = mask = 0
	MOVQ $47, R10                   // p = 47

m0Loop:
	// Row byte offset: p * 136 = p * 128 + p * 8.
	MOVQ R10, R11
	SHLQ $7, R11                    // R11 = p * 128
	LEAQ (R11)(R10*8), R11          // R11 = p * 128 + p * 8 = p * 136
	LEAQ (R14)(R11*1), R12          // R12 = &crow[p][0]

	VMOVDQU64 (R12), Z3             // Z3 = crow[p][0..7]
	VMOVDQU64 64(R12), Z4           // Z4 = crow[p][8..15]
	MOVQ 128(R12), R13              // R13 = crow[p][16] (scalar spillover)

	VPANDQ Z29, Z1, Z7              // Z7 = krem & 15 (VPERMI2Q per-lane index)
	VPERMI2Q Z4, Z3, Z7             // Z7 = concat(Z3, Z4)[Z7 & 15] per lane
	//                                  = per-lane C(p, krem) for krem in [0, 15]

	// Mask-merge C(p, 16) into lanes where krem == 16.
	VPCMPEQQ Z28, Z1, K5            // K5 = (krem == 16)
	MOVQ R13, X14
	VPBROADCASTQ X14, K5, Z7        // Z7[K5 lanes] = C(p, 16)

	VPCMPUQ $5, Z7, Z0, K1          // K1 = (rank >= c)
	VPTESTMQ Z1, Z1, K2             // K2 = (krem != 0)
	KANDW K1, K2, K3                // K3 = pick

	MOVQ $1, R8
	MOVQ R10, CX
	SHLQ CX, R8                     // R8 = 1 << p
	MOVQ R8, X14
	VPBROADCASTQ X14, Z5
	VPORQ Z5, Z2, K3, Z2            // mask |= (1<<p) on picked lanes
	VPSUBQ Z7, Z0, K3, Z0           // rank -= c on picked lanes
	VPSUBQ Z6, Z1, K3, Z1           // krem -= 1 on picked lanes

	SUBQ $1, R10
	JGE m0Loop

	VMOVDQA64 Z2, Z10               // Z10 = m0

	// ---- unrank m1Local: rank = idx1, n = 32, k = 16 ----
	// idx1 is *[8]uint32 = 32 bytes; zero-extend to 8 qwords.
	VPMOVZXDQ (BX), Z0
	VMOVDQA64 Z28, Z1               // Z1 = krem = 16
	VPXORQ Z2, Z2, Z2
	MOVQ $31, R10                   // p = 31

m1Loop:
	MOVQ R10, R11
	SHLQ $7, R11
	LEAQ (R11)(R10*8), R11
	LEAQ (R14)(R11*1), R12

	VMOVDQU64 (R12), Z3
	VMOVDQU64 64(R12), Z4
	MOVQ 128(R12), R13

	VPANDQ Z29, Z1, Z7
	VPERMI2Q Z4, Z3, Z7
	VPCMPEQQ Z28, Z1, K5
	MOVQ R13, X14
	VPBROADCASTQ X14, K5, Z7

	VPCMPUQ $5, Z7, Z0, K1
	VPTESTMQ Z1, Z1, K2
	KANDW K1, K2, K3

	MOVQ $1, R8
	MOVQ R10, CX
	SHLQ CX, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z5
	VPORQ Z5, Z2, K3, Z2
	VPSUBQ Z7, Z0, K3, Z0
	VPSUBQ Z6, Z1, K3, Z1

	SUBQ $1, R10
	JGE m1Loop

	VMOVDQA64 Z2, Z11               // Z11 = m1Local

	// ---- remap: m1 = PDEP(m1Local, remaining) — 8 scalar PDEPQ ----
	//
	// The per-lane deposit of m1Local's bits onto the positions m0
	// leaves free is exactly BMI2 PDEP with mask = remaining: bit t of
	// m1Local lands on the t-th set bit of remaining (ascending), the
	// same walk a bit-serial formulation performs across all 48
	// positions. The 8 qword lanes are spilled to the stack and each
	// runs one scalar PDEPQ; m2 = remaining ^ m1 (m1 is a subset of
	// remaining by construction, so the XOR clears exactly m1's bits).
	//
	// Constant-time: PDEP is data-oblivious (fixed latency) on Intel
	// Haswell+ and AMD Zen 3+ — the microarchitectural floor already
	// assumed by the PEXTQ / PDEPQ chunk kernels above. Pre-Zen 3 AMD
	// executes PDEPQ in microcode with data-dependent latency; on such
	// parts this is a performance caveat, not a new leakage surface
	// relative to the rest of this path.
	MOVQ $0x0000FFFFFFFFFFFF, R8
	MOVQ R8, X14
	VPBROADCASTQ X14, Z27           // Z27 = 0xFFFF_FFFF_FFFF (48-bit domain)
	VPANDNQ Z27, Z10, Z0            // Z0 = remaining = (~m0) & domain
	VMOVDQU64 Z10, (DI)             // out[0] = m0
	VMOVDQU64 Z0, rem-128(SP)       // spill remaining lanes 0..7
	VMOVDQU64 Z11, ml-64(SP)        // spill m1Local lanes 0..7

	// Per lane j: R8 = remaining[j], R9 = m1Local[j];
	// R10 = m1 = PDEP(m1Local, remaining); R8 ^= R10 -> m2.
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
