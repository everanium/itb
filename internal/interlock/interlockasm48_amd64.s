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
//                                     crow *[49][16]uint64, out *[3][8]uint64)
//
// Lane-parallel combinatorial-number-system unrank for 8 lanes on qwords
// (all 8 ZMM qword lanes carry payload). Mirrors the bit-exact Go
// reference in the parent package: two unranks (16-of-48 from idx0,
// 16-of-32 from idx1) plus the remap onto the bits m0 leaves free.
//
// Row lookup: per descending position p, c = C(p, krem) is selected by
// loading two ZMM halves of the packed 16-entry row (slot 0 = C(p, 16),
// slot i = C(p, i) for i = 1..15) and combining via VPERMT2Q indexed by
// krem directly — VPERMT2Q overwrites its first-table operand and
// preserves the index register, so krem feeds the permute with no
// index-adjust op on the loop-carried chain. The permute consumes only
// the low 4 bits of each qword index: krem = 16 wraps to slot 0 =
// C(p, 16) (the spillover entry of a 17-entry layout, folded into the
// permute), and krem = 0 also reads slot 0 — a garbage value whose
// pick the krem != 0 zeroing predicate on VPCMPUQ suppresses. The pick
// is applied via mask registers throughout — neither memory access nor
// control flow depends on secret indices — constant-time.
//
// The hot loops contain no scalar-to-SIMD bridge and no legacy-SSE
// instruction: Go's assembler emits the non-VEX encoding for MOVQ
// GPR->XMM, and a legacy-SSE write while the ZMM upper state is dirty
// triggers a save/restore state transition on Golden Cove Server
// P-cores (Sapphire Rapids / Emerald Rapids) costing on the order of
// a thousand cycles per loop iteration. Loop constants (the per-
// position bit, the row address) are maintained by EVEX shifts and
// scalar pointer arithmetic instead.
//
// Frame: 4 pointer args = 32 bytes; 128 bytes of locals spill the
// remaining / m1Local lane vectors for the scalar-PDEPQ remap tail.
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)
TEXT ·rankToMaskTripleUnrank48AVX512(SB), NOSPLIT, $128-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	// Global broadcast constants — derived arithmetically in-register.
	// No MOVQ GPR->XMM bridges: Go's assembler emits the legacy-SSE
	// (non-VEX) encoding for MOVQ to an X register, and a legacy-SSE
	// write while the ZMM upper state is dirty triggers a save/restore
	// state transition on Golden Cove Server P-cores (Sapphire Rapids /
	// Emerald Rapids) costing hundreds of cycles per site. Every
	// constant below is produced by EVEX-only instructions instead.
	VPTERNLOGQ $0xFF, Z6, Z6, Z6    // Z6 = all-ones
	VPSRLQ $63, Z6, Z6              // Z6 = 1 (per qword lane)
	VPSLLQ $4, Z6, Z28              // Z28 = 16 (krem initial value)

	// ---- interleaved unrank: m0 (rank = idx0, n = 48, k = 16) and
	//      m1Local (rank = idx1, n = 32, k = 16) ----
	//
	// The two unranks are data-independent, so their per-position
	// loop-carried dependency chains (krem -> VPERMT2Q -> VPCMPUQ ->
	// masked update) run concurrently: 32 joint iterations retire one
	// m0 position AND one m1 position each, then 16 m0-solo iterations
	// finish positions 15..0. Total trip count 48 instead of 48 + 32.
	//
	// Register split: m0 state in Z0/Z1/Z2 (rank/krem/mask), row window
	// Z3/Z4 (VPERMT2Q leaves c in Z3), bit in Z5, predicates K2/K3,
	// row pointer R12; m1 state in Z16/Z17/Z18, rows Z20/Z21 (c in
	// Z20), bit in Z19, predicates K5/K6, row pointer R13.
	VMOVDQU64 (AX), Z0              // Z0 = idx0[0..7]
	VPMOVZXDQ (BX), Z16             // Z16 = idx1[0..7] zero-extended to qwords
	VMOVDQA64 Z28, Z1               // Z1 = m0 krem = 16
	VMOVDQA64 Z28, Z17              // Z17 = m1 krem = 16
	VPXORQ Z2, Z2, Z2               // Z2 = m0 mask = 0
	VPXORQ Z18, Z18, Z18            // Z18 = m1 mask = 0
	VPSLLQ $47, Z6, Z5              // Z5 = m0 bit = 1 << 47
	VPSLLQ $31, Z6, Z19             // Z19 = m1 bit = 1 << 31
	LEAQ 47*128(R14), R12           // R12 = &crow[47][0] (m0 row)
	LEAQ 31*128(R14), R13           // R13 = &crow[31][0] (m1 row)
	MOVQ $31, R10                   // joint loop counter (public)

jointLoop:
	VMOVDQU64 (R12), Z3             // m0 row: slots 0..7  = C(p0, {16, 1..7})
	VMOVDQU64 64(R12), Z4           // m0 row: slots 8..15 = C(p0, 8..15)
	VMOVDQU64 (R13), Z20            // m1 row: slots 0..7  = C(p1, {16, 1..7})
	VMOVDQU64 64(R13), Z21          // m1 row: slots 8..15 = C(p1, 8..15)
	VPERMT2Q Z4, Z1, Z3             // m0: c = C(p0, krem) (Z1 index preserved)
	VPERMT2Q Z21, Z17, Z20          // m1: c = C(p1, krem)
	VPTESTMQ Z1, Z1, K2             // m0: krem != 0
	VPTESTMQ Z17, Z17, K5           // m1: krem != 0
	VPCMPUQ $5, Z3, Z0, K2, K3      // m0: pick = (rank >= c) & (krem != 0)
	VPCMPUQ $5, Z20, Z16, K5, K6    // m1: pick
	VPORQ Z5, Z2, K3, Z2            // m0: mask |= bit
	VPORQ Z19, Z18, K6, Z18         // m1: mask |= bit
	VPSUBQ Z3, Z0, K3, Z0           // m0: rank -= c
	VPSUBQ Z20, Z16, K6, Z16        // m1: rank -= c
	VPSUBQ Z6, Z1, K3, Z1           // m0: krem -= 1
	VPSUBQ Z6, Z17, K6, Z17         // m1: krem -= 1
	VPSRLQ $1, Z5, Z5               // m0: bit >>= 1
	VPSRLQ $1, Z19, Z19             // m1: bit >>= 1
	SUBQ $128, R12
	SUBQ $128, R13
	SUBQ $1, R10
	JGE jointLoop

	VMOVDQA64 Z18, Z11              // Z11 = m1Local (m1 unrank complete)
	MOVQ $15, R10                   // m0 solo positions 15..0

m0Solo:
	VMOVDQU64 (R12), Z3
	VMOVDQU64 64(R12), Z4
	VPERMT2Q Z4, Z1, Z3
	VPTESTMQ Z1, Z1, K2
	VPCMPUQ $5, Z3, Z0, K2, K3
	VPORQ Z5, Z2, K3, Z2
	VPSUBQ Z3, Z0, K3, Z0
	VPSUBQ Z6, Z1, K3, Z1
	VPSRLQ $1, Z5, Z5
	SUBQ $128, R12
	SUBQ $1, R10
	JGE m0Solo

	VMOVDQA64 Z2, Z10               // Z10 = m0

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
	VPTERNLOGQ $0xFF, Z27, Z27, Z27 // Z27 = all-ones
	VPSRLQ $16, Z27, Z27            // Z27 = 0xFFFF_FFFF_FFFF (48-bit domain)
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
