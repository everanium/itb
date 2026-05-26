//go:build amd64 && !purego && !noitbasm

#include "textflag.h"

// func Chunk24Lock(x, m0, m1, m2 uint32) (l0, l1, l2 uint32)
//
// Frame layout (ABI0, all uint32 = 4 bytes):
//   x   at FP+0
//   m0  at FP+4
//   m1  at FP+8
//   m2  at FP+12
//   l0  at FP+16  (return)
//   l1  at FP+20  (return)
//   l2  at FP+24  (return)
//
// Three BMI2 PEXTL instructions extract the lane bytes by mask. Each
// PEXT compresses x's bits selected by mask_i into a contiguous low
// byte. Since each mask has popcount 8, the result fits in 8 bits;
// the upper bits of the 32-bit output are zero. Caller takes byte().
TEXT ·Chunk24Lock(SB),NOSPLIT,$0-28
	MOVL x+0(FP), AX
	MOVL m0+4(FP), BX
	PEXTL BX, AX, CX
	MOVL CX, l0+16(FP)
	MOVL m1+8(FP), BX
	PEXTL BX, AX, CX
	MOVL CX, l1+20(FP)
	MOVL m2+12(FP), BX
	PEXTL BX, AX, CX
	MOVL CX, l2+24(FP)
	RET

// func Unchunk24Lock(l0, l1, l2, m0, m1, m2 uint32) (x uint32)
//
// Frame layout (ABI0, all uint32 = 4 bytes):
//   l0  at FP+0
//   l1  at FP+4
//   l2  at FP+8
//   m0  at FP+12
//   m1  at FP+16
//   m2  at FP+20
//   x   at FP+24  (return)
//
// Three PDEPL instructions expand each lane byte's bits into the
// 24-bit positions selected by mask_i; the three results are disjoint
// (m0|m1|m2 covers all 24 bits with no overlap), so OR-ing them
// reconstructs x.
TEXT ·Unchunk24Lock(SB),NOSPLIT,$0-28
	MOVL l0+0(FP), AX
	MOVL m0+12(FP), BX
	PDEPL BX, AX, R8
	MOVL l1+4(FP), AX
	MOVL m1+16(FP), BX
	PDEPL BX, AX, R9
	ORL R9, R8
	MOVL l2+8(FP), AX
	MOVL m2+20(FP), BX
	PDEPL BX, AX, R9
	ORL R9, R8
	MOVL R8, x+24(FP)
	RET

// func Permute24Avx512(x uint32, perm *[32]byte) (y uint32)
//
// Frame layout (ABI0):
//   x    at FP+0   (uint32, 4 bytes)
//   perm at FP+8   (pointer, 8 bytes; +4 padding for 8-byte alignment)
//   y    at FP+16  (uint32, 4 bytes return)
//
// Total arg+ret span is 20 bytes; declared frame is 24 to satisfy
// 8-byte alignment of the call's stack argument area (matches the
// existing $0-24 patterns used elsewhere in the codebase).
//
// Approach (AVX-512 VBMI bit-spread + VPERMB + bit-pack):
//   Step 1: KMOVD AX → K1 spreads x's low 24 bits across mask register.
//   Step 2: VPMOVM2B K1 → Y0 produces -1/0 per byte (24 active bytes,
//           upper 8 of YMM zero by AVX-512VL semantics).
//   Step 3: VPABSB Y0 → Y0 collapses -1/0 to 1/0 per byte.
//   Step 4: VMOVDQU loads perm[0..31] into Y1.
//   Step 5: VPERMB Y0 (table), Y1 (idx) → Y2, where Y2[i] = Y0[Y1[i]&63].
//           For i in 0..23 this gathers bit perm[i] of x into byte i of Y2.
//   Step 6: VPTESTMB Y2 → K2 sets a mask bit per nonzero byte of Y2.
//   Step 7: KMOVD K2 → AX, masked to 24 bits (the high bytes of Y2 may
//           hold gather artifacts from perm[24..31]; the AND clears them).
//
// VZEROUPPER on exit per Go convention to keep upper YMM/ZMM state
// from polluting downstream non-AVX code.
TEXT ·Permute24Avx512(SB),NOSPLIT,$0-20
	MOVL    x+0(FP), AX            // AX = x
	ANDL    $0x00FFFFFF, AX        // mask to low 24 bits (defensive)
	MOVQ    perm+8(FP), DX         // DX = &perm[0]

	KMOVD   AX, K1                 // K1 = bit-mask of x
	VPMOVM2B K1, Y0                // Y0 byte = -1 / 0 per K1 bit
	VPABSB  Y0, Y0                 // Y0 byte = 1 / 0

	VMOVDQU (DX), Y1               // Y1 = perm[0..31]
	VPERMB  Y0, Y1, Y2             // Y2[i] = Y0[Y1[i] & 0x3F]
	VPTESTMB Y2, Y2, K2            // K2[i] = (Y2[i] != 0)

	KMOVD   K2, AX                 // AX = K2 low 32 bits
	ANDL    $0x00FFFFFF, AX        // mask to low 24 bits

	MOVL    AX, y+16(FP)
	VZEROUPPER
	RET

// func rankToMaskTripleUnrankAVX512(idx0, idx1 *[8]uint32, crow *[25][16]uint32, out *[3][8]uint32)
//
// Lane-parallel combinatorial-number-system unrank for 8 lanes (low 256 bits
// of ZMM; upper lanes carry harmless garbage and are never stored). Mirrors
// the bit-exact Go spec: two unranks (8-of-24 from idx0, 8-of-16 from idx1)
// plus the remap onto the bits m0 leaves free. The division (index split)
// is done caller-side; this kernel receives idx0/idx1 directly.
//
// Per descending position p, c = C(p, krem) is selected with VPERMD from the
// 16-wide table row crow[p] (krem in [0,8] addresses lanes 0..8). The pick
// (rank >= c AND krem != 0) is a mask register; the masked VPORD/VPSUBD apply
// it without secret-dependent branches or memory addressing — constant-time.
//
// Frame: 4 pointer args = 32 bytes.
//   idx0 +0(FP)  idx1 +8(FP)  crow +16(FP)  out +24(FP)
TEXT ·rankToMaskTripleUnrankAVX512(SB), NOSPLIT, $0-32
	MOVQ idx0+0(FP), AX
	MOVQ idx1+8(FP), BX
	MOVQ crow+16(FP), R14
	MOVQ out+24(FP), DI

	MOVL $1, R8
	MOVQ R8, X14
	VPBROADCASTD X14, Z6           // Z6 = 1 (all lanes)

	// ---- unrank m0: rank = idx0, n = 24 ----
	VMOVDQU (AX), Y0               // Z0 = idx0 (low 8 lanes; upper zeroed)
	MOVL $8, R8
	MOVQ R8, X14
	VPBROADCASTD X14, Z1           // Z1 = krem = 8
	VPXORD Z2, Z2, Z2              // Z2 = mask = 0
	MOVQ $23, R10                  // p = 23
loop0:
	MOVQ R10, R11
	SHLQ $6, R11                   // p * 64 (row stride)
	VMOVDQU32 (R14)(R11*1), Z3     // Z3 = crow[p] = C(p, 0..15)
	VPERMD Z3, Z1, Z4              // Z4 = C(p, krem)
	VPCMPUD $5, Z4, Z0, K1         // K1 = (rank >= c)
	VPTESTMD Z1, Z1, K2            // K2 = (krem != 0)
	KANDW K1, K2, K3               // K3 = pick
	MOVL $1, R8
	MOVQ R10, CX
	SHLL CX, R8                    // R8 = 1 << p
	MOVQ R8, X14
	VPBROADCASTD X14, Z5
	VPORD Z5, Z2, K3, Z2           // mask |= (1<<p) on picked lanes
	VPSUBD Z4, Z0, K3, Z0          // rank -= c on picked lanes
	VPSUBD Z6, Z1, K3, Z1          // krem -= 1 on picked lanes
	SUBQ $1, R10
	JGE loop0
	VMOVDQA32 Z2, Z10              // Z10 = m0

	// ---- unrank m1Local: rank = idx1, n = 16 ----
	VMOVDQU (BX), Y0
	MOVL $8, R8
	MOVQ R8, X14
	VPBROADCASTD X14, Z1
	VPXORD Z2, Z2, Z2
	MOVQ $15, R10                  // p = 15
loop1:
	MOVQ R10, R11
	SHLQ $6, R11
	VMOVDQU32 (R14)(R11*1), Z3
	VPERMD Z3, Z1, Z4
	VPCMPUD $5, Z4, Z0, K1
	VPTESTMD Z1, Z1, K2
	KANDW K1, K2, K3
	MOVL $1, R8
	MOVQ R10, CX
	SHLL CX, R8
	MOVQ R8, X14
	VPBROADCASTD X14, Z5
	VPORD Z5, Z2, K3, Z2
	VPSUBD Z4, Z0, K3, Z0
	VPSUBD Z6, Z1, K3, Z1
	SUBQ $1, R10
	JGE loop1
	VMOVDQA32 Z2, Z11             // Z11 = m1Local

	// ---- remap: deposit m1Local's bits onto the positions m0 leaves free ----
	MOVL $0x00FFFFFF, R8
	MOVQ R8, X14
	VPBROADCASTD X14, Z7          // Z7 = 0xFFFFFF
	VPANDND Z7, Z10, Z0           // Z0 = remaining = ~m0 & 0xFFFFFF
	VPXORD Z12, Z12, Z12          // Z12 = m1 = 0
	VPXORD Z13, Z13, Z13          // Z13 = posIdx = 0
	XORQ R10, R10                 // bit = 0
	// Remap temporaries use Z16..Z21 — their low halves X16..X21 never serve
	// as scratch, so the shift-count xmm X15 is not clobbered mid-iteration
	// (Z14/Z15 would alias X14/X15).
loop2:
	MOVQ R10, X15
	VPSRLD X15, Z0, Z16           // remaining >> bit
	VPANDD Z6, Z16, Z17           // remBit = (...) & 1
	VPSRLVD Z13, Z11, Z18         // m1Local >> posIdx (per-lane)
	VPANDD Z6, Z18, Z19           // mlBit = (...) & 1
	VPANDD Z17, Z19, Z20          // set = remBit & mlBit
	VPSLLD X15, Z20, Z21          // set << bit
	VPORD Z21, Z12, Z12           // m1 |= set << bit
	VPADDD Z17, Z13, Z13          // posIdx += remBit
	INCQ R10
	CMPQ R10, $24
	JLT loop2

	VPANDND Z0, Z12, Z8           // Z8 = m2 = ~m1 & remaining

	VMOVDQU Y10, (DI)             // out[0] = m0
	VMOVDQU Y12, 32(DI)           // out[1] = m1
	VMOVDQU Y8, 64(DI)            // out[2] = m2
	VZEROUPPER
	RET

// func derivePermPosAVX512(digits, out *[24][8]uint32)
//
// Single Lock Soup permutation expansion for 8 lanes (low 256 bits of ZMM;
// upper lanes carry harmless garbage and are never stored). For each output
// index i in 0..23: the digits[i][lane]-th still-free position is located by a
// 5-level popcount binary search over the per-lane free mask, written to
// out[i][lane], then cleared from the free mask. The factoradic digit
// extraction (the division) is done caller-side.
//
// Per level the d-th-free search counts set bits in the low `lvl` bits of the
// working value (VPOPCNTD), and where that count is below the rank target
// advances: rank -= count, value >>= lvl, pos += lvl — all mask-merged, so no
// secret-dependent branch or memory address. Constant-time.
//
// Frame: 2 pointer args = 16 bytes.  digits +0(FP)  out +8(FP)
TEXT ·derivePermPosAVX512(SB), NOSPLIT, $0-16
	MOVQ digits+0(FP), AX
	MOVQ out+8(FP), DI

	// Level masks (1<<lvl)-1 and pos addends, broadcast once.
	MOVL $0x0000FFFF, R8; MOVQ R8, X0; VPBROADCASTD X0, Z16  // mask16
	MOVL $0x000000FF, R8; MOVQ R8, X0; VPBROADCASTD X0, Z17  // mask8
	MOVL $0x0000000F, R8; MOVQ R8, X0; VPBROADCASTD X0, Z18  // mask4
	MOVL $0x00000003, R8; MOVQ R8, X0; VPBROADCASTD X0, Z19  // mask2
	MOVL $0x00000001, R8; MOVQ R8, X0; VPBROADCASTD X0, Z20  // mask1 / one / add1
	MOVL $16, R8; MOVQ R8, X0; VPBROADCASTD X0, Z21          // add16
	MOVL $8,  R8; MOVQ R8, X0; VPBROADCASTD X0, Z22          // add8
	MOVL $4,  R8; MOVQ R8, X0; VPBROADCASTD X0, Z23          // add4
	MOVL $2,  R8; MOVQ R8, X0; VPBROADCASTD X0, Z24          // add2
	MOVL $0x00FFFFFF, R8; MOVQ R8, X0; VPBROADCASTD X0, Z25  // free init

	VMOVDQA32 Z25, Z2              // Z2 = free = 0xFFFFFF

	XORQ R10, R10                 // i = 0
permloop:
	MOVQ R10, R11
	SHLQ $5, R11                  // i * 32
	VMOVDQU (AX)(R11*1), Y3       // Z3 = digits[i] (8 lanes)
	VPADDD Z20, Z3, Z3            // Z3 = r = digit + 1
	VPXORD Z4, Z4, Z4             // Z4 = pos = 0
	VMOVDQA32 Z2, Z5             // Z5 = x = free

	VPANDD Z16, Z5, Z6            // level 16
	VPOPCNTD Z6, Z7
	VPCMPUD $1, Z3, Z7, K1        // K1 = (c < r)
	VPSUBD Z7, Z3, K1, Z3
	VPSRLD $16, Z5, K1, Z5
	VPADDD Z21, Z4, K1, Z4

	VPANDD Z17, Z5, Z6            // level 8
	VPOPCNTD Z6, Z7
	VPCMPUD $1, Z3, Z7, K1
	VPSUBD Z7, Z3, K1, Z3
	VPSRLD $8, Z5, K1, Z5
	VPADDD Z22, Z4, K1, Z4

	VPANDD Z18, Z5, Z6            // level 4
	VPOPCNTD Z6, Z7
	VPCMPUD $1, Z3, Z7, K1
	VPSUBD Z7, Z3, K1, Z3
	VPSRLD $4, Z5, K1, Z5
	VPADDD Z23, Z4, K1, Z4

	VPANDD Z19, Z5, Z6            // level 2
	VPOPCNTD Z6, Z7
	VPCMPUD $1, Z3, Z7, K1
	VPSUBD Z7, Z3, K1, Z3
	VPSRLD $2, Z5, K1, Z5
	VPADDD Z24, Z4, K1, Z4

	VPANDD Z20, Z5, Z6            // level 1
	VPOPCNTD Z6, Z7
	VPCMPUD $1, Z3, Z7, K1
	VPSUBD Z7, Z3, K1, Z3
	VPSRLD $1, Z5, K1, Z5
	VPADDD Z20, Z4, K1, Z4        // add1 == Z20

	VMOVDQU Y4, (DI)(R11*1)       // out[i] = pos

	VPSLLVD Z4, Z20, Z6          // Z6 = 1 << pos (per lane)
	VPANDND Z2, Z6, Z2          // free = ~bit & free

	INCQ R10
	CMPQ R10, $24
	JLT permloop
	VZEROUPPER
	RET
