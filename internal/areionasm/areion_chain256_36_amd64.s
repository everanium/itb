//go:build amd64 && !purego

// Fused chained-absorb VAES kernel for Areion-SoEM-256 with 36-byte
// per-lane data input (the ITB SetNonceBits(256) buf shape).
//
// Replaces the Go closure path that builds keys[4][64]byte +
// states[4][32]byte in stack memory, calls AreionSoEM256x4 twice (once
// per CBC-MAC absorb round), and unpacks the result. Instead this
// kernel:
//
//   1. Pre-loads broadcast fixedKey (Z8/Z9) and SoA-packed per-lane
//      seedKey (Z10/Z11) once at function entry — no Go-side
//      keys[4][64] memory roundtrip.
//   2. Holds the 32-byte SoEM state in two ZMM registers (Z14/Z15) for
//      both CBC-MAC absorb rounds — no states[4][32] memory roundtrip
//      between rounds.
//   3. Inlines the 10-round Areion256 permutation twice with the same
//      interleaved (state1 / state2) ILP pattern as the fused per-half
//      kernel (`Areion256SoEMPermutex4Interleaved`).
//   4. Writes the final 32-byte result per lane directly to the
//      caller's *[4][4]uint64 output via VEXTRACTI64X2 — no
//      intermediate AoS [4][32]byte buffer.
//
// Per-lane data layout (36 bytes total) is consumed across two rounds:
//   Round 0:  state[0..8]  = lengthTag (= 36, baked into the kernel)
//             state[8..32] = data[0..24]  (chunkSize = 24 bytes)
//   Round 1:  state[8..16] ⊕= data[24..32]   (8 bytes — high half b0)
//             state[16..20] ⊕= data[32..36]  (4 bytes — low quarter b1)
//             state[20..32]  unchanged
// where (state[0..16], state[16..32]) maps to (b0, b1) Block4 SoA in
// (Z14, Z15).

#include "textflag.h"

// AREION256_FUSED_ROUND emits the per-round body of the Areion-SoEM-256
// fused permutation. (state1, state2) play the (a, b) roles per round;
// the caller swaps argument order across odd/even rounds to encode the
// Areion `(x0, x1)` role rotation. Z2 / Z6 are scratch; Z3 must hold
// zero (FinalRoundNoKey). Identical shape to the per-round body in
// the fused per-half kernel (areion_soem256_amd64.s).
#define AREION256_FUSED_ROUND(s1a, s1b, s2a, s2b, rc) \
	VMOVDQA64 s1a, Z2; \
	VMOVDQA64 s2a, Z6; \
	VAESENC rc, Z2, Z2; \
	VAESENC rc, Z6, Z6; \
	VAESENC s1b, Z2, Z2; \
	VAESENC s2b, Z6, Z6; \
	VAESENCLAST Z3, s1a, s1a; \
	VAESENCLAST Z3, s2a, s2a; \
	VMOVDQA64 Z2, s1b; \
	VMOVDQA64 Z6, s2b

// func Areion256ChainAbsorb36x4(
//     fixedKey *[32]byte,        // shared 32-byte fixed key
//     seeds *[4][4]uint64,       // per-lane 32-byte seed components
//     dataPtrs *[4]*byte,        // 4 pointers, each ≥36 bytes valid
//     out *[4][4]uint64)         // output (4 lanes × 4 uint64 = 32 bytes per lane)
//
// Frame: 128 bytes stack scratch (4 × 32 bytes for AoS state staging).
TEXT ·Areion256ChainAbsorb36x4(SB), NOSPLIT, $128-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	// Load the 4 data-buffer pointers from *(*[4]*byte).
	MOVQ 0(CX),  R8     // data[0]
	MOVQ 8(CX),  R9     // data[1]
	MOVQ 16(CX), R10    // data[2]
	MOVQ 24(CX), R11    // data[3]

	// Z3 = zero (FinalRoundNoKey "round key" for VAESENCLAST).
	VPXORD Z3, Z3, Z3

	// Z8, Z9: fixedKey b0, b1 broadcast — 4 copies of fixedKey[0..16]
	// and fixedKey[16..32] respectively, filling all 4 lane slots of
	// each ZMM. The same fixedKey is XOR'd into every lane's state
	// per SoEM key1 setup.
	VBROADCASTI32X4 0(AX),  Z8
	VBROADCASTI32X4 16(AX), Z9

	// Z10, Z11: seedKey b0, b1 SoA — lane i's seeds[0..16] in
	// Z10[i*16:i*16+16] and seeds[16..32] in Z11[i*16:i*16+16].
	// Built by VINSERTI64X2 from 16-byte fragments at stride 32 in
	// the seeds *[4][4]uint64 buffer (lane i at byte offset i*32).
	VMOVDQU 0(BX),  X10
	VINSERTI64X2 $1, 32(BX), Y10, Y10
	VINSERTI64X2 $2, 64(BX), Z10, Z10
	VINSERTI64X2 $3, 96(BX), Z10, Z10
	VMOVDQU 16(BX), X11
	VINSERTI64X2 $1, 48(BX), Y11, Y11
	VINSERTI64X2 $2, 80(BX), Z11, Z11
	VINSERTI64X2 $3, 112(BX), Z11, Z11

	// Z12: SoEM domain-separation constant — 0x01 in byte[0] of each
	// lane slot, zero elsewhere. Pre-built in package globals.
	VMOVDQU64 ·AreionSoEMDomainSep256(SB), Z12

	// Z16..Z25: Areion256 round constants RC[0..9] (4-broadcast form).
	VMOVDQU64 ·AreionRC4x+0(SB),   Z16
	VMOVDQU64 ·AreionRC4x+64(SB),  Z17
	VMOVDQU64 ·AreionRC4x+128(SB), Z18
	VMOVDQU64 ·AreionRC4x+192(SB), Z19
	VMOVDQU64 ·AreionRC4x+256(SB), Z20
	VMOVDQU64 ·AreionRC4x+320(SB), Z21
	VMOVDQU64 ·AreionRC4x+384(SB), Z22
	VMOVDQU64 ·AreionRC4x+448(SB), Z23
	VMOVDQU64 ·AreionRC4x+512(SB), Z24
	VMOVDQU64 ·AreionRC4x+576(SB), Z25

	// ===== Round 0: build state from lengthTag(36) + data[0..24] =====
	//
	// Compose the AoS state for each lane in stack scratch:
	//   stack[lane*32 + 0..8]  = 36 (length tag, baked in)
	//   stack[lane*32 + 8..32] = data[lane][0..24]
	// then pack to (Z14, Z15) SoA Block4.
	MOVQ $36, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 64(SP)
	MOVQ R12, 96(SP)

	// Lane 0 data[0..24] → stack[8..32].
	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 8(R8),  R12
	MOVQ R12, 16(SP)
	MOVQ 16(R8), R12
	MOVQ R12, 24(SP)
	// Lane 1.
	MOVQ 0(R9),  R12
	MOVQ R12, 40(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 48(SP)
	MOVQ 16(R9), R12
	MOVQ R12, 56(SP)
	// Lane 2.
	MOVQ 0(R10), R12
	MOVQ R12, 72(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 80(SP)
	MOVQ 16(R10), R12
	MOVQ R12, 88(SP)
	// Lane 3.
	MOVQ 0(R11), R12
	MOVQ R12, 104(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVQ 16(R11), R12
	MOVQ R12, 120(SP)

	// Pack AoS stack → SoA Block4 in (Z14, Z15). VMOVDQU on the
	// XMM-form (low 128 bits of ZMM) zero-extends the upper lanes; the
	// 3 subsequent VINSERTI64X2 fills lanes 1..3 from per-lane stack
	// fragments.
	VMOVDQU 0(SP), X14
	VINSERTI64X2 $1, 32(SP), Y14, Y14
	VINSERTI64X2 $2, 64(SP), Z14, Z14
	VINSERTI64X2 $3, 96(SP), Z14, Z14
	VMOVDQU 16(SP), X15
	VINSERTI64X2 $1, 48(SP), Y15, Y15
	VINSERTI64X2 $2, 80(SP), Z15, Z15
	VINSERTI64X2 $3, 112(SP), Z15, Z15

	// SoEM state setup for round 0:
	//   state1 = state ⊕ fixedKey
	//   state2 = state ⊕ seedKey ⊕ d
	VPXORD Z8,  Z14, Z0       // s1.b0 = state.b0 ⊕ fixedKey.b0
	VPXORD Z9,  Z15, Z1       // s1.b1 = state.b1 ⊕ fixedKey.b1
	VPXORD Z10, Z14, Z4       // s2.b0 = state.b0 ⊕ seedKey.b0
	VPXORD Z12, Z4,  Z4       // s2.b0 ⊕= domainSep
	VPXORD Z11, Z15, Z5       // s2.b1 = state.b1 ⊕ seedKey.b1

	// 10-round Areion256 permutation interleaved on (Z0, Z1) and (Z4, Z5).
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z16)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z17)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z18)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z19)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z20)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z21)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z22)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z23)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z24)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z25)

	// Round 0 SoEM output — replaces (Z14, Z15) with the new state.
	VPXORD Z4, Z0, Z14         // new_state.b0 = s1.b0' ⊕ s2.b0'
	VPXORD Z5, Z1, Z15         // new_state.b1 = s1.b1' ⊕ s2.b1'

	// ===== Round 1: XOR data[24..36] (12 bytes) into state[8..20] =====
	//
	// For each lane, build the 32-byte XOR pattern in stack scratch:
	//   stack[lane*32 + 0..8]   = 0
	//   stack[lane*32 + 8..16]  = data[lane][24..32]
	//   stack[lane*32 + 16..20] = data[lane][32..36]
	//   stack[lane*32 + 20..32] = 0
	// then pack and VPXORD into (Z14, Z15).
	XORQ R12, R12              // R12 = 0
	// Lane 0.
	MOVQ R12, 0(SP)
	MOVQ 24(R8), R13
	MOVQ R13, 8(SP)
	MOVL 32(R8), R13
	MOVL R13, 16(SP)
	MOVL R12, 20(SP)
	MOVQ R12, 24(SP)
	// Lane 1.
	MOVQ R12, 32(SP)
	MOVQ 24(R9), R13
	MOVQ R13, 40(SP)
	MOVL 32(R9), R13
	MOVL R13, 48(SP)
	MOVL R12, 52(SP)
	MOVQ R12, 56(SP)
	// Lane 2.
	MOVQ R12, 64(SP)
	MOVQ 24(R10), R13
	MOVQ R13, 72(SP)
	MOVL 32(R10), R13
	MOVL R13, 80(SP)
	MOVL R12, 84(SP)
	MOVQ R12, 88(SP)
	// Lane 3.
	MOVQ R12, 96(SP)
	MOVQ 24(R11), R13
	MOVQ R13, 104(SP)
	MOVL 32(R11), R13
	MOVL R13, 112(SP)
	MOVL R12, 116(SP)
	MOVQ R12, 120(SP)

	// Pack XOR pattern to (Z2, Z6) — Z2/Z6 are scratch (no permute in
	// flight at this point).
	VMOVDQU 0(SP), X2
	VINSERTI64X2 $1, 32(SP), Y2, Y2
	VINSERTI64X2 $2, 64(SP), Z2, Z2
	VINSERTI64X2 $3, 96(SP), Z2, Z2
	VMOVDQU 16(SP), X6
	VINSERTI64X2 $1, 48(SP), Y6, Y6
	VINSERTI64X2 $2, 80(SP), Z6, Z6
	VINSERTI64X2 $3, 112(SP), Z6, Z6

	// XOR data into state.
	VPXORD Z2, Z14, Z14
	VPXORD Z6, Z15, Z15

	// SoEM state setup for round 1.
	VPXORD Z8,  Z14, Z0
	VPXORD Z9,  Z15, Z1
	VPXORD Z10, Z14, Z4
	VPXORD Z12, Z4,  Z4
	VPXORD Z11, Z15, Z5

	// 10-round permute (round 1).
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z16)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z17)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z18)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z19)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z20)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z21)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z22)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z23)
	AREION256_FUSED_ROUND(Z0, Z1, Z4, Z5, Z24)
	AREION256_FUSED_ROUND(Z1, Z0, Z5, Z4, Z25)

	// Round 1 SoEM output — final state.
	VPXORD Z4, Z0, Z14
	VPXORD Z5, Z1, Z15

	// ===== Output: SoA Block4 (Z14, Z15) → AoS *[4][4]uint64 (DX) =====
	//
	// Each lane's 32-byte digest = b0 (16 bytes) at &out[lane][0], b1
	// (16 bytes) at &out[lane][2]. Use VEXTRACTI64X2 to pull 16-byte
	// fragments by lane index, write straight to caller memory.
	VEXTRACTI64X2 $0, Z14, 0(DX)
	VEXTRACTI64X2 $0, Z15, 16(DX)
	VEXTRACTI64X2 $1, Z14, 32(DX)
	VEXTRACTI64X2 $1, Z15, 48(DX)
	VEXTRACTI64X2 $2, Z14, 64(DX)
	VEXTRACTI64X2 $2, Z15, 80(DX)
	VEXTRACTI64X2 $3, Z14, 96(DX)
	VEXTRACTI64X2 $3, Z15, 112(DX)

	VZEROUPPER
	RET
