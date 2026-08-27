//go:build amd64 && !purego && !noitbasm

// YMM VAES (no AVX-512) fused chained-absorb kernel for Areion-SoEM-256
// with 20-byte per-lane data input (the ITB Config.NonceBits=128 buf
// shape — the default config). Batched path for hosts that expose VAES
// on YMM (VAESENC / VAESENCLAST, 2 AES blocks per instruction) but lack
// AVX-512: Alder Lake / Raptor Lake / Meteor Lake / Lunar Lake / Arrow
// Lake E-cores, P-cores with BIOS-disabled AVX-512, some enterprise
// SKUs. Bit-exact with the ZMM kernel Areion256ChainAbsorb20x4, the XMM
// AES-NI kernel Areion256ChainAbsorb20x4AesNi, and the Go single closure.
//
// 20 bytes <= 24-byte chunkSize, so the absorb is one SoEM round.
//
// Lane strategy (playbook §2 natural active-width / §8 ILP restore):
// the 4 pixel lanes are processed in two passes of 2 lanes each. Each
// YMM register holds two lanes' 16-byte AES block (low 128 = even lane,
// high 128 = odd lane); VAESENC on YMM applies the same round to both
// 128-bit halves. Within a pass, state1 and state2 permutations run
// interleaved = 4 independent VAES ops per round (two temp-chain heads
// + two FinalRoundNoKey), enough to hide the ~4-cycle VAESENC latency on
// a single VAES issue port. This is the direct ZMM 4-lane -> YMM 2-lane
// narrowing: round algebra is identical, only the register width and
// the EVEX -> VEX encoding change.
//
// Per-lane data layout (matches the ZMM kernel / Go closure):
//   state[0..8]   = lengthTag (= 20, baked in)
//   state[8..28]  = data[0..20]
//   state[28..32] = 0
//
// Register allocation (per pass, 2 lanes):
//   Y0,Y1  state1 (a,b)          Y4,Y5  round temps (t1,t2)
//   Y2,Y3  state2 (a,b)          Y6     zero (FinalRoundNoKey)
//   Y7     round constant        Y8..Y11 fixedKey/seed scratch (setup)
//   Y12    domain separation
//
// Stack frame: 128 bytes SoA staging (b0 of all 4 lanes at SP+0/16/32/48,
// b1 at SP+64/80/96/112), built once at entry, then loaded 2 lanes/pass.

#include "textflag.h"

// AR256_YROUND — one Areion256 round across the 2-lane pass's state1
// (s1a,s1b) and state2 (s2a,s2b), each a YMM holding two lanes. rcoff is
// the byte offset of the round constant in ·AreionRC4x (only its low
// 16 bytes are read; VBROADCASTI128 replicates them to both YMM halves).
// Maps the software round via 3-operand VEX (no pre-copy needed — s1a is
// read into the temp before it is overwritten by FinalRoundNoKey):
//   t = RoundNoKey(a) ⊕ rc; t = RoundNoKey(t) ⊕ b;
//   a = FinalRoundNoKey(a); b = t
// The caller swaps (a,b) argument order across odd/even rounds to encode
// the Areion (x0,x1) role rotation.
#define AR256_YROUND(s1a, s1b, s2a, s2b, rcoff) \
	VBROADCASTI128 ·AreionRC4x+rcoff(SB), Y7; \
	VAESENC Y7, s1a, Y4; \
	VAESENC Y7, s2a, Y5; \
	VAESENC s1b, Y4, Y4; \
	VAESENC s2b, Y5, Y5; \
	VAESENCLAST Y6, s1a, s1a; \
	VAESENCLAST Y6, s2a, s2a; \
	VMOVDQA Y4, s1b; \
	VMOVDQA Y5, s2b

// AR256_YPERM10 — the 10-round Areion256 permutation on state1 (Y0,Y1)
// and state2 (Y2,Y3), (a,b) role swap per round.
#define AR256_YPERM10 \
	AR256_YROUND(Y0, Y1, Y2, Y3, 0) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 64) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 128) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 192) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 256) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 320) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 384) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 448) \
	AR256_YROUND(Y0, Y1, Y2, Y3, 512) \
	AR256_YROUND(Y1, Y0, Y3, Y2, 576)

// func Areion256ChainAbsorb20x4VaesAvx2(
//     fixedKey *[32]byte,
//     seeds *[4][4]uint64,
//     dataPtrs *[4]*byte,        // each ptr to >=20 bytes
//     out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb20x4VaesAvx2(SB), NOSPLIT, $128-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	VPXOR Y6, Y6, Y6
	VMOVDQU ·AreionSoEMDomainSep256(SB), Y12

	// ===== SoA staging: lengthTag(20) + data[0..20] + zero pad =====
	//   SP+0/16/32/48    = b0 of lane 0/1/2/3: [len(8) | data[0..8]]
	//   SP+64/80/96/112  = b1 of lane 0/1/2/3: [data[8..16] | data[16..20] | 0]
	MOVQ $20, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 8(R8),  R12
	MOVQ R12, 64(SP)
	MOVL 16(R8), R12
	MOVL R12, 72(SP)
	MOVL $0, 76(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 80(SP)
	MOVL 16(R9), R12
	MOVL R12, 88(SP)
	MOVL $0, 92(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 96(SP)
	MOVL 16(R10), R12
	MOVL R12, 104(SP)
	MOVL $0, 108(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVL 16(R11), R12
	MOVL R12, 120(SP)
	MOVL $0, 124(SP)

	// ============================ PASS A: lanes 0,1 ============================
	// state1 (Y0,Y1) = raw ⊕ fixedKey ; state2 (Y2,Y3) = raw ⊕ seed ⊕ dom.
	VMOVDQU 0(SP),  Y8            // raw b0 (lanes 0,1)
	VMOVDQU 64(SP), Y9           // raw b1 (lanes 0,1)
	VBROADCASTI128 0(AX),  Y10
	VPXOR Y10, Y8, Y0            // s1.a
	VBROADCASTI128 16(AX), Y11
	VPXOR Y11, Y9, Y1           // s1.b
	VMOVDQU 0(BX), X10
	VINSERTI128 $1, 32(BX), Y10, Y10   // seed b0 (lanes 0,1)
	VPXOR Y10, Y8, Y2
	VPXOR Y12, Y2, Y2           // s2.a = raw ⊕ seed ⊕ dom
	VMOVDQU 16(BX), X11
	VINSERTI128 $1, 48(BX), Y11, Y11   // seed b1 (lanes 0,1)
	VPXOR Y11, Y9, Y3           // s2.b

	AR256_YPERM10

	VPXOR Y2, Y0, Y0            // SoEM output b0 = s1.a' ⊕ s2.a'
	VPXOR Y3, Y1, Y1           // SoEM output b1 = s1.b' ⊕ s2.b'
	VEXTRACTI128 $0, Y0, 0(DX)
	VEXTRACTI128 $0, Y1, 16(DX)
	VEXTRACTI128 $1, Y0, 32(DX)
	VEXTRACTI128 $1, Y1, 48(DX)

	// ============================ PASS B: lanes 2,3 ============================
	VMOVDQU 32(SP), Y8           // raw b0 (lanes 2,3)
	VMOVDQU 96(SP), Y9          // raw b1 (lanes 2,3)
	VBROADCASTI128 0(AX),  Y10
	VPXOR Y10, Y8, Y0
	VBROADCASTI128 16(AX), Y11
	VPXOR Y11, Y9, Y1
	VMOVDQU 64(BX), X10
	VINSERTI128 $1, 96(BX), Y10, Y10   // seed b0 (lanes 2,3)
	VPXOR Y10, Y8, Y2
	VPXOR Y12, Y2, Y2
	VMOVDQU 80(BX), X11
	VINSERTI128 $1, 112(BX), Y11, Y11  // seed b1 (lanes 2,3)
	VPXOR Y11, Y9, Y3

	AR256_YPERM10

	VPXOR Y2, Y0, Y0
	VPXOR Y3, Y1, Y1
	VEXTRACTI128 $0, Y0, 64(DX)
	VEXTRACTI128 $0, Y1, 80(DX)
	VEXTRACTI128 $1, Y0, 96(DX)
	VEXTRACTI128 $1, Y1, 112(DX)

	VZEROUPPER
	RET
