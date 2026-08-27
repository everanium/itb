//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-256
// with 36-byte per-lane data input (the ITB Config.NonceBits=256 buf
// shape). 36 > 24-byte chunkSize, so the absorb runs as 2 SoEM rounds;
// within a 2-lane pass the intermediate SoEM state is carried in XMM
// registers across both rounds (no memory round-trip). AES-NI-only
// fallback; see areion_chain256_20_aesni_amd64.s for the pass /
// register-layout rationale. Bit-exact with the VAES kernel
// Areion256ChainAbsorb36x4.
//
// Per-lane data layout consumed across two rounds (matches VAES kernel):
//   Round 0:  state[0..8]  = lengthTag (= 36)
//             state[8..32] = data[0..24]   (24-byte chunk)
//   Round 1:  state[8..16] ⊕= data[24..32]  (8 bytes — b0 high half)
//             state[16..20] ⊕= data[32..36] (4 bytes — b1 low quarter)

#include "textflag.h"

#define AR256_ROUND(pa, pb, qa, qb, ra, rb, sa, sb, rcoff) \
	MOVOU ·AreionRC4x+rcoff(SB), X13; \
	MOVOU pa, X8;   MOVOU qa, X9;   MOVOU ra, X10;  MOVOU sa, X11; \
	AESENC X13, X8; AESENC X13, X9; AESENC X13, X10; AESENC X13, X11; \
	AESENC pb, X8;  AESENC qb, X9;  AESENC rb, X10;  AESENC sb, X11; \
	AESENCLAST X12, pa; AESENCLAST X12, qa; AESENCLAST X12, ra; AESENCLAST X12, sa; \
	MOVOU X8, pb;   MOVOU X9, qb;   MOVOU X10, rb;  MOVOU X11, sb

// AR256_PERM10 — the 10-round permutation on the four chains X0..X7.
#define AR256_PERM10 \
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 0) \
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 64) \
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 128) \
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 192) \
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 256) \
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 320) \
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 384) \
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 448) \
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 512) \
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 576)

// func Areion256ChainAbsorb36x4AesNi(
//     fixedKey *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][4]uint64)
//
// Stack frame: SP+0..128 = round-0 SoA staging (consumed by both
// passes' round-0 setup); SP+128..192 = inter-round XOR-pattern
// staging (transient per pass, kept disjoint from the round-0 region so
// pass A's round-1 staging does not clobber pass B's round-0 input).
TEXT ·Areion256ChainAbsorb36x4AesNi(SB), NOSPLIT, $192-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== SoA staging: lengthTag(36) + data[0..24] =====
	//   SP+0/16/32/48    = b0: [len(8) | data[0..8]]
	//   SP+64/80/96/112  = b1: [data[8..24]]
	MOVQ $36, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ 8(R8),  R12
	MOVQ R12, 64(SP)
	MOVQ 16(R8), R12
	MOVQ R12, 72(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ 8(R9),  R12
	MOVQ R12, 80(SP)
	MOVQ 16(R9), R12
	MOVQ R12, 88(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ 8(R10), R12
	MOVQ R12, 96(SP)
	MOVQ 16(R10), R12
	MOVQ R12, 104(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ 8(R11), R12
	MOVQ R12, 112(SP)
	MOVQ 16(R11), R12
	MOVQ R12, 120(SP)

	// ============================ PASS A: lanes 0,1 ============================
	// ---- Round 0 setup (from SP staging) ----
	MOVOU 0(AX),  X14
	MOVOU 16(AX), X15
	MOVOU ·AreionSoEMDomainSep256(SB), X13

	MOVOU 0(SP),  X8
	MOVOU 64(SP), X9
	MOVOU X8, X0
	PXOR X14, X0
	MOVOU X9, X1
	PXOR X15, X1
	MOVOU 0(BX),  X10
	MOVOU 16(BX), X11
	MOVOU X8, X2
	PXOR X10, X2
	PXOR X13, X2
	MOVOU X9, X3
	PXOR X11, X3

	MOVOU 16(SP), X8
	MOVOU 80(SP), X9
	MOVOU X8, X4
	PXOR X14, X4
	MOVOU X9, X5
	PXOR X15, X5
	MOVOU 32(BX), X10
	MOVOU 48(BX), X11
	MOVOU X8, X6
	PXOR X10, X6
	PXOR X13, X6
	MOVOU X9, X7
	PXOR X11, X7

	PXOR X12, X12
	AR256_PERM10

	// ---- Fold round-0 SoEM output into carried state ----
	PXOR X2, X0                  // new b0 lane0
	PXOR X3, X1                  // new b1 lane0
	PXOR X6, X4                  // new b0 lane1
	PXOR X7, X5                  // new b1 lane1

	// ---- Round 1 absorb: XOR data[24..36] into state[8..20] ----
	// Pattern staging uses the disjoint SP+128 region so pass B's
	// round-0 staging (SP+32/48) is not clobbered.
	// lane0 (R8): b0-pat SP+128 = [0 | data24..32]; b1-pat SP+144 = [data32..36 | 0]
	MOVQ $0, 128(SP)
	MOVQ 24(R8), R12
	MOVQ R12, 136(SP)
	MOVL 32(R8), R12
	MOVL R12, 144(SP)
	MOVL $0, 148(SP)
	MOVQ $0, 152(SP)
	// lane1 (R9): b0-pat SP+160; b1-pat SP+176
	MOVQ $0, 160(SP)
	MOVQ 24(R9), R12
	MOVQ R12, 168(SP)
	MOVL 32(R9), R12
	MOVL R12, 176(SP)
	MOVL $0, 180(SP)
	MOVQ $0, 184(SP)

	MOVOU 128(SP), X2
	PXOR X2, X0
	MOVOU 144(SP), X3
	PXOR X3, X1
	MOVOU 160(SP), X6
	PXOR X6, X4
	MOVOU 176(SP), X7
	PXOR X7, X5

	// ---- Round 1 setup (from carried state regs) ----
	MOVOU 0(AX),  X14
	MOVOU 16(AX), X15
	MOVOU ·AreionSoEMDomainSep256(SB), X13

	MOVOU 0(BX),  X10
	MOVOU 16(BX), X11
	MOVOU X0, X2
	PXOR X10, X2
	PXOR X13, X2
	MOVOU X1, X3
	PXOR X11, X3
	PXOR X14, X0
	PXOR X15, X1

	MOVOU 32(BX), X10
	MOVOU 48(BX), X11
	MOVOU X4, X6
	PXOR X10, X6
	PXOR X13, X6
	MOVOU X5, X7
	PXOR X11, X7
	PXOR X14, X4
	PXOR X15, X5

	PXOR X12, X12
	AR256_PERM10

	// ---- Write lanes 0,1 ----
	MOVOU X0, X8
	PXOR X2, X8
	MOVOU X8, 0(DX)
	MOVOU X1, X9
	PXOR X3, X9
	MOVOU X9, 16(DX)
	MOVOU X4, X8
	PXOR X6, X8
	MOVOU X8, 32(DX)
	MOVOU X5, X9
	PXOR X7, X9
	MOVOU X9, 48(DX)

	// ============================ PASS B: lanes 2,3 ============================
	MOVOU 0(AX),  X14
	MOVOU 16(AX), X15
	MOVOU ·AreionSoEMDomainSep256(SB), X13

	MOVOU 32(SP), X8
	MOVOU 96(SP), X9
	MOVOU X8, X0
	PXOR X14, X0
	MOVOU X9, X1
	PXOR X15, X1
	MOVOU 64(BX), X10
	MOVOU 80(BX), X11
	MOVOU X8, X2
	PXOR X10, X2
	PXOR X13, X2
	MOVOU X9, X3
	PXOR X11, X3

	MOVOU 48(SP),  X8
	MOVOU 112(SP), X9
	MOVOU X8, X4
	PXOR X14, X4
	MOVOU X9, X5
	PXOR X15, X5
	MOVOU 96(BX),  X10
	MOVOU 112(BX), X11
	MOVOU X8, X6
	PXOR X10, X6
	PXOR X13, X6
	MOVOU X9, X7
	PXOR X11, X7

	PXOR X12, X12
	AR256_PERM10

	PXOR X2, X0
	PXOR X3, X1
	PXOR X6, X4
	PXOR X7, X5

	// lane2 (R10): b0-pat SP+128; b1-pat SP+144
	MOVQ $0, 128(SP)
	MOVQ 24(R10), R12
	MOVQ R12, 136(SP)
	MOVL 32(R10), R12
	MOVL R12, 144(SP)
	MOVL $0, 148(SP)
	MOVQ $0, 152(SP)
	// lane3 (R11): b0-pat SP+160; b1-pat SP+176
	MOVQ $0, 160(SP)
	MOVQ 24(R11), R12
	MOVQ R12, 168(SP)
	MOVL 32(R11), R12
	MOVL R12, 176(SP)
	MOVL $0, 180(SP)
	MOVQ $0, 184(SP)

	MOVOU 128(SP), X2
	PXOR X2, X0
	MOVOU 144(SP), X3
	PXOR X3, X1
	MOVOU 160(SP), X6
	PXOR X6, X4
	MOVOU 176(SP), X7
	PXOR X7, X5

	MOVOU 0(AX),  X14
	MOVOU 16(AX), X15
	MOVOU ·AreionSoEMDomainSep256(SB), X13

	MOVOU 64(BX), X10
	MOVOU 80(BX), X11
	MOVOU X0, X2
	PXOR X10, X2
	PXOR X13, X2
	MOVOU X1, X3
	PXOR X11, X3
	PXOR X14, X0
	PXOR X15, X1

	MOVOU 96(BX),  X10
	MOVOU 112(BX), X11
	MOVOU X4, X6
	PXOR X10, X6
	PXOR X13, X6
	MOVOU X5, X7
	PXOR X11, X7
	PXOR X14, X4
	PXOR X15, X5

	PXOR X12, X12
	AR256_PERM10

	MOVOU X0, X8
	PXOR X2, X8
	MOVOU X8, 64(DX)
	MOVOU X1, X9
	PXOR X3, X9
	MOVOU X9, 80(DX)
	MOVOU X4, X8
	PXOR X6, X8
	MOVOU X8, 96(DX)
	MOVOU X5, X9
	PXOR X7, X9
	MOVOU X9, 112(DX)

	RET
