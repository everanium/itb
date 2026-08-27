//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-256
// with 68-byte per-lane data input (the ITB Config.NonceBits=512 buf
// shape). 68 > 24-byte chunkSize, so the absorb runs as 3 SoEM rounds;
// within a 2-lane pass the SoEM state is carried in XMM registers
// across all three rounds. AES-NI-only fallback; see
// areion_chain256_20_aesni_amd64.s for the pass / register-layout
// rationale. Bit-exact with the VAES kernel Areion256ChainAbsorb68x4.
//
// Per-lane data layout consumed across three rounds (matches VAES):
//   Round 0:  state[0..8]  = lengthTag (= 68); state[8..32] = data[0..24]
//   Round 1:  state[8..16] ⊕= data[24..32]; state[16..32] ⊕= data[32..48]
//   Round 2:  state[8..16] ⊕= data[48..56]; state[16..28] ⊕= data[56..68]

#include "textflag.h"

#define AR256_ROUND(pa, pb, qa, qb, ra, rb, sa, sb, rcoff) \
	MOVOU ·AreionRC4x+rcoff(SB), X13; \
	MOVOU pa, X8;   MOVOU qa, X9;   MOVOU ra, X10;  MOVOU sa, X11; \
	AESENC X13, X8; AESENC X13, X9; AESENC X13, X10; AESENC X13, X11; \
	AESENC pb, X8;  AESENC qb, X9;  AESENC rb, X10;  AESENC sb, X11; \
	AESENCLAST X12, pa; AESENCLAST X12, qa; AESENCLAST X12, ra; AESENCLAST X12, sa; \
	MOVOU X8, pb;   MOVOU X9, qb;   MOVOU X10, rb;  MOVOU X11, sb

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

// SETUP_ROUND0 loads fixedKey / domainSep and builds state1/state2 for
// the two pass lanes from the SoA staging at SP. spb0P/spb1P/... are SP
// offsets; s0P/s1P are the lane-P seed offsets in BX; likewise lane Q.
// Emits: X0,X1=s1P  X2,X3=s2P  X4,X5=s1Q  X6,X7=s2Q; zeroes X12.

// func Areion256ChainAbsorb68x4AesNi(
//     fixedKey *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][4]uint64)
// Stack frame: SP+0..128 = round-0 SoA staging (consumed by both
// passes' round-0 setup); SP+128..192 = inter-round XOR-pattern staging
// (transient per pass, disjoint from the round-0 region).
TEXT ·Areion256ChainAbsorb68x4AesNi(SB), NOSPLIT, $192-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== SoA staging: lengthTag(68) + data[0..24] =====
	MOVQ $68, R12
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
	// ---- Round 0 setup ----
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

	PXOR X2, X0
	PXOR X3, X1
	PXOR X6, X4
	PXOR X7, X5

	// ---- Round 1 absorb: data[24..48] into state[8..32] ----
	// Pattern staging uses the disjoint SP+128 region (pass B round-0
	// input at SP+32/48 must survive).
	// lane0 (R8): b0-pat SP+128=[0|data24-32]; b1-pat SP+144=data[32..48]
	MOVQ $0, 128(SP)
	MOVQ 24(R8), R12
	MOVQ R12, 136(SP)
	MOVQ 32(R8), R12
	MOVQ R12, 144(SP)
	MOVQ 40(R8), R12
	MOVQ R12, 152(SP)
	// lane1 (R9): b0-pat SP+160; b1-pat SP+176
	MOVQ $0, 160(SP)
	MOVQ 24(R9), R12
	MOVQ R12, 168(SP)
	MOVQ 32(R9), R12
	MOVQ R12, 176(SP)
	MOVQ 40(R9), R12
	MOVQ R12, 184(SP)

	MOVOU 128(SP), X2
	PXOR X2, X0
	MOVOU 144(SP), X3
	PXOR X3, X1
	MOVOU 160(SP), X6
	PXOR X6, X4
	MOVOU 176(SP), X7
	PXOR X7, X5

	// ---- Round 1 setup ----
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

	PXOR X2, X0
	PXOR X3, X1
	PXOR X6, X4
	PXOR X7, X5

	// ---- Round 2 absorb: data[48..68] into state[8..28] ----
	// lane0 (R8): b0-pat SP+128=[0|data48-56]; b1-pat SP+144=[data56-64|data64-68|0]
	MOVQ $0, 128(SP)
	MOVQ 48(R8), R12
	MOVQ R12, 136(SP)
	MOVQ 56(R8), R12
	MOVQ R12, 144(SP)
	MOVL 64(R8), R12
	MOVL R12, 152(SP)
	MOVL $0, 156(SP)
	// lane1 (R9)
	MOVQ $0, 160(SP)
	MOVQ 48(R9), R12
	MOVQ R12, 168(SP)
	MOVQ 56(R9), R12
	MOVQ R12, 176(SP)
	MOVL 64(R9), R12
	MOVL R12, 184(SP)
	MOVL $0, 188(SP)

	MOVOU 128(SP), X2
	PXOR X2, X0
	MOVOU 144(SP), X3
	PXOR X3, X1
	MOVOU 160(SP), X6
	PXOR X6, X4
	MOVOU 176(SP), X7
	PXOR X7, X5

	// ---- Round 2 setup ----
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
	// ---- Round 0 setup ----
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

	// ---- Round 1 absorb: data[24..48] ----
	MOVQ $0, 128(SP)
	MOVQ 24(R10), R12
	MOVQ R12, 136(SP)
	MOVQ 32(R10), R12
	MOVQ R12, 144(SP)
	MOVQ 40(R10), R12
	MOVQ R12, 152(SP)
	MOVQ $0, 160(SP)
	MOVQ 24(R11), R12
	MOVQ R12, 168(SP)
	MOVQ 32(R11), R12
	MOVQ R12, 176(SP)
	MOVQ 40(R11), R12
	MOVQ R12, 184(SP)

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

	PXOR X2, X0
	PXOR X3, X1
	PXOR X6, X4
	PXOR X7, X5

	// ---- Round 2 absorb: data[48..68] ----
	MOVQ $0, 128(SP)
	MOVQ 48(R10), R12
	MOVQ R12, 136(SP)
	MOVQ 56(R10), R12
	MOVQ R12, 144(SP)
	MOVL 64(R10), R12
	MOVL R12, 152(SP)
	MOVL $0, 156(SP)
	MOVQ $0, 160(SP)
	MOVQ 48(R11), R12
	MOVQ R12, 168(SP)
	MOVQ 56(R11), R12
	MOVQ R12, 176(SP)
	MOVL 64(R11), R12
	MOVL R12, 184(SP)
	MOVL $0, 188(SP)

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
