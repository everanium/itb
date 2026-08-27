//go:build amd64 && !purego && !noitbasm

// XMM AES-NI (no VAES) fused chained-absorb kernel for Areion-SoEM-256
// with 13-byte per-lane data input — the Interlocked Barrier PRF fill
// message shape (0x03 || uint64-LE(groupIdx) || 4 reserved). 13 bytes ≤
// 24-byte chunkSize, so the absorb is a single SoEM round. AES-NI-only
// fallback; identical structure to the 20-byte kernel
// (areion_chain256_20_aesni_amd64.s) except lengthTag = 13 and the b1
// staging loads exactly data[8..13] (MOVL 4B + MOVBLZX 1B) so a lane
// pointer to an exactly-13-byte buffer is never over-read.
//
//   state[0..8]   = lengthTag (= 13)
//   state[8..21]  = data[0..13]
//   state[21..32] = 0

#include "textflag.h"

#define AR256_ROUND(pa, pb, qa, qb, ra, rb, sa, sb, rcoff) \
	MOVOU ·AreionRC4x+rcoff(SB), X13; \
	MOVOU pa, X8;   MOVOU qa, X9;   MOVOU ra, X10;  MOVOU sa, X11; \
	AESENC X13, X8; AESENC X13, X9; AESENC X13, X10; AESENC X13, X11; \
	AESENC pb, X8;  AESENC qb, X9;  AESENC rb, X10;  AESENC sb, X11; \
	AESENCLAST X12, pa; AESENCLAST X12, qa; AESENCLAST X12, ra; AESENCLAST X12, sa; \
	MOVOU X8, pb;   MOVOU X9, qb;   MOVOU X10, rb;  MOVOU X11, sb

// func Areion256ChainAbsorb13x4AesNi(
//     fixedKey *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][4]uint64)
TEXT ·Areion256ChainAbsorb13x4AesNi(SB), NOSPLIT, $128-32
	MOVQ fixedKey+0(FP), AX
	MOVQ seeds+8(FP),    BX
	MOVQ dataPtrs+16(FP), CX
	MOVQ out+24(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== SoA staging: lengthTag(13) + data[0..13] + zero pad =====
	//   SP+0/16/32/48    = b0 of lane 0/1/2/3: [len(8) | data[0..8]]
	//   SP+64/80/96/112  = b1 of lane 0/1/2/3: [data[8..12] | data[12] | 0]
	MOVQ $13, R12
	MOVQ R12, 0(SP)
	MOVQ R12, 16(SP)
	MOVQ R12, 32(SP)
	MOVQ R12, 48(SP)

	MOVQ 0(R8),  R12
	MOVQ R12, 8(SP)
	MOVQ $0, 64(SP)
	MOVQ $0, 72(SP)
	MOVL 8(R8),  R12
	MOVL R12, 64(SP)
	MOVBLZX 12(R8), R12
	MOVB R12, 68(SP)

	MOVQ 0(R9),  R12
	MOVQ R12, 24(SP)
	MOVQ $0, 80(SP)
	MOVQ $0, 88(SP)
	MOVL 8(R9),  R12
	MOVL R12, 80(SP)
	MOVBLZX 12(R9), R12
	MOVB R12, 84(SP)

	MOVQ 0(R10), R12
	MOVQ R12, 40(SP)
	MOVQ $0, 96(SP)
	MOVQ $0, 104(SP)
	MOVL 8(R10), R12
	MOVL R12, 96(SP)
	MOVBLZX 12(R10), R12
	MOVB R12, 100(SP)

	MOVQ 0(R11), R12
	MOVQ R12, 56(SP)
	MOVQ $0, 112(SP)
	MOVQ $0, 120(SP)
	MOVL 8(R11), R12
	MOVL R12, 112(SP)
	MOVBLZX 12(R11), R12
	MOVB R12, 116(SP)

	// ============================ PASS A: lanes 0,1 ============================
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

	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 0)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 64)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 128)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 192)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 256)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 320)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 384)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 448)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 512)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 576)

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

	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 0)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 64)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 128)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 192)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 256)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 320)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 384)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 448)
	AR256_ROUND(X0,X1, X2,X3, X4,X5, X6,X7, 512)
	AR256_ROUND(X1,X0, X3,X2, X5,X4, X7,X6, 576)

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
