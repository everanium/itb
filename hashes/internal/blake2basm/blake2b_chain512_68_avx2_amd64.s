//go:build amd64 && !purego && !noitbasm

// AVX2 YMM-batched fused two-block chain-absorb kernel for BLAKE2b-512
// with 68-byte per-lane data input (the ITB SetNonceBits(512) buf
// shape). AVX2 counterpart of blake2b_chain512_68_amd64.s. Two 128-byte
// compression blocks per lane:
//
//	Block 1 (t=128, f=0):   buf[0:128]   = b2key + (data[0:64] ⊕ seed)
//	Block 2 (t=132, f=^0):  buf[128:132] = data[64:68], 124 zero pad
//
// The four lanes' states stay lane-parallel in YMM across both blocks;
// message words live in stack slots and v[15] in a stack slot with the
// v[12] excursion (see blake2b_chain256_20_avx2_amd64.s). The block-1
// chaining hash (cv1) is spilled into the caller's `out` buffer — dead
// until the final writeback and exactly 256 bytes (4 × 64) — so the
// stack frame stays small; it is reloaded for the block-2 final fold,
// then overwritten by the digest.
//
// Register allocation: see blake2b_chain256_20_avx2_amd64.s.

#include "textflag.h"

#define ROR63(b, t) \
	VPSRLQ $63, b, t; \
	VPADDQ b, b, b; \
	VPOR t, b, b

#define GA(a, b, c, d, mx, my, t) \
	VPADDQ b, a, a; \
	VPADDQ mx(SP), a, a; \
	VPXOR a, d, d; \
	VPSHUFD $0xB1, d, d; \
	VPADDQ d, c, c; \
	VPXOR c, b, b; \
	VPSHUFB b2bRor24<>(SB), b, b; \
	VPADDQ b, a, a; \
	VPADDQ my(SP), a, a; \
	VPXOR a, d, d; \
	VPSHUFB b2bRor16<>(SB), d, d; \
	VPADDQ d, c, c; \
	VPXOR c, b, b; \
	ROR63(b, t)

#define M(i)   (i*32)
#define V15    512
#define V12    544

#define ROUND(s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15) \
	GA(Y0, Y4, Y8,  Y12, M(s0),  M(s1),  Y15); \
	GA(Y1, Y5, Y9,  Y13, M(s2),  M(s3),  Y15); \
	GA(Y2, Y6, Y10, Y14, M(s4),  M(s5),  Y15); \
	VMOVDQU Y12, V12(SP); \
	VMOVDQU V15(SP), Y15; \
	GA(Y3, Y7, Y11, Y15, M(s6),  M(s7),  Y12); \
	GA(Y0, Y5, Y10, Y15, M(s8),  M(s9),  Y12); \
	VMOVDQU Y15, V15(SP); \
	VMOVDQU V12(SP), Y12; \
	GA(Y1, Y6, Y11, Y12, M(s10), M(s11), Y15); \
	GA(Y2, Y7, Y8,  Y13, M(s12), M(s13), Y15); \
	GA(Y3, Y4, Y9,  Y14, M(s14), M(s15), Y15)

#define ALLROUNDS \
	ROUND(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15); \
	ROUND(14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3); \
	ROUND(11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4); \
	ROUND(7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8); \
	ROUND(9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13); \
	ROUND(2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9); \
	ROUND(12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11); \
	ROUND(13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10); \
	ROUND(6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5); \
	ROUND(10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0); \
	ROUND(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15); \
	ROUND(14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3)

#define BUILD_DXS_Q(data_off, seed_idx, slot) \
	MOVQ data_off(R8),  R12; XORQ seed_idx*8+0*64(CX), R12; MOVQ R12, slot+0(SP); \
	MOVQ data_off(R9),  R13; XORQ seed_idx*8+1*64(CX), R13; MOVQ R13, slot+8(SP); \
	MOVQ data_off(R10), R14; XORQ seed_idx*8+2*64(CX), R14; MOVQ R14, slot+16(SP); \
	MOVQ data_off(R11), DI;  XORQ seed_idx*8+3*64(CX), DI;  MOVQ DI,  slot+24(SP)

#define BUILD_DEXT4_Q(data_off, slot) \
	MOVL data_off(R8),  R12; MOVQ R12, slot+0(SP); \
	MOVL data_off(R9),  R13; MOVQ R13, slot+8(SP); \
	MOVL data_off(R10), R14; MOVQ R14, slot+16(SP); \
	MOVL data_off(R11), DI;  MOVQ DI,  slot+24(SP)

#define BUILD_BCST_Q(key_off, slot) \
	MOVQ key_off(BX), R12; \
	MOVQ R12, slot+0(SP); MOVQ R12, slot+8(SP); \
	MOVQ R12, slot+16(SP); MOVQ R12, slot+24(SP)

#define ZERO_SLOT(slot) \
	VPXOR Y15, Y15, Y15; \
	VMOVDQU Y15, slot(SP)

#define STORE_LANE(y, off) \
	VEXTRACTI128 $0, y, X15; \
	VPEXTRQ $0, X15, off(R8); \
	VPEXTRQ $1, X15, off(R9); \
	VEXTRACTI128 $1, y, X15; \
	VPEXTRQ $0, X15, off(R10); \
	VPEXTRQ $1, X15, off(R11)

// func blake2b512ChainAbsorb68x4Avx2Asm(h0 *[8]uint64, b2key *[64]byte,
//     seeds *[4][8]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)
TEXT ·blake2b512ChainAbsorb68x4Avx2Asm(SB), NOSPLIT, $608-40
	MOVQ h0+0(FP),        AX
	MOVQ b2key+8(FP),     BX
	MOVQ seeds+16(FP),    CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== Block 1 state init =====
	VPBROADCASTQ 0(AX),  Y0
	VPBROADCASTQ 8(AX),  Y1
	VPBROADCASTQ 16(AX), Y2
	VPBROADCASTQ 24(AX), Y3
	VPBROADCASTQ 32(AX), Y4
	VPBROADCASTQ 40(AX), Y5
	VPBROADCASTQ 48(AX), Y6
	VPBROADCASTQ 56(AX), Y7

	VPBROADCASTQ ·Blake2bIV+0(SB),  Y8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Y9
	VPBROADCASTQ ·Blake2bIV+16(SB), Y10
	VPBROADCASTQ ·Blake2bIV+24(SB), Y11
	VPBROADCASTQ ·Blake2bIV+32(SB), Y12
	VPBROADCASTQ ·Blake2bIV+40(SB), Y13
	VPBROADCASTQ ·Blake2bIV+48(SB), Y14

	// Block 1: t=128, f=0. v15=IV[7] → slot.
	MOVQ $128, R12
	VMOVQ R12, X15
	VPBROADCASTQ X15, Y15
	VPXOR Y15, Y12, Y12
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15
	VMOVDQU Y15, V15(SP)

	// Block 1 messages: m0..7=key, m8..15 = data[0:64] ⊕ seed[0:8].
	BUILD_DXS_Q(0,  0, M(8))
	BUILD_DXS_Q(8,  1, M(9))
	BUILD_DXS_Q(16, 2, M(10))
	BUILD_DXS_Q(24, 3, M(11))
	BUILD_DXS_Q(32, 4, M(12))
	BUILD_DXS_Q(40, 5, M(13))
	BUILD_DXS_Q(48, 6, M(14))
	BUILD_DXS_Q(56, 7, M(15))
	BUILD_BCST_Q(0,  M(0))
	BUILD_BCST_Q(8,  M(1))
	BUILD_BCST_Q(16, M(2))
	BUILD_BCST_Q(24, M(3))
	BUILD_BCST_Q(32, M(4))
	BUILD_BCST_Q(40, M(5))
	BUILD_BCST_Q(48, M(6))
	BUILD_BCST_Q(56, M(7))

	ALLROUNDS

	// Block 1 fold: cv1[k] = h0[k]^v[k]^v[k+8] → Y0..Y7.
	VPBROADCASTQ 0(AX),  Y15
	VPXOR Y8, Y0, Y0
	VPXOR Y15, Y0, Y0
	VPBROADCASTQ 8(AX),  Y15
	VPXOR Y9, Y1, Y1
	VPXOR Y15, Y1, Y1
	VPBROADCASTQ 16(AX), Y15
	VPXOR Y10, Y2, Y2
	VPXOR Y15, Y2, Y2
	VPBROADCASTQ 24(AX), Y15
	VPXOR Y11, Y3, Y3
	VPXOR Y15, Y3, Y3
	VPBROADCASTQ 32(AX), Y15
	VPXOR Y12, Y4, Y4
	VPXOR Y15, Y4, Y4
	VPBROADCASTQ 40(AX), Y15
	VPXOR Y13, Y5, Y5
	VPXOR Y15, Y5, Y5
	VPBROADCASTQ 48(AX), Y15
	VPXOR Y14, Y6, Y6
	VPXOR Y15, Y6, Y6
	VMOVDQU V15(SP), Y15
	VPXOR Y15, Y7, Y7
	VPBROADCASTQ 56(AX), Y15
	VPXOR Y15, Y7, Y7

	// Spill cv1 (Y0..Y7) to the caller's out buffer (linear 8 × 32B).
	VMOVDQU Y0, 0(R15)
	VMOVDQU Y1, 32(R15)
	VMOVDQU Y2, 64(R15)
	VMOVDQU Y3, 96(R15)
	VMOVDQU Y4, 128(R15)
	VMOVDQU Y5, 160(R15)
	VMOVDQU Y6, 192(R15)
	VMOVDQU Y7, 224(R15)

	// ===== Block 2 state init (v0..7 = cv1 already in Y0..Y7) =====
	VPBROADCASTQ ·Blake2bIV+0(SB),  Y8
	VPBROADCASTQ ·Blake2bIV+8(SB),  Y9
	VPBROADCASTQ ·Blake2bIV+16(SB), Y10
	VPBROADCASTQ ·Blake2bIV+24(SB), Y11
	VPBROADCASTQ ·Blake2bIV+32(SB), Y12
	VPBROADCASTQ ·Blake2bIV+40(SB), Y13
	VPBROADCASTQ ·Blake2bIV+48(SB), Y14

	// Block 2: t=132, f=^0 (final). v15=IV[7] → slot.
	MOVQ $132, R12
	VMOVQ R12, X15
	VPBROADCASTQ X15, Y15
	VPXOR Y15, Y12, Y12
	VPCMPEQB Y15, Y15, Y15
	VPXOR Y15, Y14, Y14
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15
	VMOVDQU Y15, V15(SP)

	// Block 2 messages: m0 = (data[64:68]||0), no seed; m1..15 = 0.
	BUILD_DEXT4_Q(64, M(0))
	ZERO_SLOT(M(1))
	ZERO_SLOT(M(2))
	ZERO_SLOT(M(3))
	ZERO_SLOT(M(4))
	ZERO_SLOT(M(5))
	ZERO_SLOT(M(6))
	ZERO_SLOT(M(7))
	ZERO_SLOT(M(8))
	ZERO_SLOT(M(9))
	ZERO_SLOT(M(10))
	ZERO_SLOT(M(11))
	ZERO_SLOT(M(12))
	ZERO_SLOT(M(13))
	ZERO_SLOT(M(14))
	ZERO_SLOT(M(15))

	ALLROUNDS

	// Block 2 final fold: out[k] = cv1[k]^v[k]^v[k+8]. cv1 reloaded
	// from the out spill via memory operands; the fold completes into
	// Y0..Y7 before STORE_LANE overwrites the spill region.
	VPXOR 0(R15),   Y0, Y0
	VPXOR Y8, Y0, Y0
	VPXOR 32(R15),  Y1, Y1
	VPXOR Y9, Y1, Y1
	VPXOR 64(R15),  Y2, Y2
	VPXOR Y10, Y2, Y2
	VPXOR 96(R15),  Y3, Y3
	VPXOR Y11, Y3, Y3
	VPXOR 128(R15), Y4, Y4
	VPXOR Y12, Y4, Y4
	VPXOR 160(R15), Y5, Y5
	VPXOR Y13, Y5, Y5
	VPXOR 192(R15), Y6, Y6
	VPXOR Y14, Y6, Y6
	VPXOR 224(R15), Y7, Y7
	VMOVDQU V15(SP), Y15
	VPXOR Y15, Y7, Y7

	// Writeback (interleaved lane layout; overwrites the cv1 spill).
	MOVQ R15, R8
	LEAQ 64(R15),  R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11
	STORE_LANE(Y0, 0)
	STORE_LANE(Y1, 8)
	STORE_LANE(Y2, 16)
	STORE_LANE(Y3, 24)
	STORE_LANE(Y4, 32)
	STORE_LANE(Y5, 40)
	STORE_LANE(Y6, 48)
	STORE_LANE(Y7, 56)

	VZEROUPPER
	RET

DATA b2bRor24<>+0(SB)/8,  $0x0201000706050403
DATA b2bRor24<>+8(SB)/8,  $0x0a09080f0e0d0c0b
DATA b2bRor24<>+16(SB)/8, $0x0201000706050403
DATA b2bRor24<>+24(SB)/8, $0x0a09080f0e0d0c0b
GLOBL b2bRor24<>(SB), RODATA|NOPTR, $32

DATA b2bRor16<>+0(SB)/8,  $0x0100070605040302
DATA b2bRor16<>+8(SB)/8,  $0x09080f0e0d0c0b0a
DATA b2bRor16<>+16(SB)/8, $0x0100070605040302
DATA b2bRor16<>+24(SB)/8, $0x09080f0e0d0c0b0a
GLOBL b2bRor16<>(SB), RODATA|NOPTR, $32
