//go:build amd64 && !purego && !noitbasm

// AVX2 YMM-batched fused chain-absorb kernel for BLAKE2b-256 with
// 36-byte per-lane data input (the ITB SetNonceBits(256) buf shape).
// AVX2 counterpart of blake2b_chain256_36_amd64.s. Single compression
// block per lane (buf is 68 bytes ≤ 128), t = 68 = key_len(32) +
// data_len(36). The seed-injection region is buf[32:64] = m[4..7]; the
// 4-byte data tail at m[8] carries no seed XOR. Layout and register
// schedule identical to the 20-byte AVX2 kernel.

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

#define BUILD_DXS_Q(data_off, seed_idx, slot) \
	MOVQ data_off(R8),  R12; XORQ seed_idx*8+0*32(CX), R12; MOVQ R12, slot+0(SP); \
	MOVQ data_off(R9),  R13; XORQ seed_idx*8+1*32(CX), R13; MOVQ R13, slot+8(SP); \
	MOVQ data_off(R10), R14; XORQ seed_idx*8+2*32(CX), R14; MOVQ R14, slot+16(SP); \
	MOVQ data_off(R11), DI;  XORQ seed_idx*8+3*32(CX), DI;  MOVQ DI,  slot+24(SP)

// 4-byte data tail zero-extended, no seed XOR (m[8] of the 36-byte shape).
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

// func blake2b256ChainAbsorb36x4Avx2Asm(h0 *[8]uint64, b2key *[32]byte,
//     seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)
TEXT ·blake2b256ChainAbsorb36x4Avx2Asm(SB), NOSPLIT, $608-40
	MOVQ h0+0(FP),        AX
	MOVQ b2key+8(FP),     BX
	MOVQ seeds+16(FP),    CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

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

	MOVQ $68, R12
	VMOVQ R12, X15
	VPBROADCASTQ X15, Y15
	VPXOR Y15, Y12, Y12
	VPCMPEQB Y15, Y15, Y15
	VPXOR Y15, Y14, Y14
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15
	VMOVDQU Y15, V15(SP)

	BUILD_DXS_Q(0,  0, M(4))
	BUILD_DXS_Q(8,  1, M(5))
	BUILD_DXS_Q(16, 2, M(6))
	BUILD_DXS_Q(24, 3, M(7))
	BUILD_DEXT4_Q(32, M(8))
	BUILD_BCST_Q(0,  M(0))
	BUILD_BCST_Q(8,  M(1))
	BUILD_BCST_Q(16, M(2))
	BUILD_BCST_Q(24, M(3))
	ZERO_SLOT(M(9))
	ZERO_SLOT(M(10))
	ZERO_SLOT(M(11))
	ZERO_SLOT(M(12))
	ZERO_SLOT(M(13))
	ZERO_SLOT(M(14))
	ZERO_SLOT(M(15))

	ROUND(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
	ROUND(14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3)
	ROUND(11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4)
	ROUND(7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8)
	ROUND(9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13)
	ROUND(2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9)
	ROUND(12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11)
	ROUND(13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10)
	ROUND(6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5)
	ROUND(10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0)
	ROUND(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
	ROUND(14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3)

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

	MOVQ R15, R8
	LEAQ 64(R15),  R9
	LEAQ 128(R15), R10
	LEAQ 192(R15), R11
	STORE_LANE(Y0, 0)
	STORE_LANE(Y1, 8)
	STORE_LANE(Y2, 16)
	STORE_LANE(Y3, 24)

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
