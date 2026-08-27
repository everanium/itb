//go:build amd64 && !purego && !noitbasm

// AVX2 XMM-batched fused chain-absorb kernel for BLAKE2s-256 with
// 13-byte per-lane data input (the Interlocked Barrier PRF fill shape).
// AVX2 counterpart of blake2s_chain256_13_amd64.s, for hosts with AVX2
// but without AVX-512F. Same 4-lane dword-parallel layout (4 × 32-bit
// lanes fill one XMM). AVX2 exposes only 16 vector registers, so the
// message words live in stack slots (read as memory operands) and
// v[15] is held in a stack slot; the round schedule spills v[12]
// during the two G-functions that touch v[15] so a single XMM (X15, or
// X12 during the excursion) serves as the rotate-synthesis temp.
//
// Rotate synthesis (no VPRORD outside AVX-512):
//
//	ror16 = VPSHUFB ror16 mask       (in-place, .rodata memory operand)
//	ror8  = VPSHUFB ror8 mask        (in-place, .rodata memory operand)
//	ror12 = VPSRLD $12 ; VPSLLD $20 ; VPOR   (one temp)
//	ror7  = VPSRLD $7  ; VPSLLD $25 ; VPOR   (one temp)
//
// One BLAKE2s compression with t=64 (= 32 key + 32 max(data,32)),
// f=^0 (final). Per-lane absorb construction matches hashes.BLAKE2s256
// bit-exactly (buf = b2key[0:32] ++ data ++ zero, seed XOR over
// buf[32:64]).
//
// Register allocation:
//
//	AX  h0 ptr; BX b2key ptr; CX seeds ptr (stride 32); DX dataPtrs;
//	R8..R11 lane data ptrs; R12..R14, DI scratch GPRs; R15 out ptr;
//	X0..X14 v[0..14]; X15 rotate temp / transient v[15] carrier;
//	m[0..15] stack slots 0..255; v[15] slot 256; v[12] spill slot 272.

#include "textflag.h"

#define RORD(x, n, ln, t) \
	VPSRLD n, x, t; \
	VPSLLD ln, x, x; \
	VPOR t, x, x

#define GA(a, b, c, d, mx, my, t) \
	VPADDD b, a, a; \
	VPADDD mx(SP), a, a; \
	VPXOR a, d, d; \
	VPSHUFB b2sRor16<>(SB), d, d; \
	VPADDD d, c, c; \
	VPXOR c, b, b; \
	RORD(b, $12, $20, t); \
	VPADDD b, a, a; \
	VPADDD my(SP), a, a; \
	VPXOR a, d, d; \
	VPSHUFB b2sRor8<>(SB), d, d; \
	VPADDD d, c, c; \
	VPXOR c, b, b; \
	RORD(b, $7, $25, t)

#define M(i)  (i*16)
#define V15   256
#define V12   272

#define ROUND(s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15) \
	GA(X0, X4, X8,  X12, M(s0),  M(s1),  X15); \
	GA(X1, X5, X9,  X13, M(s2),  M(s3),  X15); \
	GA(X2, X6, X10, X14, M(s4),  M(s5),  X15); \
	VMOVDQU X12, V12(SP); \
	VMOVDQU V15(SP), X15; \
	GA(X3, X7, X11, X15, M(s6),  M(s7),  X12); \
	GA(X0, X5, X10, X15, M(s8),  M(s9),  X12); \
	VMOVDQU X15, V15(SP); \
	VMOVDQU V12(SP), X12; \
	GA(X1, X6, X11, X12, M(s10), M(s11), X15); \
	GA(X2, X7, X8,  X13, M(s12), M(s13), X15); \
	GA(X3, X4, X9,  X14, M(s14), M(s15), X15)

#define DXS_LO(data_off, seed_idx, slot) \
	MOVL data_off(R8),  R12; XORL seed_idx*8+0*32+0(CX), R12; MOVL R12, slot+0(SP); \
	MOVL data_off(R9),  R13; XORL seed_idx*8+1*32+0(CX), R13; MOVL R13, slot+4(SP); \
	MOVL data_off(R10), R14; XORL seed_idx*8+2*32+0(CX), R14; MOVL R14, slot+8(SP); \
	MOVL data_off(R11), DI;  XORL seed_idx*8+3*32+0(CX), DI;  MOVL DI,  slot+12(SP)

#define DXS_HI(data_off, seed_idx, slot) \
	MOVL data_off(R8),  R12; XORL seed_idx*8+0*32+4(CX), R12; MOVL R12, slot+0(SP); \
	MOVL data_off(R9),  R13; XORL seed_idx*8+1*32+4(CX), R13; MOVL R13, slot+4(SP); \
	MOVL data_off(R10), R14; XORL seed_idx*8+2*32+4(CX), R14; MOVL R14, slot+8(SP); \
	MOVL data_off(R11), DI;  XORL seed_idx*8+3*32+4(CX), DI;  MOVL DI,  slot+12(SP)

// DBYTE_HI — one data byte (zero-extended) XOR seed_hi (m[11] of 13-byte).
#define DBYTE_HI(data_off, seed_idx, slot) \
	MOVBLZX data_off(R8),  R12; XORL seed_idx*8+0*32+4(CX), R12; MOVL R12, slot+0(SP); \
	MOVBLZX data_off(R9),  R13; XORL seed_idx*8+1*32+4(CX), R13; MOVL R13, slot+4(SP); \
	MOVBLZX data_off(R10), R14; XORL seed_idx*8+2*32+4(CX), R14; MOVL R14, slot+8(SP); \
	MOVBLZX data_off(R11), DI;  XORL seed_idx*8+3*32+4(CX), DI;  MOVL DI,  slot+12(SP)

#define SEED_LO(seed_idx, slot) \
	MOVL seed_idx*8+0*32+0(CX), R12; MOVL R12, slot+0(SP); \
	MOVL seed_idx*8+1*32+0(CX), R13; MOVL R13, slot+4(SP); \
	MOVL seed_idx*8+2*32+0(CX), R14; MOVL R14, slot+8(SP); \
	MOVL seed_idx*8+3*32+0(CX), DI;  MOVL DI,  slot+12(SP)

#define SEED_HI(seed_idx, slot) \
	MOVL seed_idx*8+0*32+4(CX), R12; MOVL R12, slot+0(SP); \
	MOVL seed_idx*8+1*32+4(CX), R13; MOVL R13, slot+4(SP); \
	MOVL seed_idx*8+2*32+4(CX), R14; MOVL R14, slot+8(SP); \
	MOVL seed_idx*8+3*32+4(CX), DI;  MOVL DI,  slot+12(SP)

#define BCST_D(key_off, slot) \
	MOVL key_off(BX), R12; \
	MOVL R12, slot+0(SP); MOVL R12, slot+4(SP); \
	MOVL R12, slot+8(SP); MOVL R12, slot+12(SP)

#define ZERO_SLOT(slot) \
	VPXOR X15, X15, X15; \
	VMOVDQU X15, slot(SP)

#define STORE_LANE(x, off) \
	VPEXTRD $0, x, off(R8); \
	VPEXTRD $1, x, off(R9); \
	VPEXTRD $2, x, off(R10); \
	VPEXTRD $3, x, off(R11)

// func blake2s256ChainAbsorb13x4Avx2Asm(h0 *[8]uint32, b2key *[32]byte,
//     seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint32)
TEXT ·blake2s256ChainAbsorb13x4Avx2Asm(SB), NOSPLIT, $288-40
	MOVQ h0+0(FP),        AX
	MOVQ b2key+8(FP),     BX
	MOVQ seeds+16(FP),    CX
	MOVQ dataPtrs+24(FP), DX
	MOVQ out+32(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	VPBROADCASTD 0(AX),  X0
	VPBROADCASTD 4(AX),  X1
	VPBROADCASTD 8(AX),  X2
	VPBROADCASTD 12(AX), X3
	VPBROADCASTD 16(AX), X4
	VPBROADCASTD 20(AX), X5
	VPBROADCASTD 24(AX), X6
	VPBROADCASTD 28(AX), X7

	VPBROADCASTD ·Blake2sIV+0(SB),  X8
	VPBROADCASTD ·Blake2sIV+4(SB),  X9
	VPBROADCASTD ·Blake2sIV+8(SB),  X10
	VPBROADCASTD ·Blake2sIV+12(SB), X11
	VPBROADCASTD ·Blake2sIV+16(SB), X12
	VPBROADCASTD ·Blake2sIV+20(SB), X13
	VPBROADCASTD ·Blake2sIV+24(SB), X14

	MOVL $64, R12
	VMOVD R12, X15
	VPBROADCASTD X15, X15
	VPXOR X15, X12, X12
	VPCMPEQB X15, X15, X15
	VPXOR X15, X14, X14
	VPBROADCASTD ·Blake2sIV+28(SB), X15
	VMOVDQU X15, V15(SP)

	DXS_LO( 0, 0, M(8))
	DXS_HI( 4, 0, M(9))
	DXS_LO( 8, 1, M(10))
	DBYTE_HI(12, 1, M(11))
	SEED_LO(2, M(12))
	SEED_HI(2, M(13))
	SEED_LO(3, M(14))
	SEED_HI(3, M(15))
	BCST_D(0,  M(0))
	BCST_D(4,  M(1))
	BCST_D(8,  M(2))
	BCST_D(12, M(3))
	BCST_D(16, M(4))
	BCST_D(20, M(5))
	BCST_D(24, M(6))
	BCST_D(28, M(7))

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

	VPBROADCASTD 0(AX),  X15
	VPXOR X8,  X0, X0
	VPXOR X15, X0, X0
	VPBROADCASTD 4(AX),  X15
	VPXOR X9,  X1, X1
	VPXOR X15, X1, X1
	VPBROADCASTD 8(AX),  X15
	VPXOR X10, X2, X2
	VPXOR X15, X2, X2
	VPBROADCASTD 12(AX), X15
	VPXOR X11, X3, X3
	VPXOR X15, X3, X3
	VPBROADCASTD 16(AX), X15
	VPXOR X12, X4, X4
	VPXOR X15, X4, X4
	VPBROADCASTD 20(AX), X15
	VPXOR X13, X5, X5
	VPXOR X15, X5, X5
	VPBROADCASTD 24(AX), X15
	VPXOR X14, X6, X6
	VPXOR X15, X6, X6
	VMOVDQU V15(SP), X15
	VPXOR X15, X7, X7
	VPBROADCASTD 28(AX), X15
	VPXOR X15, X7, X7

	MOVQ R15, R8
	LEAQ 32(R15),  R9
	LEAQ 64(R15),  R10
	LEAQ 96(R15),  R11
	STORE_LANE(X0, 0)
	STORE_LANE(X1, 4)
	STORE_LANE(X2, 8)
	STORE_LANE(X3, 12)
	STORE_LANE(X4, 16)
	STORE_LANE(X5, 20)
	STORE_LANE(X6, 24)
	STORE_LANE(X7, 28)

	VZEROUPPER
	RET

DATA b2sRor16<>+0(SB)/8, $0x0504070601000302
DATA b2sRor16<>+8(SB)/8, $0x0d0c0f0e09080b0a
GLOBL b2sRor16<>(SB), RODATA|NOPTR, $16

DATA b2sRor8<>+0(SB)/8, $0x0407060500030201
DATA b2sRor8<>+8(SB)/8, $0x0c0f0e0d080b0a09
GLOBL b2sRor8<>(SB), RODATA|NOPTR, $16
