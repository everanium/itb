//go:build amd64 && !purego && !noitbasm

// AVX2 YMM-batched fused chain-absorb kernel for BLAKE2b-256 with
// 20-byte per-lane data input (the ITB SetNonceBits(128) buf shape —
// default config). This is the AVX2 counterpart of the AVX-512 kernel
// in blake2b_chain256_20_amd64.s, for hosts with AVX2 but without
// AVX-512F (Zen 3, Cascade Lake, AVX2-only cloud VMs). Same 4-lane
// qword-parallel layout: state element v[k] of all 4 lanes packed in
// one YMM. AVX2 exposes only 16 YMM, so the message words live in
// stack slots (read as memory operands) and v[15] is held in a stack
// slot; the round schedule spills v[12] during the two G-functions
// that touch v[15] so a single YMM (Y15, or Y12 during the excursion)
// serves as the ror63 synthesis temp.
//
// Rotate synthesis (no VPRORQ outside AVX-512):
//
//	ror32 = VPSHUFD $0xB1              (in-place dword swap in qword)
//	ror24 = VPSHUFB ror24 mask         (in-place, .rodata memory operand)
//	ror16 = VPSHUFB ror16 mask         (in-place, .rodata memory operand)
//	ror63 = VPSRLQ $63 ; VPADDQ(=<<1) ; VPOR   (one temp register)
//
// The three-way output fold h0[k] ⊕ v[k] ⊕ v[k+8] is two VPXOR plus a
// VPBROADCASTQ (AVX2 has no VPTERNLOGQ / embedded broadcast).
//
// Per-lane absorb construction (matches the public hashes.BLAKE2b256
// closure bit-exactly, identical to the AVX-512 kernel):
//
//	buf[0:32]   = b2key                (shared across all 4 lanes)
//	buf[32:52]  = data[lane]           (per-lane, 20 bytes)
//	buf[52:64]  = zero pad
//	then for i in 0..3:
//	  buf[32+i*8 : 40+i*8] ^= seeds[lane][i]   (LE)
//
// One compression with t=64 (= 32 key + 32 max(data,32)), f=^0 (final).
//
// Register allocation:
//
//	AX        h0 ptr       (Blake2bIV256Param)
//	BX        b2key ptr    (32-byte shared key)
//	CX        seeds ptr    (4 lanes × 4 uint64; per-lane stride 32 bytes)
//	DX        dataPtrs ptr (4 lane pointers)
//	R8..R11   per-lane data ptrs (loaded at entry)
//	R12..R14, DI    scratch GPRs for lane packing
//	R15       out ptr
//	Y0..Y14   state v[0..14]
//	Y15       ror63 temp / transient v[15] carrier during G3+G4
//	m[0..15]  stack slots 0..511; v[15] slot 512; v[12] spill slot 544

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

#define BUILD_DEXT4XS_Q(data_off, seed_idx, slot) \
	MOVL data_off(R8),  R12; XORQ seed_idx*8+0*32(CX), R12; MOVQ R12, slot+0(SP); \
	MOVL data_off(R9),  R13; XORQ seed_idx*8+1*32(CX), R13; MOVQ R13, slot+8(SP); \
	MOVL data_off(R10), R14; XORQ seed_idx*8+2*32(CX), R14; MOVQ R14, slot+16(SP); \
	MOVL data_off(R11), DI;  XORQ seed_idx*8+3*32(CX), DI;  MOVQ DI,  slot+24(SP)

#define BUILD_SEED_Q(seed_idx, slot) \
	MOVQ seed_idx*8+0*32(CX), R12; MOVQ R12, slot+0(SP); \
	MOVQ seed_idx*8+1*32(CX), R13; MOVQ R13, slot+8(SP); \
	MOVQ seed_idx*8+2*32(CX), R14; MOVQ R14, slot+16(SP); \
	MOVQ seed_idx*8+3*32(CX), DI;  MOVQ DI,  slot+24(SP)

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

// func blake2b256ChainAbsorb20x4Avx2Asm(
//     h0       *[8]uint64,        // Blake2bIV256Param
//     b2key    *[32]byte,         // shared 32-byte fixed key
//     seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//     dataPtrs *[4]*byte,         // 4 pointers, each to ≥20 bytes
//     out      *[4][8]uint64)     // output: only out[lane][0:4] meaningful
TEXT ·blake2b256ChainAbsorb20x4Avx2Asm(SB), NOSPLIT, $608-40
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

	// t=64 → v12; f=^0 → v14; v15=IV[7] → slot.
	MOVQ $64, R12
	VMOVQ R12, X15
	VPBROADCASTQ X15, Y15
	VPXOR Y15, Y12, Y12
	VPCMPEQB Y15, Y15, Y15
	VPXOR Y15, Y14, Y14
	VPBROADCASTQ ·Blake2bIV+56(SB), Y15
	VMOVDQU Y15, V15(SP)

	// m[4..7] (per-lane), m[0..3] (key), m[8..15]=0.
	BUILD_DXS_Q(0, 0, M(4))
	BUILD_DXS_Q(8, 1, M(5))
	BUILD_DEXT4XS_Q(16, 2, M(6))
	BUILD_SEED_Q(3, M(7))
	BUILD_BCST_Q(0,  M(0))
	BUILD_BCST_Q(8,  M(1))
	BUILD_BCST_Q(16, M(2))
	BUILD_BCST_Q(24, M(3))
	ZERO_SLOT(M(8))
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

	// out[k] = h0[k]^v[k]^v[k+8], k in 0..3.
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
