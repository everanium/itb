//go:build amd64 && !purego && !noitbasm

// AVX2 XMM-batched fused chain-absorb kernel for BLAKE3-256 with
// 20-byte per-lane data input (the ITB SetNonceBits(128) buf shape).
// AVX2 counterpart of blake3_chain256_20_amd64.s, for hosts with AVX2
// but without AVX-512F. Same 4-lane dword-parallel layout (4 × 32-bit
// lanes fill one XMM). AVX2 exposes only 16 vector registers, so the
// message words live in stack slots and v[15] (flags) is held in a
// stack slot; the round schedule spills v[12] during the two G's that
// touch v[15] so a single XMM (X15, or X12) serves as the rotate temp.
//
// BLAKE3 vs BLAKE2s: the key lives in v[0..7] (not the message buffer),
// v[12]/v[13] = t (0), v[14] = block_len (32), v[15] = flags (0x1B =
// KEYED_HASH | CHUNK_START | CHUNK_END | ROOT), 7 rounds with the
// BLAKE3 message-permutation order, and the final fold is v[k] ⊕ v[k+8]
// with NO key term. Seed XOR covers mixed[0:32] = m[0..7].
//
// Rotate synthesis: ror16/ror8 via VPSHUFB (.rodata masks), ror12/ror7
// via VPSRLD/VPSLLD/VPOR (one temp). One BLAKE3 keyed-hash compression.
// Matches hashes.BLAKE3 bit-exactly.
//
// Register allocation:
//
//	AX  key ptr; CX seeds ptr (stride 32); DX dataPtrs; R8..R11 lane
//	data ptrs; R12..R14, DI scratch GPRs; R15 out ptr; X0..X14 v[0..14];
//	X15 rotate temp / transient v[15] carrier; m[0..15] stack slots
//	0..255; v[15] slot 256; v[12] spill slot 272.

#include "textflag.h"

#define RORD(x, n, ln, t) \
	VPSRLD n, x, t; \
	VPSLLD ln, x, x; \
	VPOR t, x, x

#define GA(a, b, c, d, mx, my, t) \
	VPADDD b, a, a; \
	VPADDD mx(SP), a, a; \
	VPXOR a, d, d; \
	VPSHUFB b3Ror16<>(SB), d, d; \
	VPADDD d, c, c; \
	VPXOR c, b, b; \
	RORD(b, $12, $20, t); \
	VPADDD b, a, a; \
	VPADDD my(SP), a, a; \
	VPXOR a, d, d; \
	VPSHUFB b3Ror8<>(SB), d, d; \
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

#define ZERO_SLOT(slot) \
	VPXOR X15, X15, X15; \
	VMOVDQU X15, slot(SP)

#define STORE_LANE(x, off) \
	VPEXTRD $0, x, off(R8); \
	VPEXTRD $1, x, off(R9); \
	VPEXTRD $2, x, off(R10); \
	VPEXTRD $3, x, off(R11)

// func blake3256ChainAbsorb20x4Avx2Asm(key *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][8]uint32)
TEXT ·blake3256ChainAbsorb20x4Avx2Asm(SB), NOSPLIT, $288-32
	MOVQ key+0(FP),       AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

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

	VPBROADCASTD ·Blake3IV+0(SB),  X8
	VPBROADCASTD ·Blake3IV+4(SB),  X9
	VPBROADCASTD ·Blake3IV+8(SB),  X10
	VPBROADCASTD ·Blake3IV+12(SB), X11
	VPXOR X12, X12, X12
	VPXOR X13, X13, X13
	MOVL $32, R12
	VMOVD R12, X14
	VPBROADCASTD X14, X14
	MOVL $0x1B, R12
	VMOVD R12, X15
	VPBROADCASTD X15, X15
	VMOVDQU X15, V15(SP)

	DXS_LO( 0, 0, M(0))
	DXS_HI( 4, 0, M(1))
	DXS_LO( 8, 1, M(2))
	DXS_HI(12, 1, M(3))
	DXS_LO(16, 2, M(4))
	SEED_HI(2, M(5))
	SEED_LO(3, M(6))
	SEED_HI(3, M(7))
	ZERO_SLOT(M(8))
	ZERO_SLOT(M(9))
	ZERO_SLOT(M(10))
	ZERO_SLOT(M(11))
	ZERO_SLOT(M(12))
	ZERO_SLOT(M(13))
	ZERO_SLOT(M(14))
	ZERO_SLOT(M(15))

	ROUND(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
	ROUND(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8)
	ROUND(3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1)
	ROUND(10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6)
	ROUND(12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4)
	ROUND(9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7)
	ROUND(11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13)

	// Fold: out[k] = v[k] ⊕ v[k+8] (k 0..7). No key term.
	VPXOR X8,  X0, X0
	VPXOR X9,  X1, X1
	VPXOR X10, X2, X2
	VPXOR X11, X3, X3
	VPXOR X12, X4, X4
	VPXOR X13, X5, X5
	VPXOR X14, X6, X6
	VMOVDQU V15(SP), X15
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

DATA b3Ror16<>+0(SB)/8, $0x0504070601000302
DATA b3Ror16<>+8(SB)/8, $0x0d0c0f0e09080b0a
GLOBL b3Ror16<>(SB), RODATA|NOPTR, $16

DATA b3Ror8<>+0(SB)/8, $0x0407060500030201
DATA b3Ror8<>+8(SB)/8, $0x0c0f0e0d080b0a09
GLOBL b3Ror8<>(SB), RODATA|NOPTR, $16
