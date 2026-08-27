//go:build amd64 && !purego && !noitbasm

// AVX2 (no AVX-512) 4-lane XMM chain-absorb kernel for ChaCha20-256
// with 20-byte per-lane data input (the ITB SetNonceBits(128) buf shape
// — default config). AVX2-only fallback for hosts lacking the AVX-512
// tier (AVX2-only Intel pre-Skylake-X / Skylake-client, AMD Zen 1–3,
// every AVX2-no-AVX-512 cloud VM). Bit-exact with the AVX-512 kernel
// chaCha20256ChainAbsorb20x4Asm and the Go single closure.
//
// Shape (measured winner, ~2.09× over single-hash-4×4-diagonal on the
// 11700K): 4 pixel lanes packed per XMM (word-major), 16 state words.
// AVX2 has only 16 vector registers, so state words v14/v15 — which are
// only ever the ChaCha quarter-round 'd' operand, never a source — live
// in stack slots (S14/S15), freeing X14/X15 as the rotate temp for the
// non-byte-aligned 12/7 rotates. The 16/8 rotates use VPSHUFB
// memory-operand masks (zero temp). v_init is saved to a 256-byte stack
// region for the final `keystream = state + v_init` add.
//
// Per-lane absorb construction (matches hashes.ChaCha20 bit-exactly):
//	key = fixedKey; key[i*8:] ^= seeds[lane][i] (LE u64, i in 0..3)
//	state[0:8]=uint64(20); state[8:28]=data[0:20]; state[28:32]=0
//	state[0:32] ^= ks_lo (dwords 0..7 of the counter=0 block)
//	out[lane] = state[0:32]
//
// Register allocation:
//	AX  fixedKey ptr   CX  seeds ptr   DX  dataPtrs ptr   R15  out ptr
//	R8..R11  per-lane data ptrs   R12..R14, DI  scratch GPRs
//	X0..X13  state v[0..13]        X14,X15  rotate temp / v14,v15 scratch
// Stack: VINIT(256) + S14(16) + S15(16) = 288.

#include "textflag.h"

DATA rol16<>+0(SB)/8, $0x0504070601000302
DATA rol16<>+8(SB)/8, $0x0d0c0f0e09080b0a
GLOBL rol16<>(SB), RODATA|NOPTR, $16
DATA rol8<>+0(SB)/8,  $0x0605040702010003
DATA rol8<>+8(SB)/8,  $0x0e0d0c0f0a09080b
GLOBL rol8<>(SB), RODATA|NOPTR, $16

#define R16(r) VPSHUFB rol16<>(SB), r, r
#define R8x(r) VPSHUFB rol8<>(SB), r, r
// QRT — ChaCha quarter round on (a,b,c,d), rotate temp t.
#define QRT(a, b, c, d, t) \
	VPADDD b,a,a; VPXOR a,d,d; R16(d); \
	VPADDD d,c,c; VPXOR c,b,b; VPSLLD $12,b,t; VPSRLD $20,b,b; VPOR t,b,b; \
	VPADDD b,a,a; VPXOR a,d,d; R8x(d); \
	VPADDD d,c,c; VPXOR c,b,b; VPSLLD $7,b,t;  VPSRLD $25,b,b; VPOR t,b,b

// CHACHA_DR_A — one 4-lane doubleround with v14/v15 held in S14/S15.
// S14 at 256(SP), S15 at 272(SP).
#define CHACHA_DR_A \
	QRT(X0,X4,X8,X12, X15); \
	QRT(X1,X5,X9,X13, X15); \
	VMOVDQU 256(SP), X14; QRT(X2,X6,X10,X14, X15); VMOVDQU X14, 256(SP); \
	VMOVDQU 272(SP), X15; QRT(X3,X7,X11,X15, X14); VMOVDQU X15, 272(SP); \
	VMOVDQU 272(SP), X15; QRT(X0,X5,X10,X15, X14); VMOVDQU X15, 272(SP); \
	QRT(X1,X6,X11,X12, X15); \
	QRT(X2,X7,X8,X13, X15); \
	VMOVDQU 256(SP), X14; QRT(X3,X4,X9,X14, X15); VMOVDQU X14, 256(SP)

#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

#define PACK_KEY_DWORD(k, x_dst) \
	MOVL k*4(AX), R12; XORL k*4 + 0*32(CX), R12; \
	MOVL k*4(AX), R13; XORL k*4 + 1*32(CX), R13; \
	MOVL k*4(AX), R14; XORL k*4 + 2*32(CX), R14; \
	MOVL k*4(AX), DI;  XORL k*4 + 3*32(CX), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst)

#define PACK_DATA_DWORD(off, x_dst) \
	MOVL off(R8),  R12; \
	MOVL off(R9),  R13; \
	MOVL off(R10), R14; \
	MOVL off(R11), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst)

#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

// func chaCha20256ChainAbsorb20x4Avx2Asm(
//     fixedKey *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][4]uint64)
TEXT ·chaCha20256ChainAbsorb20x4Avx2Asm(SB), NOSPLIT, $288-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== v_init =====
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  X0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  X1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  X2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), X3
	PACK_KEY_DWORD(0, X4)
	PACK_KEY_DWORD(1, X5)
	PACK_KEY_DWORD(2, X6)
	PACK_KEY_DWORD(3, X7)
	PACK_KEY_DWORD(4, X8)
	PACK_KEY_DWORD(5, X9)
	PACK_KEY_DWORD(6, X10)
	PACK_KEY_DWORD(7, X11)
	VPXOR X12, X12, X12
	VPXOR X13, X13, X13
	VPXOR X14, X14, X14
	VPXOR X15, X15, X15

	// Save v_init[0..7] (ks_lo add operands) + stage v14/v15.
	VMOVDQU X0,  0(SP)
	VMOVDQU X1,  16(SP)
	VMOVDQU X2,  32(SP)
	VMOVDQU X3,  48(SP)
	VMOVDQU X4,  64(SP)
	VMOVDQU X5,  80(SP)
	VMOVDQU X6,  96(SP)
	VMOVDQU X7,  112(SP)
	VMOVDQU X14, 256(SP)
	VMOVDQU X15, 272(SP)

	// ===== 10 doublerounds =====
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A
	CHACHA_DR_A

	// ===== ks_lo = state[0:8] + v_init[0:8] =====
	VPADDD 0(SP),   X0, X0
	VPADDD 16(SP),  X1, X1
	VPADDD 32(SP),  X2, X2
	VPADDD 48(SP),  X3, X3
	VPADDD 64(SP),  X4, X4
	VPADDD 80(SP),  X5, X5
	VPADDD 96(SP),  X6, X6
	VPADDD 112(SP), X7, X7

	// ===== absorb_state (X8..X15), XOR ks_lo =====
	MOVL $20, R12
	VMOVD R12, X8
	VPBROADCASTD X8, X8       // as[0] = 20 (broadcast)
	VPXOR X9, X9, X9          // as[1] = 0
	PACK_DATA_DWORD( 0, X10)  // as[2] = data[0:4]
	PACK_DATA_DWORD( 4, X11)  // as[3] = data[4:8]
	PACK_DATA_DWORD( 8, X12)  // as[4] = data[8:12]
	PACK_DATA_DWORD(12, X13)  // as[5] = data[12:16]
	PACK_DATA_DWORD(16, X14)  // as[6] = data[16:20]
	VPXOR X15, X15, X15       // as[7] = 0

	VPXOR X0, X8,  X8
	VPXOR X1, X9,  X9
	VPXOR X2, X10, X10
	VPXOR X3, X11, X11
	VPXOR X4, X12, X12
	VPXOR X5, X13, X13
	VPXOR X6, X14, X14
	VPXOR X7, X15, X15

	// ===== writeback =====
	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11
	STORE_LANE_DW(X8,  0)
	STORE_LANE_DW(X9,  4)
	STORE_LANE_DW(X10, 8)
	STORE_LANE_DW(X11, 12)
	STORE_LANE_DW(X12, 16)
	STORE_LANE_DW(X13, 20)
	STORE_LANE_DW(X14, 24)
	STORE_LANE_DW(X15, 28)

	VZEROUPPER
	RET
