//go:build amd64 && !purego && !noitbasm

// AVX2 (no AVX-512) fused dual-compression chain-absorb kernel for
// ChaCha20-256 with 68-byte per-lane data input (the ITB
// SetNonceBits(512) buf shape). AVX2-only fallback. Bit-exact with the
// AVX-512 kernel chaCha20256ChainAbsorb68x4Asm.
//
// Shape (measured winner, ~1.97× over two sequential 4-lane XMM
// compressions on the 11700K): the two ChaCha20 compressions (counter=0
// and counter=1), independent given v_init, run in ONE YMM round body —
// each YMM word holds [4 lanes @ counter0 | 4 lanes @ counter1] (low
// 128 | high 128). State words v14/v15 (only ever the QR 'd' operand)
// live in stack slots freeing Y14/Y15 as the rotate temp; 16/8 rotates
// use VPSHUFB memory masks, 12/7 rotates VPSLLD/VPSRLD/VPOR.
//
//	state[0:8]=uint64(68); state[8:32]=data[0:24]
//	state[0:32] ^= ks_lo(block0);  state[8:32] ^= data[24:48]   r1 + tail1
//	state[0:32] ^= ks_hi(block0);  state[8:28] ^= data[48:68]   r2 + tail2
//	state[0:32] ^= ks_lo(block1)                                r3
//	out[lane] = state[0:32]
//
// Stack: KS(512, YMM word-major, doubles as the v_init save — the
// keystream add is in-place so v_init is dead once consumed) +
// S14(32) + S15(32) = 576.

#include "textflag.h"

DATA rol16d<>+0(SB)/8,  $0x0504070601000302
DATA rol16d<>+8(SB)/8,  $0x0d0c0f0e09080b0a
DATA rol16d<>+16(SB)/8, $0x0504070601000302
DATA rol16d<>+24(SB)/8, $0x0d0c0f0e09080b0a
GLOBL rol16d<>(SB), RODATA|NOPTR, $32
DATA rol8d<>+0(SB)/8,   $0x0605040702010003
DATA rol8d<>+8(SB)/8,   $0x0e0d0c0f0a09080b
DATA rol8d<>+16(SB)/8,  $0x0605040702010003
DATA rol8d<>+24(SB)/8,  $0x0e0d0c0f0a09080b
GLOBL rol8d<>(SB), RODATA|NOPTR, $32

#define YR16(r) VPSHUFB rol16d<>(SB), r, r
#define YR8(r)  VPSHUFB rol8d<>(SB), r, r
#define YQRT(a, b, c, d, t) \
	VPADDD b,a,a; VPXOR a,d,d; YR16(d); \
	VPADDD d,c,c; VPXOR c,b,b; VPSLLD $12,b,t; VPSRLD $20,b,b; VPOR t,b,b; \
	VPADDD b,a,a; VPXOR a,d,d; YR8(d); \
	VPADDD d,c,c; VPXOR c,b,b; VPSLLD $7,b,t;  VPSRLD $25,b,b; VPOR t,b,b

// S14 at 512(SP), S15 at 544(SP).
#define CHACHA_DR_F \
	YQRT(Y0,Y4,Y8,Y12, Y15); \
	YQRT(Y1,Y5,Y9,Y13, Y15); \
	VMOVDQU 512(SP), Y14; YQRT(Y2,Y6,Y10,Y14, Y15); VMOVDQU Y14, 512(SP); \
	VMOVDQU 544(SP), Y15; YQRT(Y3,Y7,Y11,Y15, Y14); VMOVDQU Y15, 544(SP); \
	VMOVDQU 544(SP), Y15; YQRT(Y0,Y5,Y10,Y15, Y14); VMOVDQU Y15, 544(SP); \
	YQRT(Y1,Y6,Y11,Y12, Y15); \
	YQRT(Y2,Y7,Y8,Y13, Y15); \
	VMOVDQU 512(SP), Y14; YQRT(Y3,Y4,Y9,Y14, Y15); VMOVDQU Y14, 512(SP)

#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

// PACK_KEY_DWORD_DUP — key⊕seed dword k packed into low XMM of y_dst,
// then duplicated to the high 128 (same key for counter0 and counter1).
#define PACK_KEY_DWORD_DUP(k, x_dst, y_dst) \
	MOVL k*4(AX), R12; XORL k*4 + 0*32(CX), R12; \
	MOVL k*4(AX), R13; XORL k*4 + 1*32(CX), R13; \
	MOVL k*4(AX), R14; XORL k*4 + 2*32(CX), R14; \
	MOVL k*4(AX), DI;  XORL k*4 + 3*32(CX), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst); \
	VINSERTI128 $1, x_dst, y_dst, y_dst

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

// func chaCha20256ChainAbsorb68x4Avx2Asm(
//     fixedKey *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][4]uint64)
TEXT ·chaCha20256ChainAbsorb68x4Avx2Asm(SB), NOSPLIT, $576-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== fused v_init (both counters) =====
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Y0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Y1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Y2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Y3
	PACK_KEY_DWORD_DUP(0, X4, Y4)
	PACK_KEY_DWORD_DUP(1, X5, Y5)
	PACK_KEY_DWORD_DUP(2, X6, Y6)
	PACK_KEY_DWORD_DUP(3, X7, Y7)
	PACK_KEY_DWORD_DUP(4, X8, Y8)
	PACK_KEY_DWORD_DUP(5, X9, Y9)
	PACK_KEY_DWORD_DUP(6, X10, Y10)
	PACK_KEY_DWORD_DUP(7, X11, Y11)
	// v12 = [counter0=0 | counter1=1]: low 128 = 0, high 128 = 1.
	VPXOR X12, X12, X12
	MOVL $1, R12
	VMOVD R12, X13
	VPBROADCASTD X13, X13
	VINSERTI128 $1, X13, Y12, Y12
	VPXOR Y13, Y13, Y13
	VPXOR Y14, Y14, Y14
	VPXOR Y15, Y15, Y15

	VMOVDQU Y0,  0(SP)
	VMOVDQU Y1,  32(SP)
	VMOVDQU Y2,  64(SP)
	VMOVDQU Y3,  96(SP)
	VMOVDQU Y4,  128(SP)
	VMOVDQU Y5,  160(SP)
	VMOVDQU Y6,  192(SP)
	VMOVDQU Y7,  224(SP)
	VMOVDQU Y8,  256(SP)
	VMOVDQU Y9,  288(SP)
	VMOVDQU Y10, 320(SP)
	VMOVDQU Y11, 352(SP)
	VMOVDQU Y12, 384(SP)
	VMOVDQU Y13, 416(SP)
	VMOVDQU Y14, 448(SP)
	VMOVDQU Y15, 480(SP)
	VMOVDQU Y14, 512(SP)   // S14
	VMOVDQU Y15, 544(SP)   // S15

	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F
	CHACHA_DR_F

	// keystream = state + v_init, stored in-place over the v_init slots.
	VPADDD 0(SP),   Y0,  Y0;  VMOVDQU Y0,  0(SP)
	VPADDD 32(SP),  Y1,  Y1;  VMOVDQU Y1,  32(SP)
	VPADDD 64(SP),  Y2,  Y2;  VMOVDQU Y2,  64(SP)
	VPADDD 96(SP),  Y3,  Y3;  VMOVDQU Y3,  96(SP)
	VPADDD 128(SP), Y4,  Y4;  VMOVDQU Y4,  128(SP)
	VPADDD 160(SP), Y5,  Y5;  VMOVDQU Y5,  160(SP)
	VPADDD 192(SP), Y6,  Y6;  VMOVDQU Y6,  192(SP)
	VPADDD 224(SP), Y7,  Y7;  VMOVDQU Y7,  224(SP)
	VPADDD 256(SP), Y8,  Y8;  VMOVDQU Y8,  256(SP)
	VPADDD 288(SP), Y9,  Y9;  VMOVDQU Y9,  288(SP)
	VPADDD 320(SP), Y10, Y10; VMOVDQU Y10, 320(SP)
	VPADDD 352(SP), Y11, Y11; VMOVDQU Y11, 352(SP)
	VPADDD 384(SP), Y12, Y12; VMOVDQU Y12, 384(SP)
	VPADDD 416(SP), Y13, Y13; VMOVDQU Y13, 416(SP)
	VMOVDQU 512(SP), Y14; VPADDD 448(SP), Y14, Y14; VMOVDQU Y14, 448(SP)
	VMOVDQU 544(SP), Y15; VPADDD 480(SP), Y15, Y15; VMOVDQU Y15, 480(SP)

	VZEROUPPER

	// ===== absorb (4-lane XMM) =====
	// block0 dword w low128 at KS+w*32; block1 dword w at KS+w*32+16.
	MOVL $68, R12
	VMOVD R12, X0
	VPBROADCASTD X0, X0       // as[0] = 68
	VPXOR X1, X1, X1          // as[1] = 0
	PACK_DATA_DWORD( 0, X2)   // as[2] = data[0:4]
	PACK_DATA_DWORD( 4, X3)
	PACK_DATA_DWORD( 8, X4)
	PACK_DATA_DWORD(12, X5)
	PACK_DATA_DWORD(16, X6)
	PACK_DATA_DWORD(20, X7)   // as[7] = data[20:24]

	// Round 1: ks_lo block0 = KS[w*32], w=0..7.
	VPXOR 0(SP),   X0, X0
	VPXOR 32(SP),  X1, X1
	VPXOR 64(SP),  X2, X2
	VPXOR 96(SP),  X3, X3
	VPXOR 128(SP), X4, X4
	VPXOR 160(SP), X5, X5
	VPXOR 192(SP), X6, X6
	VPXOR 224(SP), X7, X7

	// Tail1: state[8:32] ^= data[24:48] → as[2..7] ^= data24-48 (6 dw).
	PACK_DATA_DWORD(24, X8);  VPXOR X8,  X2, X2
	PACK_DATA_DWORD(28, X9);  VPXOR X9,  X3, X3
	PACK_DATA_DWORD(32, X10); VPXOR X10, X4, X4
	PACK_DATA_DWORD(36, X11); VPXOR X11, X5, X5
	PACK_DATA_DWORD(40, X12); VPXOR X12, X6, X6
	PACK_DATA_DWORD(44, X13); VPXOR X13, X7, X7

	// Round 2: ks_hi block0 = KS[(8+w)*32], w=0..7.
	VPXOR 256(SP), X0, X0
	VPXOR 288(SP), X1, X1
	VPXOR 320(SP), X2, X2
	VPXOR 352(SP), X3, X3
	VPXOR 384(SP), X4, X4
	VPXOR 416(SP), X5, X5
	VPXOR 448(SP), X6, X6
	VPXOR 480(SP), X7, X7

	// Tail2: state[8:28] ^= data[48:68] → as[2..6] ^= data48-68 (5 dw).
	PACK_DATA_DWORD(48, X8);  VPXOR X8,  X2, X2
	PACK_DATA_DWORD(52, X9);  VPXOR X9,  X3, X3
	PACK_DATA_DWORD(56, X10); VPXOR X10, X4, X4
	PACK_DATA_DWORD(60, X11); VPXOR X11, X5, X5
	PACK_DATA_DWORD(64, X12); VPXOR X12, X6, X6

	// Round 3: ks_lo block1 = KS[w*32+16], w=0..7.
	VPXOR 16(SP),  X0, X0
	VPXOR 48(SP),  X1, X1
	VPXOR 80(SP),  X2, X2
	VPXOR 112(SP), X3, X3
	VPXOR 144(SP), X4, X4
	VPXOR 176(SP), X5, X5
	VPXOR 208(SP), X6, X6
	VPXOR 240(SP), X7, X7

	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11
	STORE_LANE_DW(X0, 0)
	STORE_LANE_DW(X1, 4)
	STORE_LANE_DW(X2, 8)
	STORE_LANE_DW(X3, 12)
	STORE_LANE_DW(X4, 16)
	STORE_LANE_DW(X5, 20)
	STORE_LANE_DW(X6, 24)
	STORE_LANE_DW(X7, 28)

	RET
