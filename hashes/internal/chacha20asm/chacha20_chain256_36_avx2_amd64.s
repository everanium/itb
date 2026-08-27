//go:build amd64 && !purego && !noitbasm

// AVX2 (no AVX-512) 4-lane XMM chain-absorb kernel for ChaCha20-256
// with 36-byte per-lane data input (the ITB SetNonceBits(256) buf
// shape). One ChaCha20 compression (counter=0); both keystream halves
// consumed across two absorb rounds. AVX2-only fallback. Bit-exact with
// the AVX-512 kernel chaCha20256ChainAbsorb36x4Asm.
//
//	state[0:8]=uint64(36); state[8:32]=data[0:24]
//	state[0:32] ^= ks_lo (dwords 0..7)             round 1
//	state[8:20] ^= data[24:36] (12-byte tail)
//	state[0:32] ^= ks_hi (dwords 8..15)            round 2
//	out[lane] = state[0:32]
//
// The full 16-dword keystream is staged to a 256-byte KS stack region
// after the final `state + v_init` add; both absorb rounds then read
// their half from KS via memory-operand VPXOR.
//
// Stack: VINIT(256) + S14(16) + S15(16) + KS(256) = 544.

#include "textflag.h"

DATA rol16c<>+0(SB)/8, $0x0504070601000302
DATA rol16c<>+8(SB)/8, $0x0d0c0f0e09080b0a
GLOBL rol16c<>(SB), RODATA|NOPTR, $16
DATA rol8c<>+0(SB)/8,  $0x0605040702010003
DATA rol8c<>+8(SB)/8,  $0x0e0d0c0f0a09080b
GLOBL rol8c<>(SB), RODATA|NOPTR, $16

#define R16(r) VPSHUFB rol16c<>(SB), r, r
#define R8x(r) VPSHUFB rol8c<>(SB), r, r
#define QRT(a, b, c, d, t) \
	VPADDD b,a,a; VPXOR a,d,d; R16(d); \
	VPADDD d,c,c; VPXOR c,b,b; VPSLLD $12,b,t; VPSRLD $20,b,b; VPOR t,b,b; \
	VPADDD b,a,a; VPXOR a,d,d; R8x(d); \
	VPADDD d,c,c; VPXOR c,b,b; VPSLLD $7,b,t;  VPSRLD $25,b,b; VPOR t,b,b

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

// func chaCha20256ChainAbsorb36x4Avx2Asm(
//     fixedKey *[32]byte, seeds *[4][4]uint64,
//     dataPtrs *[4]*byte, out *[4][4]uint64)
TEXT ·chaCha20256ChainAbsorb36x4Avx2Asm(SB), NOSPLIT, $544-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

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

	// Save all 16 v_init words (both keystream halves are needed).
	VMOVDQU X0,  0(SP)
	VMOVDQU X1,  16(SP)
	VMOVDQU X2,  32(SP)
	VMOVDQU X3,  48(SP)
	VMOVDQU X4,  64(SP)
	VMOVDQU X5,  80(SP)
	VMOVDQU X6,  96(SP)
	VMOVDQU X7,  112(SP)
	VMOVDQU X8,  128(SP)
	VMOVDQU X9,  144(SP)
	VMOVDQU X10, 160(SP)
	VMOVDQU X11, 176(SP)
	VMOVDQU X12, 192(SP)
	VMOVDQU X13, 208(SP)
	VMOVDQU X14, 224(SP)
	VMOVDQU X15, 240(SP)
	VMOVDQU X14, 256(SP)   // S14 (mutable v14)
	VMOVDQU X15, 272(SP)   // S15 (mutable v15)

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

	// keystream = state + v_init → KS(288)
	VPADDD 0(SP),   X0,  X0;  VMOVDQU X0,  288(SP)
	VPADDD 16(SP),  X1,  X1;  VMOVDQU X1,  304(SP)
	VPADDD 32(SP),  X2,  X2;  VMOVDQU X2,  320(SP)
	VPADDD 48(SP),  X3,  X3;  VMOVDQU X3,  336(SP)
	VPADDD 64(SP),  X4,  X4;  VMOVDQU X4,  352(SP)
	VPADDD 80(SP),  X5,  X5;  VMOVDQU X5,  368(SP)
	VPADDD 96(SP),  X6,  X6;  VMOVDQU X6,  384(SP)
	VPADDD 112(SP), X7,  X7;  VMOVDQU X7,  400(SP)
	VPADDD 128(SP), X8,  X8;  VMOVDQU X8,  416(SP)
	VPADDD 144(SP), X9,  X9;  VMOVDQU X9,  432(SP)
	VPADDD 160(SP), X10, X10; VMOVDQU X10, 448(SP)
	VPADDD 176(SP), X11, X11; VMOVDQU X11, 464(SP)
	VPADDD 192(SP), X12, X12; VMOVDQU X12, 480(SP)
	VPADDD 208(SP), X13, X13; VMOVDQU X13, 496(SP)
	VMOVDQU 256(SP), X14; VPADDD 224(SP), X14, X14; VMOVDQU X14, 512(SP)
	VMOVDQU 272(SP), X15; VPADDD 240(SP), X15, X15; VMOVDQU X15, 528(SP)

	// ===== absorb_state (X0..X7) =====
	MOVL $36, R12
	VMOVD R12, X0
	VPBROADCASTD X0, X0       // as[0] = 36
	VPXOR X1, X1, X1          // as[1] = 0
	PACK_DATA_DWORD( 0, X2)   // as[2] = data[0:4]
	PACK_DATA_DWORD( 4, X3)   // as[3] = data[4:8]
	PACK_DATA_DWORD( 8, X4)   // as[4] = data[8:12]
	PACK_DATA_DWORD(12, X5)   // as[5] = data[12:16]
	PACK_DATA_DWORD(16, X6)   // as[6] = data[16:20]
	PACK_DATA_DWORD(20, X7)   // as[7] = data[20:24]

	// Round 1: XOR ks_lo (KS dwords 0..7).
	VPXOR 288(SP), X0, X0
	VPXOR 304(SP), X1, X1
	VPXOR 320(SP), X2, X2
	VPXOR 336(SP), X3, X3
	VPXOR 352(SP), X4, X4
	VPXOR 368(SP), X5, X5
	VPXOR 384(SP), X6, X6
	VPXOR 400(SP), X7, X7

	// Tail: state[8:20] ^= data[24:36] → as[2..4] ^= data24-36.
	PACK_DATA_DWORD(24, X8)
	PACK_DATA_DWORD(28, X9)
	PACK_DATA_DWORD(32, X10)
	VPXOR X8,  X2, X2
	VPXOR X9,  X3, X3
	VPXOR X10, X4, X4

	// Round 2: XOR ks_hi (KS dwords 8..15).
	VPXOR 416(SP), X0, X0
	VPXOR 432(SP), X1, X1
	VPXOR 448(SP), X2, X2
	VPXOR 464(SP), X3, X3
	VPXOR 480(SP), X4, X4
	VPXOR 496(SP), X5, X5
	VPXOR 512(SP), X6, X6
	VPXOR 528(SP), X7, X7

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

	VZEROUPPER
	RET
