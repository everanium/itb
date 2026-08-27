//go:build amd64 && !purego && !noitbasm

// AVX2 (no AVX-512) 4-lane YMM chain-absorb kernel for SipHash-2-4-128
// with 13-byte per-lane data input. AVX2-only fallback for hosts lacking the AVX-512
// tier. Bit-exact with the AVX-512 kernel sipHash24Chain128Absorb20x4Asm
// and the Go single closure.
//
// SipHash's 4-word state fits AVX2's 16-register file comfortably, so
// the layout is identical to the AVX-512 tier: v0..v3 in Y0..Y3, one
// YMM per state word, lane = qword index (qwords 0..3). The SipRound
// immediate rotates are synthesized: 32 via VPSHUFD $0xB1 (swap dwords
// within each qword), 16 via VPSHUFB memory mask, and 13/21/17 via
// VPSLLQ/VPSRLQ/VPOR (temp Y5). Seed de-interleave uses a GPR pack (the
// AVX-512 variable VPERMQ has no AVX2 form).
//
//	K0,K1 = seeds[lane][0], seeds[lane][1]
//	v0=K0^0x736f6d6570736575  v1=K1^0x646f72616e646f83
//	v2=K0^0x6c7967656e657261  v3=K1^0x7465646279746573
//	compress data[0:8]; compress data[8:16];
//	final block m = uint64(data[16:20]) | (20<<56)
//	finalize: v2^=0xee; ×4 SipRound; out0 = v0^v1^v2^v3
//	          v1^=0xdd; ×4 SipRound; out1 = v0^v1^v2^v3
//
// Register allocation:
//	BX seeds ptr  CX dataPtrs ptr  DX out ptr  R8..R11 data ptrs  R12 scratch
//	Y0..Y3 state  Y4 message  Y5 rotate temp  Y6/Y7 seeds(init)/finalize outputs

#include "textflag.h"

DATA rol16qa<>+0(SB)/8,  $0x0504030201000706
DATA rol16qa<>+8(SB)/8,  $0x0d0c0b0a09080f0e
DATA rol16qa<>+16(SB)/8, $0x0504030201000706
DATA rol16qa<>+24(SB)/8, $0x0d0c0b0a09080f0e
GLOBL rol16qa<>(SB), RODATA|NOPTR, $32

#define ROLQ32(r) VPSHUFD $0xB1, r, r
#define ROLQ16(r) VPSHUFB rol16qa<>(SB), r, r
#define ROLQ13(r) VPSLLQ $13, r, Y5; VPSRLQ $51, r, r; VPOR Y5, r, r
#define ROLQ21(r) VPSLLQ $21, r, Y5; VPSRLQ $43, r, r; VPOR Y5, r, r
#define ROLQ17(r) VPSLLQ $17, r, Y5; VPSRLQ $47, r, r; VPOR Y5, r, r

#define SIP_ROUND \
	VPADDQ Y1, Y0, Y0; ROLQ13(Y1); VPXOR Y0, Y1, Y1; ROLQ32(Y0); \
	VPADDQ Y3, Y2, Y2; ROLQ16(Y3); VPXOR Y2, Y3, Y3;             \
	VPADDQ Y3, Y0, Y0; ROLQ21(Y3); VPXOR Y0, Y3, Y3;             \
	VPADDQ Y1, Y2, Y2; ROLQ17(Y1); VPXOR Y2, Y1, Y1; ROLQ32(Y2)

// PACK_M_QWORD — LE u64 from each lane data ptr at offset `off` into
// Y4 qwords 0..3.
#define PACK_M_QWORD(off) \
	MOVQ off(R8),  R12; VMOVQ R12, X4; \
	MOVQ off(R9),  R12; VPINSRQ $1, R12, X4, X4; \
	MOVQ off(R10), R12; VMOVQ R12, X6; \
	MOVQ off(R11), R12; VPINSRQ $1, R12, X6, X6; \
	VINSERTI128 $1, X6, Y4, Y4

#define SIP_ABSORB \
	VPXOR Y4, Y3, Y3; SIP_ROUND; SIP_ROUND; VPXOR Y4, Y0, Y0

// func sipHash24Chain128Absorb20x4Avx2Asm(
//     seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
TEXT ·sipHash24Chain128Absorb13x4Avx2Asm(SB), NOSPLIT, $0-24
	MOVQ seeds+0(FP),    BX
	MOVQ dataPtrs+8(FP), CX
	MOVQ out+16(FP),     DX

	MOVQ 0(CX),  R8
	MOVQ 8(CX),  R9
	MOVQ 16(CX), R10
	MOVQ 24(CX), R11

	// ===== seeds: Y6 = K0 lanes 0..3, Y7 = K1 lanes 0..3 =====
	MOVQ 0(BX),  R12; VMOVQ R12, X6
	MOVQ 16(BX), R12; VPINSRQ $1, R12, X6, X6
	MOVQ 32(BX), R12; VMOVQ R12, X8
	MOVQ 48(BX), R12; VPINSRQ $1, R12, X8, X8
	VINSERTI128 $1, X8, Y6, Y6
	MOVQ 8(BX),  R12; VMOVQ R12, X7
	MOVQ 24(BX), R12; VPINSRQ $1, R12, X7, X7
	MOVQ 40(BX), R12; VMOVQ R12, X8
	MOVQ 56(BX), R12; VPINSRQ $1, R12, X8, X8
	VINSERTI128 $1, X8, Y7, Y7

	// ===== state init =====
	MOVQ $0x736f6d6570736575, R12; VMOVQ R12, X0; VPBROADCASTQ X0, Y0; VPXOR Y6, Y0, Y0
	MOVQ $0x646f72616e646f83, R12; VMOVQ R12, X1; VPBROADCASTQ X1, Y1; VPXOR Y7, Y1, Y1
	MOVQ $0x6c7967656e657261, R12; VMOVQ R12, X2; VPBROADCASTQ X2, Y2; VPXOR Y6, Y2, Y2
	MOVQ $0x7465646279746573, R12; VMOVQ R12, X3; VPBROADCASTQ X3, Y3; VPXOR Y7, Y3, Y3

	PACK_M_QWORD(0)
	SIP_ABSORB

	// ===== final padded block: data[8:13] (5 bytes) | (13<<56) =====
	MOVL 8(R8),  R12; MOVBLZX 12(R8),  R13; SHLQ $32, R13; ORQ R13, R12; VMOVQ R12, X4
	MOVL 8(R9),  R12; MOVBLZX 12(R9),  R13; SHLQ $32, R13; ORQ R13, R12; VPINSRQ $1, R12, X4, X4
	MOVL 8(R10), R12; MOVBLZX 12(R10), R13; SHLQ $32, R13; ORQ R13, R12; VMOVQ R12, X6
	MOVL 8(R11), R12; MOVBLZX 12(R11), R13; SHLQ $32, R13; ORQ R13, R12; VPINSRQ $1, R12, X6, X6
	VINSERTI128 $1, X6, Y4, Y4
	MOVQ $0x0d00000000000000, R12; VMOVQ R12, X6; VPBROADCASTQ X6, Y6; VPXOR Y6, Y4, Y4
	SIP_ABSORB

	// ===== finalization =====
	MOVQ $0xee, R12; VMOVQ R12, X6; VPBROADCASTQ X6, Y6; VPXOR Y6, Y2, Y2
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VPXOR Y1, Y0, Y6; VPXOR Y3, Y6, Y6; VPXOR Y2, Y6, Y6   // out0

	MOVQ $0xdd, R12; VMOVQ R12, X7; VPBROADCASTQ X7, Y7; VPXOR Y7, Y1, Y1
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	SIP_ROUND
	VPXOR Y1, Y0, Y7; VPXOR Y3, Y7, Y7; VPXOR Y2, Y7, Y7   // out1

	// ===== writeback: out[lane] = [out0, out1], lane k at k*16 =====
	VPEXTRQ $0, X6, 0(DX)
	VPEXTRQ $0, X7, 8(DX)
	VPEXTRQ $1, X6, 16(DX)
	VPEXTRQ $1, X7, 24(DX)
	VEXTRACTI128 $1, Y6, X6
	VEXTRACTI128 $1, Y7, X7
	VPEXTRQ $0, X6, 32(DX)
	VPEXTRQ $0, X7, 40(DX)
	VPEXTRQ $1, X6, 48(DX)
	VPEXTRQ $1, X7, 56(DX)

	VZEROUPPER
	RET
