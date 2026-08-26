//go:build amd64 && !purego && !noitbasm

// YMM-batched fused dual-compression chain-absorb kernel for
// ChaCha20-256 with 68-byte per-lane data input (the ITB
// SetNonceBits(512) buf shape). The two ChaCha20 compressions
// (counter=0 and counter=1) are independent given v_init, so both run
// in ONE 8-dword YMM round body:
//
//	Y0..Y15 state; dwords 0..3 = 4 pixel lanes at counter=0,
//	               dwords 4..7 = the same 4 pixel lanes at counter=1.
//
// This halves the round-body op count versus running two sequential
// 4-dword compressions, and the narrower (256-bit) ops issue on three
// vector ALU ports (p0/p1/p5) on Ice/Rocket Lake client cores versus
// two ports (p0+p5) for 512-bit ops.
//
// Per-lane absorb construction (matches the public hashes.ChaCha20
// closure bit-exactly):
//
//	state[0:8]  = uint64(68) (LE)
//	state[8:32] = data[lane][0:24]
//	XKS call 1: state[i] ^= ks_lo_dword[i] (block 0)  for i in 0..7
//	state[8:32] ^= data[lane][24:48]            (6 dwords absorbXOR)
//	XKS call 2: state[i] ^= ks_hi_dword[i] (block 0)  for i in 0..7
//	state[8:28] ^= data[lane][48:68]            (5 dwords absorbXOR)
//	XKS call 3: state[i] ^= ks_lo_dword[i] (block 1)  for i in 0..7
//	output:    state[0:32] (4 × LE uint64)
//
// Register allocation:
//
//	AX        fixedKey ptr (32-byte shared key)
//	CX        seeds ptr    (4 lanes × 4 uint64; per-lane stride 32 bytes)
//	DX        dataPtrs ptr (4 lane pointers)
//	R8..R11   per-lane data ptrs (loaded at entry)
//	R12..R14, DI    scratch GPRs for lane packing
//	R15       out ptr (saved through the round body, used at writeback)
//	Y0..Y15   dual-counter ChaCha20 state v[0..15] across 20 rounds
//	          (low 128 bits = counter 0, high 128 bits = counter 1)
//	Y16       dual-counter v[12] v_init save; Y17 broadcast scratch
//	Y24..Y31  key v_init save (used at the keystream `+ v_init` add)
//	X16..X23  absorb_state after the round body; X24..X31 receive the
//	          block-1 ks_lo extracted from the high halves of Y0..Y7

#include "textflag.h"

#define CHACHA_QR(a, b, c, d) \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $16, d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $12, b, b; \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $8,  d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $7,  b, b

#define CHACHA_DR \
	CHACHA_QR(Y0, Y4, Y8,  Y12); \
	CHACHA_QR(Y1, Y5, Y9,  Y13); \
	CHACHA_QR(Y2, Y6, Y10, Y14); \
	CHACHA_QR(Y3, Y7, Y11, Y15); \
	CHACHA_QR(Y0, Y5, Y10, Y15); \
	CHACHA_QR(Y1, Y6, Y11, Y12); \
	CHACHA_QR(Y2, Y7, Y8,  Y13); \
	CHACHA_QR(Y3, Y4, Y9,  Y14)

#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

#define PACK_KEY_DWORD(k, x_dst) \
	MOVL k*4(AX),         R12; XORL k*4 + 0*32(CX), R12; \
	MOVL k*4(AX),         R13; XORL k*4 + 1*32(CX), R13; \
	MOVL k*4(AX),         R14; XORL k*4 + 2*32(CX), R14; \
	MOVL k*4(AX),         DI;  XORL k*4 + 3*32(CX), DI;  \
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

// func chaCha20256ChainAbsorb68x4Asm(
//     fixedKey *[32]byte,         // shared 32-byte fixed key
//     seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//     dataPtrs *[4]*byte,         // 4 pointers, each to ≥68 bytes
//     out      *[4][4]uint64)     // output: 32 bytes per lane
TEXT ·chaCha20256ChainAbsorb68x4Asm(SB), NOSPLIT, $0-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== State init (both compressions at once) =====
	// v[0..3] = sigma, identical in both halves.
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Y0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Y1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Y2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Y3

	// v[4..11] = per-lane key, packed into low 128 then duplicated
	// into the high 128 (both compressions share the key).
	PACK_KEY_DWORD(0, X4)
	PACK_KEY_DWORD(1, X5)
	PACK_KEY_DWORD(2, X6)
	PACK_KEY_DWORD(3, X7)
	PACK_KEY_DWORD(4, X8)
	PACK_KEY_DWORD(5, X9)
	PACK_KEY_DWORD(6, X10)
	PACK_KEY_DWORD(7, X11)
	VINSERTI32X4 $1, X4,  Y4,  Y4
	VINSERTI32X4 $1, X5,  Y5,  Y5
	VINSERTI32X4 $1, X6,  Y6,  Y6
	VINSERTI32X4 $1, X7,  Y7,  Y7
	VINSERTI32X4 $1, X8,  Y8,  Y8
	VINSERTI32X4 $1, X9,  Y9,  Y9
	VINSERTI32X4 $1, X10, Y10, Y10
	VINSERTI32X4 $1, X11, Y11, Y11

	// v[12] = counter: 0 in the low half, 1 in the high half.
	MOVL $1, R12
	VPBROADCASTD R12, X17       // X17 = [1,1,1,1] (scratch)
	VPXORD Y12, Y12, Y12
	VINSERTI32X4 $1, X17, Y12, Y12   // Y12 = [0,0,0,0, 1,1,1,1]

	// v[13..15] = 0 (zero nonce).
	VPXORD Y13, Y13, Y13
	VPXORD Y14, Y14, Y14
	VPXORD Y15, Y15, Y15

	// Save v_init pieces needed at the keystream add: key to
	// Y24..Y31, dual-counter v12 to Y16. Sigma is re-broadcast.
	VMOVDQA64 Y4,  Y24
	VMOVDQA64 Y5,  Y25
	VMOVDQA64 Y6,  Y26
	VMOVDQA64 Y7,  Y27
	VMOVDQA64 Y8,  Y28
	VMOVDQA64 Y9,  Y29
	VMOVDQA64 Y10, Y30
	VMOVDQA64 Y11, Y31
	VMOVDQA64 Y12, Y16

	// ===== 10 doublerounds = 20 rounds, both compressions =====
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR
	CHACHA_DR

	// ===== keystream = state + v_init =====
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Y17; VPADDD Y17, Y0, Y0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Y17; VPADDD Y17, Y1, Y1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Y17; VPADDD Y17, Y2, Y2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Y17; VPADDD Y17, Y3, Y3
	VPADDD Y24, Y4,  Y4
	VPADDD Y25, Y5,  Y5
	VPADDD Y26, Y6,  Y6
	VPADDD Y27, Y7,  Y7
	VPADDD Y28, Y8,  Y8
	VPADDD Y29, Y9,  Y9
	VPADDD Y30, Y10, Y10
	VPADDD Y31, Y11, Y11
	VPADDD Y16, Y12, Y12
	// v_init[13..15] = 0 — adds are no-ops.

	// Low halves of Y0..Y7  = block 0 ks_lo.
	// Low halves of Y8..Y15 = block 0 ks_hi.
	// High halves of Y0..Y7 = block 1 ks_lo → extract to X24..X31
	// before X0..X7 get reused as packing scratch.
	VEXTRACTI32X4 $1, Y0, X24
	VEXTRACTI32X4 $1, Y1, X25
	VEXTRACTI32X4 $1, Y2, X26
	VEXTRACTI32X4 $1, Y3, X27
	VEXTRACTI32X4 $1, Y4, X28
	VEXTRACTI32X4 $1, Y5, X29
	VEXTRACTI32X4 $1, Y6, X30
	VEXTRACTI32X4 $1, Y7, X31

	// ===== Build absorb_state into X16..X23 =====
	MOVL $68, R12
	VPBROADCASTD R12, X16
	VPXORD X17, X17, X17
	PACK_DATA_DWORD( 0, X18)
	PACK_DATA_DWORD( 4, X19)
	PACK_DATA_DWORD( 8, X20)
	PACK_DATA_DWORD(12, X21)
	PACK_DATA_DWORD(16, X22)
	PACK_DATA_DWORD(20, X23)

	// XKS call 1: absorb_state ^= ks_lo of block 0.
	VPXORD X0, X16, X16
	VPXORD X1, X17, X17
	VPXORD X2, X18, X18
	VPXORD X3, X19, X19
	VPXORD X4, X20, X20
	VPXORD X5, X21, X21
	VPXORD X6, X22, X22
	VPXORD X7, X23, X23

	// absorbXOR: state[8:32] ^= data[24:48] (6 dwords). X0..X5 dead.
	PACK_DATA_DWORD(24, X0); VPXORD X0, X18, X18
	PACK_DATA_DWORD(28, X1); VPXORD X1, X19, X19
	PACK_DATA_DWORD(32, X2); VPXORD X2, X20, X20
	PACK_DATA_DWORD(36, X3); VPXORD X3, X21, X21
	PACK_DATA_DWORD(40, X4); VPXORD X4, X22, X22
	PACK_DATA_DWORD(44, X5); VPXORD X5, X23, X23

	// XKS call 2: absorb_state ^= ks_hi of block 0.
	VPXORD X8,  X16, X16
	VPXORD X9,  X17, X17
	VPXORD X10, X18, X18
	VPXORD X11, X19, X19
	VPXORD X12, X20, X20
	VPXORD X13, X21, X21
	VPXORD X14, X22, X22
	VPXORD X15, X23, X23

	// absorbXOR: state[8:28] ^= data[48:68] (5 dwords). X8..X12 dead.
	PACK_DATA_DWORD(48, X8);  VPXORD X8,  X18, X18
	PACK_DATA_DWORD(52, X9);  VPXORD X9,  X19, X19
	PACK_DATA_DWORD(56, X10); VPXORD X10, X20, X20
	PACK_DATA_DWORD(60, X11); VPXORD X11, X21, X21
	PACK_DATA_DWORD(64, X12); VPXORD X12, X22, X22

	// XKS call 3: absorb_state ^= ks_lo of block 1 (X24..X31).
	VPXORD X24, X16, X16
	VPXORD X25, X17, X17
	VPXORD X26, X18, X18
	VPXORD X27, X19, X19
	VPXORD X28, X20, X20
	VPXORD X29, X21, X21
	VPXORD X30, X22, X22
	VPXORD X31, X23, X23

	// ===== Writeback =====
	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11

	STORE_LANE_DW(X16, 0)
	STORE_LANE_DW(X17, 4)
	STORE_LANE_DW(X18, 8)
	STORE_LANE_DW(X19, 12)
	STORE_LANE_DW(X20, 16)
	STORE_LANE_DW(X21, 20)
	STORE_LANE_DW(X22, 24)
	STORE_LANE_DW(X23, 28)

	VZEROUPPER
	RET
