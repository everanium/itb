//go:build amd64 && !purego && !noitbasm

// ZMM-batched fused chain-absorb kernel for ChaCha20-256 with 20-byte
// per-lane data input (the ITB SetNonceBits(128) buf shape — default
// config). Lane-parallel layout across 4 pixels, mirroring the
// blake2{b,s}asm / blake3asm ZMM scaffold.
//
// Per-lane absorb construction (matches the public hashes.ChaCha20
// closure bit-exactly):
//
//	per-call key:  key[i*8:(i+1)*8] ^= seeds[lane][i] (LE uint64,
//	                                                    i in 0..3)
//	cipher:        chacha20.NewUnauthenticatedCipher(key, zero_nonce)
//	state init:    state[0:8]   = uint64(20) (LE)
//	               state[8:28]  = data[lane][0:20]
//	               state[28:32] = 0
//	XKS round 1:   state[i] ^= ks_lo_dword[i]  for i in 0..7
//	                 (consumes lower 32 bytes of compression block 0)
//	output:        state[0:32] (4 × LE uint64)
//
// One ChaCha20 compression (counter=0) is run per kernel call. The
// 16-dword keystream block is computed in full, but only the lower
// 8 dwords (= ks_lo) are XOR'd into absorb_state. Upper 8 dwords
// (= ks_hi) are unused for the 20-byte buf shape.
//
// Register allocation:
//
//	AX        fixedKey ptr (32-byte shared key)
//	CX        seeds ptr    (4 lanes × 4 uint64; per-lane stride 32 bytes)
//	DX        dataPtrs ptr (4 lane pointers)
//	R8..R11   per-lane data ptrs (loaded at entry)
//	R12..R14, DI    scratch GPRs for PACK_M_LANES_FROM_GPRS
//	R15       out ptr (saved through the round body, used at writeback)
//	Z0..Z15   ChaCha20 state v[0..15] across 20 rounds
//	Z16..Z31  v_init save (used at end for keystream `+ v_init`),
//	          then repurposed as absorb_state (Z16..Z23)
//
//	chaCha20256ChainAbsorb20x4Asm(
//	    fixedKey *[32]byte,         // shared 32-byte fixed key
//	    seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//	    dataPtrs *[4]*byte,         // 4 pointers, each to ≥20 bytes
//	    out      *[4][4]uint64)     // output: 32 bytes per lane

#include "textflag.h"

// CHACHA_QR — full ChaCha20 quarter-round, lane-parallel on 4 pixels.
// Spec rotates: 16, 12, 8, 7 (LEFT — VPROLD, distinct from BLAKE2/3
// right rotates). All in-place.
#define CHACHA_QR(a, b, c, d) \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $16, d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $12, b, b; \
	VPADDD b, a, a; VPXORD a, d, d; VPROLD $8,  d, d; \
	VPADDD d, c, c; VPXORD c, b, b; VPROLD $7,  b, b

// CHACHA_DR — one ChaCha20 doubleround = 4 column QRs + 4 diagonal
// QRs. 10 doublerounds = 20 rounds.
#define CHACHA_DR \
	CHACHA_QR(Z0, Z4, Z8,  Z12); \
	CHACHA_QR(Z1, Z5, Z9,  Z13); \
	CHACHA_QR(Z2, Z6, Z10, Z14); \
	CHACHA_QR(Z3, Z7, Z11, Z15); \
	CHACHA_QR(Z0, Z5, Z10, Z15); \
	CHACHA_QR(Z1, Z6, Z11, Z12); \
	CHACHA_QR(Z2, Z7, Z8,  Z13); \
	CHACHA_QR(Z3, Z4, Z9,  Z14)

// PACK_M_LANES_FROM_GPRS — 4 × 32-bit values (one per lane) into XMM
// dwords 0..3. EVEX writes zero upper ZMM lanes automatically.
#define PACK_M_LANES_FROM_GPRS(l0, l1, l2, l3, x_dst) \
	VMOVD  l0, x_dst; \
	VPINSRD $1, l1, x_dst, x_dst; \
	VPINSRD $2, l2, x_dst, x_dst; \
	VPINSRD $3, l3, x_dst, x_dst

// PACK_KEY_DWORD — assemble the 4-lane key dword at index k into
// x_dst. The ChaCha20 closure XORs fixedKey ^ seed at uint64
// granularity; in dword terms that means key_dword[k] for lane L is
// fixedKey_dword[k] ^ seeds[L][k/2]_{lo if k even else hi}. Since
// the per-lane seed stride is 32 bytes and seeds[L][i] occupies
// bytes L*32 + i*8, the byte offset of the lo or hi half within
// seeds[L] for a given dword index k simplifies to k*4 (k=0→0,
// k=1→4, k=2→8, …, k=7→28).
#define PACK_KEY_DWORD(k, x_dst) \
	MOVL k*4(AX),         R12; XORL k*4 + 0*32(CX), R12; \
	MOVL k*4(AX),         R13; XORL k*4 + 1*32(CX), R13; \
	MOVL k*4(AX),         R14; XORL k*4 + 2*32(CX), R14; \
	MOVL k*4(AX),         DI;  XORL k*4 + 3*32(CX), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst)

// PACK_DATA_DWORD — load a 32-bit data dword at byte offset off
// from each per-lane data pointer (R8..R11) into x_dst dword lanes
// 0..3.
#define PACK_DATA_DWORD(off, x_dst) \
	MOVL off(R8),  R12; \
	MOVL off(R9),  R13; \
	MOVL off(R10), R14; \
	MOVL off(R11), DI;  \
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, x_dst)

// STORE_LANE_DW — extract one dword from Z_src per lane and store at
// out[lane]+off. Same shape as the BLAKE2/3 STORE_LANE_DW macro;
// X16 scratch self-overwrites within Z16's lower 128 bits which is
// fine since Z16 is read into X16 as part of the same instruction
// (and Z16's data has already been written to memory by the time
// X16 is overwritten on the next STORE call).
#define STORE_LANE_DW(z_src, off) \
	VEXTRACTI32X4 $0, z_src, X16; \
	VPEXTRD $0, X16, off(R8); \
	VPEXTRD $1, X16, off(R9); \
	VPEXTRD $2, X16, off(R10); \
	VPEXTRD $3, X16, off(R11)

// func chaCha20256ChainAbsorb20x4Asm(
//     fixedKey *[32]byte,
//     seeds    *[4][4]uint64,
//     dataPtrs *[4]*byte,
//     out      *[4][4]uint64)
TEXT ·chaCha20256ChainAbsorb20x4Asm(SB), NOSPLIT, $0-32
	MOVQ fixedKey+0(FP),  AX
	MOVQ seeds+8(FP),     CX
	MOVQ dataPtrs+16(FP), DX
	MOVQ out+24(FP),      R15

	MOVQ 0(DX),  R8
	MOVQ 8(DX),  R9
	MOVQ 16(DX), R10
	MOVQ 24(DX), R11

	// ===== State init =====
	// v[0..3] = sigma constants (broadcast across all 4 lanes).
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  Z0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  Z1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  Z2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), Z3

	// v[4..11] = per-lane ChaCha20 key (fixedKey ⊕ seed, 8 dwords).
	PACK_KEY_DWORD(0, X4)
	PACK_KEY_DWORD(1, X5)
	PACK_KEY_DWORD(2, X6)
	PACK_KEY_DWORD(3, X7)
	PACK_KEY_DWORD(4, X8)
	PACK_KEY_DWORD(5, X9)
	PACK_KEY_DWORD(6, X10)
	PACK_KEY_DWORD(7, X11)

	// v[12..15] = 0 (counter=0 for the only compression block;
	// nonce is the zero nonce per the closure).
	VPXORD Z12, Z12, Z12
	VPXORD Z13, Z13, Z13
	VPXORD Z14, Z14, Z14
	VPXORD Z15, Z15, Z15

	// ===== Save v_init to Z16..Z31 =====
	// Used at end-of-rounds for the `state += v_init` keystream
	// add. After that the same ZMMs are repurposed as the
	// absorb_state holders Z16..Z23.
	VMOVDQA64 Z0,  Z16
	VMOVDQA64 Z1,  Z17
	VMOVDQA64 Z2,  Z18
	VMOVDQA64 Z3,  Z19
	VMOVDQA64 Z4,  Z20
	VMOVDQA64 Z5,  Z21
	VMOVDQA64 Z6,  Z22
	VMOVDQA64 Z7,  Z23
	VMOVDQA64 Z8,  Z24
	VMOVDQA64 Z9,  Z25
	VMOVDQA64 Z10, Z26
	VMOVDQA64 Z11, Z27
	VMOVDQA64 Z12, Z28
	VMOVDQA64 Z13, Z29
	VMOVDQA64 Z14, Z30
	VMOVDQA64 Z15, Z31

	// ===== 10 doublerounds = 20 ChaCha20 rounds =====
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
	VPADDD Z16, Z0,  Z0
	VPADDD Z17, Z1,  Z1
	VPADDD Z18, Z2,  Z2
	VPADDD Z19, Z3,  Z3
	VPADDD Z20, Z4,  Z4
	VPADDD Z21, Z5,  Z5
	VPADDD Z22, Z6,  Z6
	VPADDD Z23, Z7,  Z7
	VPADDD Z24, Z8,  Z8
	VPADDD Z25, Z9,  Z9
	VPADDD Z26, Z10, Z10
	VPADDD Z27, Z11, Z11
	VPADDD Z28, Z12, Z12
	VPADDD Z29, Z13, Z13
	VPADDD Z30, Z14, Z14
	VPADDD Z31, Z15, Z15

	// Now Z0..Z7 = ks_lo (the half of the keystream consumed by the
	// single XKS call); Z8..Z15 = ks_hi (unused for 20-byte buf).

	// ===== Build absorb_state into Z16..Z23 =====
	// state[0:8]   = uint64(20) (LE)         → absorb_state[0]=20, [1]=0
	// state[8:28]  = data[lane][0:20]        → absorb_state[2..6]
	// state[28:32] = 0                       → absorb_state[7]=0
	MOVL $20, R12
	VPBROADCASTD R12, Z16   // absorb_state[0] = lenTag low 32 = 20
	VPXORD Z17, Z17, Z17    // absorb_state[1] = lenTag high 32 = 0
	PACK_DATA_DWORD( 0, X18) // absorb_state[2] = data[0:4] per lane
	PACK_DATA_DWORD( 4, X19) // absorb_state[3] = data[4:8]
	PACK_DATA_DWORD( 8, X20) // absorb_state[4] = data[8:12]
	PACK_DATA_DWORD(12, X21) // absorb_state[5] = data[12:16]
	PACK_DATA_DWORD(16, X22) // absorb_state[6] = data[16:20]
	VPXORD Z23, Z23, Z23    // absorb_state[7] = state[28:32] = 0

	// ===== XOR ks_lo into absorb_state =====
	// state[k] ^= ks_lo[k] for k in 0..7.
	VPXORD Z0, Z16, Z16
	VPXORD Z1, Z17, Z17
	VPXORD Z2, Z18, Z18
	VPXORD Z3, Z19, Z19
	VPXORD Z4, Z20, Z20
	VPXORD Z5, Z21, Z21
	VPXORD Z6, Z22, Z22
	VPXORD Z7, Z23, Z23

	// ===== Writeback =====
	// out is *[4][4]uint64 = 4 lanes × 32 bytes; per-lane stride 32 bytes.
	MOVQ R15, R8
	LEAQ 32(R15), R9
	LEAQ 64(R15), R10
	LEAQ 96(R15), R11

	STORE_LANE_DW(Z16, 0)
	STORE_LANE_DW(Z17, 4)
	STORE_LANE_DW(Z18, 8)
	STORE_LANE_DW(Z19, 12)
	STORE_LANE_DW(Z20, 16)
	STORE_LANE_DW(Z21, 20)
	STORE_LANE_DW(Z22, 24)
	STORE_LANE_DW(Z23, 28)

	VZEROUPPER
	RET
