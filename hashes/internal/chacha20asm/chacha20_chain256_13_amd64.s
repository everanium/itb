//go:build amd64 && !purego && !noitbasm

// XMM-batched fused chain-absorb kernel for ChaCha20-256 with 13-byte
// per-lane data input — the Interlocked Barrier PRF fill message shape
// (0x03 || uint64-LE(groupIdx) || 4 reserved). Lane-parallel across 4
// pixels; the 4 × 32-bit lane dwords fill one XMM register exactly,
// mirroring the 20-byte kernel.
//
// Per-lane absorb construction (matches hashes.ChaCha20 bit-exactly):
//
//	per-call key:  key[i*8:(i+1)*8] ^= seeds[lane][i] (LE uint64)
//	cipher:        chacha20.NewUnauthenticatedCipher(key, zero_nonce)
//	state init:    state[0:8]   = uint64(13) (LE)
//	               state[8:21]  = data[lane][0:13]
//	               state[21:32] = 0
//	XKS round 1:   state[i] ^= ks_lo_dword[i]  for i in 0..7
//	output:        state[0:32] (4 × LE uint64)
//
// One ChaCha20 compression (counter=0) per call; only ks_lo (lower 8
// dwords of the keystream block) is consumed. data is read at dword
// offsets 0, 4, 8 (MOVL, 12 bytes) + offset 12 (MOVBLZX, 1 byte) =
// exactly 13 bytes; a MOVL at offset 12 would read past the 13-byte
// scratch buffer into the adjacent lane.
//
// Register allocation: identical to the 20-byte kernel
// (chacha20_chain256_20_amd64.s).

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
	CHACHA_QR(X0, X4, X8,  X12); \
	CHACHA_QR(X1, X5, X9,  X13); \
	CHACHA_QR(X2, X6, X10, X14); \
	CHACHA_QR(X3, X7, X11, X15); \
	CHACHA_QR(X0, X5, X10, X15); \
	CHACHA_QR(X1, X6, X11, X12); \
	CHACHA_QR(X2, X7, X8,  X13); \
	CHACHA_QR(X3, X4, X9,  X14)

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
// X16 scratch self-overwrites within X16's lower 128 bits which is
// fine since X16 is read into X16 as part of the same instruction
// (and X16's data has already been written to memory by the time
// X16 is overwritten on the next STORE call).
#define STORE_LANE_DW(x_src, off) \
	VPEXTRD $0, x_src, off(R8); \
	VPEXTRD $1, x_src, off(R9); \
	VPEXTRD $2, x_src, off(R10); \
	VPEXTRD $3, x_src, off(R11)

// func chaCha20256ChainAbsorb13x4Asm(
//     fixedKey *[32]byte,         // shared 32-byte fixed key
//     seeds    *[4][4]uint64,     // per-lane 4 seed components (stride 32)
//     dataPtrs *[4]*byte,         // 4 pointers, each to ≥13 bytes
//     out      *[4][4]uint64)     // output: 32 bytes per lane
TEXT ·chaCha20256ChainAbsorb13x4Asm(SB), NOSPLIT, $0-32
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
	VPBROADCASTD ·ChaCha20Sigma+0(SB),  X0
	VPBROADCASTD ·ChaCha20Sigma+4(SB),  X1
	VPBROADCASTD ·ChaCha20Sigma+8(SB),  X2
	VPBROADCASTD ·ChaCha20Sigma+12(SB), X3

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
	VPXORD X12, X12, X12
	VPXORD X13, X13, X13
	VPXORD X14, X14, X14
	VPXORD X15, X15, X15

	// ===== Save v_init to X16..X31 =====
	// Used at end-of-rounds for the `state += v_init` keystream
	// add. After that the same ZMMs are repurposed as the
	// absorb_state holders X16..X23.
	VMOVDQA64 X0,  X16
	VMOVDQA64 X1,  X17
	VMOVDQA64 X2,  X18
	VMOVDQA64 X3,  X19
	VMOVDQA64 X4,  X20
	VMOVDQA64 X5,  X21
	VMOVDQA64 X6,  X22
	VMOVDQA64 X7,  X23
	VMOVDQA64 X8,  X24
	VMOVDQA64 X9,  X25
	VMOVDQA64 X10, X26
	VMOVDQA64 X11, X27
	VMOVDQA64 X12, X28
	VMOVDQA64 X13, X29
	VMOVDQA64 X14, X30
	VMOVDQA64 X15, X31

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
	VPADDD X16, X0,  X0
	VPADDD X17, X1,  X1
	VPADDD X18, X2,  X2
	VPADDD X19, X3,  X3
	VPADDD X20, X4,  X4
	VPADDD X21, X5,  X5
	VPADDD X22, X6,  X6
	VPADDD X23, X7,  X7
	VPADDD X24, X8,  X8
	VPADDD X25, X9,  X9
	VPADDD X26, X10, X10
	VPADDD X27, X11, X11
	VPADDD X28, X12, X12
	VPADDD X29, X13, X13
	VPADDD X30, X14, X14
	VPADDD X31, X15, X15

	// Now X0..X7 = ks_lo (the half of the keystream consumed by the
	// single XKS call); X8..X15 = ks_hi (unused for the 13-byte buf).

	// ===== Build absorb_state into X16..X23 =====
	// state[0:8]   = uint64(13) (LE)         → absorb_state[0]=13, [1]=0
	// state[8:21]  = data[lane][0:13]        → absorb_state[2..5]
	// state[21:32] = 0                       → absorb_state[5..7]
	MOVL $13, R12
	VPBROADCASTD R12, X16   // absorb_state[0] = lenTag low 32 = 13
	VPXORD X17, X17, X17    // absorb_state[1] = lenTag high 32 = 0
	PACK_DATA_DWORD( 0, X18) // absorb_state[2] = buf[0:4] per lane
	PACK_DATA_DWORD( 4, X19) // absorb_state[3] = buf[4:8]
	PACK_DATA_DWORD( 8, X20) // absorb_state[4] = buf[8:12]
	// absorb_state[5] = buf[12] zero-extended (13-byte message tail).
	MOVBLZX 12(R8),  R12
	MOVBLZX 12(R9),  R13
	MOVBLZX 12(R10), R14
	MOVBLZX 12(R11), DI
	PACK_M_LANES_FROM_GPRS(R12, R13, R14, DI, X21)
	VPXORD X22, X22, X22    // absorb_state[6] = 0 (state[24:28])
	VPXORD X23, X23, X23    // absorb_state[7] = 0 (state[28:32])

	// ===== XOR ks_lo into absorb_state =====
	// state[k] ^= ks_lo[k] for k in 0..7.
	VPXORD X0, X16, X16
	VPXORD X1, X17, X17
	VPXORD X2, X18, X18
	VPXORD X3, X19, X19
	VPXORD X4, X20, X20
	VPXORD X5, X21, X21
	VPXORD X6, X22, X22
	VPXORD X7, X23, X23

	// ===== Writeback =====
	// out is *[4][4]uint64 = 4 lanes × 32 bytes; per-lane stride 32 bytes.
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
