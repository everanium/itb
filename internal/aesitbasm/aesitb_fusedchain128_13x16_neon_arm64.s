//go:build arm64 && !purego && !noitbasm

// ARM64 NEON crypto-extension (AESE + AESMC, round constant folded into the next AESE key operand)
// 16-lane fused ChainHash cascade kernel for AES-ITB-128 at the 13-byte
// per-lane fill shape. See aesitbasm_fused.go for the construction; the
// kernel is pinned to the pure-Go reference (scalarFusedX16) by the
// in-package parity tests.
//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of
// the x4 path. The synthesised block is round-invariant per lane; every
// cascade round XORs key XOR (c0 || c1) and the block into the state and
// runs the three AES rounds (absorb, finaliser RC[0], finaliser RC[1]).
// Block layout per lane: [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03]
// (domain tag, 8-byte index, 4 zero bytes, 3 PKCS#7 padding bytes).
//
// Batch layout: two batches of 8 lanes, each register-resident — V0..V7
// states, V8..V15 blocks, V16 / V17 RC[0] / RC[1], V18 key, V19 key XOR
// pair (per round), V20 pair load. Each batch runs the whole cascade
// before the next starts. Issue order inside a round is round-major:
// every step (the key XOR pair fold, each of the three AESE+AESMC rounds,
// the final RC[1] XOR) runs across all 8 lanes before the next step
// starts, so the 8 independent chains keep both crypto pipes busy
// instead of serialising each lane's dependency chain behind the
// previous lane's.

#include "textflag.h"

// func aesITB128FusedChain13x16NeonAsm(key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
TEXT ·aesITB128FusedChain13x16NeonAsm(SB), NOSPLIT, $0-40
	MOVD key+0(FP), R0
	MOVD comps+8(FP), R1
	MOVD nPairs+16(FP), R2
	MOVD groupIdxBase+24(FP), R3
	MOVD out+32(FP), R4

	// Load key (V18) and round constants RC[0] (V16), RC[1] (V17)
	VLD1 (R0), [V18.B16]
	MOVD $·RC(SB), R5
	VLD1.P 16(R5), [V16.B16]  // RC[0]
	VLD1 (R5), [V17.B16]      // RC[1]

	// Materialized constant for pad tail: bytes 13-15 = 0x03
	MOVD $0x0303030000000000, R7

	// ========== BATCH 1: lanes 0–7 ==========
	// Step 1 — synthesise the 8 fill blocks in V8..V15:
	// [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] as
	// D[0] = (idx << 8) | 0x03, D[1] = (idx >> 56) | pad tail.
	MOVD R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V8.D[0]
	VMOV R9, V8.D[1]
	ADD $1, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V9.D[0]
	VMOV R9, V9.D[1]
	ADD $2, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V10.D[0]
	VMOV R9, V10.D[1]
	ADD $3, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V11.D[0]
	VMOV R9, V11.D[1]
	ADD $4, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V12.D[0]
	VMOV R9, V12.D[1]
	ADD $5, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V13.D[0]
	VMOV R9, V13.D[1]
	ADD $6, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V14.D[0]
	VMOV R9, V14.D[1]
	ADD $7, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V15.D[0]
	VMOV R9, V15.D[1]

	// Step 2 — zero the 8 states, reset the component cursor and pair count.
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	MOVD R1, R10
	MOVD R2, R11

loop0:
	// Fold key XOR pair (V19) into every state, then the block as the
	// first AESE key operand, two RC[0] rounds and the final RC[1] XOR.
	VLD1.P 16(R10), [V20.B16]
	VEOR V18.B16, V20.B16, V19.B16
	VEOR V19.B16, V0.B16, V0.B16
	VEOR V19.B16, V1.B16, V1.B16
	VEOR V19.B16, V2.B16, V2.B16
	VEOR V19.B16, V3.B16, V3.B16
	VEOR V19.B16, V4.B16, V4.B16
	VEOR V19.B16, V5.B16, V5.B16
	VEOR V19.B16, V6.B16, V6.B16
	VEOR V19.B16, V7.B16, V7.B16
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V9.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V10.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V11.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V12.B16, V4.B16
	AESMC V4.B16, V4.B16
	AESE V13.B16, V5.B16
	AESMC V5.B16, V5.B16
	AESE V14.B16, V6.B16
	AESMC V6.B16, V6.B16
	AESE V15.B16, V7.B16
	AESMC V7.B16, V7.B16
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V16.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V16.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V16.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V16.B16, V4.B16
	AESMC V4.B16, V4.B16
	AESE V16.B16, V5.B16
	AESMC V5.B16, V5.B16
	AESE V16.B16, V6.B16
	AESMC V6.B16, V6.B16
	AESE V16.B16, V7.B16
	AESMC V7.B16, V7.B16
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V16.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V16.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V16.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V16.B16, V4.B16
	AESMC V4.B16, V4.B16
	AESE V16.B16, V5.B16
	AESMC V5.B16, V5.B16
	AESE V16.B16, V6.B16
	AESMC V6.B16, V6.B16
	AESE V16.B16, V7.B16
	AESMC V7.B16, V7.B16
	VEOR V17.B16, V0.B16, V0.B16
	VEOR V17.B16, V1.B16, V1.B16
	VEOR V17.B16, V2.B16, V2.B16
	VEOR V17.B16, V3.B16, V3.B16
	VEOR V17.B16, V4.B16, V4.B16
	VEOR V17.B16, V5.B16, V5.B16
	VEOR V17.B16, V6.B16, V6.B16
	VEOR V17.B16, V7.B16, V7.B16
	SUBS $1, R11, R11
	BNE loop0

	// Store batch 1 rank pairs in lane order.
	VST1.P [V0.B16], 16(R4)
	VST1.P [V1.B16], 16(R4)
	VST1.P [V2.B16], 16(R4)
	VST1.P [V3.B16], 16(R4)
	VST1.P [V4.B16], 16(R4)
	VST1.P [V5.B16], 16(R4)
	VST1.P [V6.B16], 16(R4)
	VST1.P [V7.B16], 16(R4)

	// ========== BATCH 2: lanes 8–15 ==========
	// Step 1 — synthesise the 8 fill blocks in V8..V15:
	// [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] as
	// D[0] = (idx << 8) | 0x03, D[1] = (idx >> 56) | pad tail.
	ADD $8, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V8.D[0]
	VMOV R9, V8.D[1]
	ADD $9, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V9.D[0]
	VMOV R9, V9.D[1]
	ADD $10, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V10.D[0]
	VMOV R9, V10.D[1]
	ADD $11, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V11.D[0]
	VMOV R9, V11.D[1]
	ADD $12, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V12.D[0]
	VMOV R9, V12.D[1]
	ADD $13, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V13.D[0]
	VMOV R9, V13.D[1]
	ADD $14, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V14.D[0]
	VMOV R9, V14.D[1]
	ADD $15, R3, R6
	LSL $8, R6, R8
	ORR $3, R8, R8
	LSR $56, R6, R9
	ORR R7, R9, R9
	VMOV R8, V15.D[0]
	VMOV R9, V15.D[1]

	// Step 2 — zero the 8 states, reset the component cursor and pair count.
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	MOVD R1, R10
	MOVD R2, R11

loop1:
	// Fold key XOR pair (V19) into every state, then the block as the
	// first AESE key operand, two RC[0] rounds and the final RC[1] XOR.
	VLD1.P 16(R10), [V20.B16]
	VEOR V18.B16, V20.B16, V19.B16
	VEOR V19.B16, V0.B16, V0.B16
	VEOR V19.B16, V1.B16, V1.B16
	VEOR V19.B16, V2.B16, V2.B16
	VEOR V19.B16, V3.B16, V3.B16
	VEOR V19.B16, V4.B16, V4.B16
	VEOR V19.B16, V5.B16, V5.B16
	VEOR V19.B16, V6.B16, V6.B16
	VEOR V19.B16, V7.B16, V7.B16
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V9.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V10.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V11.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V12.B16, V4.B16
	AESMC V4.B16, V4.B16
	AESE V13.B16, V5.B16
	AESMC V5.B16, V5.B16
	AESE V14.B16, V6.B16
	AESMC V6.B16, V6.B16
	AESE V15.B16, V7.B16
	AESMC V7.B16, V7.B16
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V16.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V16.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V16.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V16.B16, V4.B16
	AESMC V4.B16, V4.B16
	AESE V16.B16, V5.B16
	AESMC V5.B16, V5.B16
	AESE V16.B16, V6.B16
	AESMC V6.B16, V6.B16
	AESE V16.B16, V7.B16
	AESMC V7.B16, V7.B16
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V16.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V16.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V16.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V16.B16, V4.B16
	AESMC V4.B16, V4.B16
	AESE V16.B16, V5.B16
	AESMC V5.B16, V5.B16
	AESE V16.B16, V6.B16
	AESMC V6.B16, V6.B16
	AESE V16.B16, V7.B16
	AESMC V7.B16, V7.B16
	VEOR V17.B16, V0.B16, V0.B16
	VEOR V17.B16, V1.B16, V1.B16
	VEOR V17.B16, V2.B16, V2.B16
	VEOR V17.B16, V3.B16, V3.B16
	VEOR V17.B16, V4.B16, V4.B16
	VEOR V17.B16, V5.B16, V5.B16
	VEOR V17.B16, V6.B16, V6.B16
	VEOR V17.B16, V7.B16, V7.B16
	SUBS $1, R11, R11
	BNE loop1

	// Store batch 2 rank pairs in lane order.
	VST1.P [V0.B16], 16(R4)
	VST1.P [V1.B16], 16(R4)
	VST1.P [V2.B16], 16(R4)
	VST1.P [V3.B16], 16(R4)
	VST1.P [V4.B16], 16(R4)
	VST1.P [V5.B16], 16(R4)
	VST1.P [V6.B16], 16(R4)
	VST1.P [V7.B16], 16(R4)

	RET
