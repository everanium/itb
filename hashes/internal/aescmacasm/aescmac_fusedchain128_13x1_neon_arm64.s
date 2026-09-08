//go:build arm64 && !purego && !noitbasm

// ARM64 NEON crypto-extension fused ChainHash cascade kernel for AES-CMAC at the
// 13-byte shape, 1 lane (1 zero-padded block, 1 AES-128
// permutation per cascade round). The tail block is staged once with the
// first round key folded in and full blocks are reloaded from the lane
// pointer every round; see aescmacasm_fused.go for the construction and
// the in-package parity tests for the bit-exact pin against the pure-Go
// cascade.

#include "textflag.h"

// func aesCMAC128FusedChain13x1NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesCMAC128FusedChain13x1NeonAsm(SB), NOSPLIT, $0-40
	MOVD roundKeys+0(FP), R0
	MOVD comps+8(FP), R6
	MOVD nPairs+16(FP), R7
	MOVD data+24(FP), R2
	MOVD out+32(FP), R3
	ADD $16, R0, R4
	VLD1.P 64(R4), [V16.B16, V17.B16, V18.B16, V19.B16]
	VLD1.P 64(R4), [V20.B16, V21.B16, V22.B16, V23.B16]
	VLD1.P 16(R4), [V24.B16]
	VLD1 (R4), [V25.B16]
	VLD1 (R0), [V7.B16]
	MOVD $13, R12
	VMOV R12, V5.D[0]
	VMOV R12, V5.D[1]
	VEOR V7.B16, V5.B16, V5.B16
	VEOR V7.B16, V25.B16, V6.B16
	MOVD R2, R8
	VEOR V28.B16, V28.B16, V28.B16
	MOVD (R8), R12
	VMOV R12, V28.D[0]
	MOVWU 8(R8), R12
	VMOV R12, V28.S[2]
	MOVBU 12(R8), R12
	VMOV R12, V28.B[12]
	VEOR V5.B16, V28.B16, V28.B16
	VEOR V0.B16, V0.B16, V0.B16

loop:
	VLD1.P 16(R6), [V4.B16]
	VEOR V4.B16, V0.B16, V0.B16
	MOVD R2, R8
	AESE V28.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V17.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V18.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V19.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V20.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V21.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V22.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V23.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V24.B16, V0.B16
	VEOR V25.B16, V0.B16, V0.B16
	SUBS $1, R7, R7
	BNE loop

	VST1 [V0.B16], (R3)
	RET
