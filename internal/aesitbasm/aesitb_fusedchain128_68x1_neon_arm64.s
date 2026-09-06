//go:build arm64 && !purego && !noitbasm

// ARM64 NEON crypto-extension fused ChainHash cascade kernel for AES-ITB-128 at the
// 68-byte shape, 1 lane (5 PKCS#7 blocks, 7 AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"

// func aesITB128FusedChain68x1NeonAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
TEXT ·aesITB128FusedChain68x1NeonAsm(SB), NOSPLIT, $0-40
	MOVD key+0(FP), R0
	MOVD comps+8(FP), R6
	MOVD nPairs+16(FP), R7
	MOVD data+24(FP), R2
	MOVD out+32(FP), R3
	VLD1 (R0), [V4.B16]
	MOVD $·RC(SB), R4
	VLD1.P 64(R4), [V16.B16, V17.B16, V18.B16, V19.B16]
	VLD1 (R4), [V20.B16, V21.B16, V22.B16, V23.B16]
	MOVD R2, R8
	MOVD $·pad4Tail(SB), R4
	VLD1 (R4), [V5.B16]
	VMOV V5.B16, V24.B16
	MOVWU 64(R8), R12
	VMOV R12, V24.S[0]
	VEOR V0.B16, V0.B16, V0.B16

loop:
	VLD1.P 16(R6), [V5.B16]
	VEOR V4.B16, V5.B16, V6.B16
	VEOR V6.B16, V0.B16, V0.B16
	MOVD R2, R8
	VLD1.P 16(R8), [V8.B16]
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	VLD1.P 16(R8), [V8.B16]
	VEOR V16.B16, V8.B16, V8.B16
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	VLD1.P 16(R8), [V8.B16]
	VEOR V17.B16, V8.B16, V8.B16
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	VLD1.P 16(R8), [V8.B16]
	VEOR V18.B16, V8.B16, V8.B16
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V19.B16, V24.B16, V8.B16
	AESE V8.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V20.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V17.B16, V0.B16, V0.B16
	SUBS $1, R7, R7
	BNE loop

	VST1 [V0.B16], (R3)
	RET
