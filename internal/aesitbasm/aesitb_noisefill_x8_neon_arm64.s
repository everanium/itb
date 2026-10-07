//go:build arm64 && !purego && !noitbasm

// ARM64 NEON crypto-extension AES-ITB noise filler kernel, eight blocks
// per iteration. AESE applies AddRoundKey, SubBytes and ShiftRows and
// AESMC applies MixColumns, so one AESENC(x, rk) round of the folded
// schedule in noisefill.go is AESE with the preceding key followed by
// AESMC, the round key deferred into the next AESE: the pre-whitening
// block C is consumed as the key of the first AESE (no separate XOR),
// RK[0..3] key the four AESE that follow, and RK[4] closes each block
// as a trailing EOR. Eight running counters [lo + j, hi] feed the eight
// independent AES chains. See noisefill.go for the construction and the
// in-package parity tests for the bit-exact pin against the pure-Go
// sponge.
//
// Register allocation:
//   V0..V7   the eight block states
//   V9       C (pre-whitening)
//   V10..V13 RK[0..3]
//   V14      RK[4]
//   V15      increment [8, 0]
//   V8       increment [1, 0] (setup only)
//   V16..V23 running counters [lo + j, hi]
//
// Frame: none. Every register that held a state, a counter or a
// schedule entry is zeroed before RET.

#include "textflag.h"

#define GEN \
	VMOV V16.B16, V0.B16; \
	VMOV V17.B16, V1.B16; \
	VMOV V18.B16, V2.B16; \
	VMOV V19.B16, V3.B16; \
	VMOV V20.B16, V4.B16; \
	VMOV V21.B16, V5.B16; \
	VMOV V22.B16, V6.B16; \
	VMOV V23.B16, V7.B16; \
	VADD V15.D2, V16.D2, V16.D2; \
	VADD V15.D2, V17.D2, V17.D2; \
	VADD V15.D2, V18.D2, V18.D2; \
	VADD V15.D2, V19.D2, V19.D2; \
	VADD V15.D2, V20.D2, V20.D2; \
	VADD V15.D2, V21.D2, V21.D2; \
	VADD V15.D2, V22.D2, V22.D2; \
	VADD V15.D2, V23.D2, V23.D2

#define ROUND8(K) \
	AESE K, V0.B16; \
	AESMC V0.B16, V0.B16; \
	AESE K, V1.B16; \
	AESMC V1.B16, V1.B16; \
	AESE K, V2.B16; \
	AESMC V2.B16, V2.B16; \
	AESE K, V3.B16; \
	AESMC V3.B16, V3.B16; \
	AESE K, V4.B16; \
	AESMC V4.B16, V4.B16; \
	AESE K, V5.B16; \
	AESMC V5.B16, V5.B16; \
	AESE K, V6.B16; \
	AESMC V6.B16, V6.B16; \
	AESE K, V7.B16; \
	AESMC V7.B16, V7.B16

#define FINAL8(K) \
	VEOR K, V0.B16, V0.B16; \
	VEOR K, V1.B16, V1.B16; \
	VEOR K, V2.B16, V2.B16; \
	VEOR K, V3.B16, V3.B16; \
	VEOR K, V4.B16, V4.B16; \
	VEOR K, V5.B16, V5.B16; \
	VEOR K, V6.B16, V6.B16; \
	VEOR K, V7.B16, V7.B16

// func noiseFillX8NeonAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
TEXT ·noiseFillX8NeonAsm(SB), NOSPLIT, $0-40
	MOVD sched+0(FP), R0
	MOVD dst+8(FP), R1
	MOVD nblk+16(FP), R2
	MOVD lo+24(FP), R3
	MOVD hi+32(FP), R4
	VLD1.P 16(R0), [V9.B16]
	VLD1.P 64(R0), [V10.B16, V11.B16, V12.B16, V13.B16]
	VLD1 (R0), [V14.B16]
	MOVD $·noiseIncTab+16(SB), R5
	VLD1 (R5), [V8.B16]
	MOVD $·noiseIncTab+128(SB), R5
	VLD1 (R5), [V15.B16]
	VMOV R3, V16.D[0]
	VMOV R4, V16.D[1]
	VADD V8.D2, V16.D2, V17.D2
	VADD V8.D2, V17.D2, V18.D2
	VADD V8.D2, V18.D2, V19.D2
	VADD V8.D2, V19.D2, V20.D2
	VADD V8.D2, V20.D2, V21.D2
	VADD V8.D2, V21.D2, V22.D2
	VADD V8.D2, V22.D2, V23.D2

loop:
	GEN
	ROUND8(V9.B16)
	ROUND8(V10.B16)
	ROUND8(V11.B16)
	ROUND8(V12.B16)
	ROUND8(V13.B16)
	FINAL8(V14.B16)
	VST1.P [V0.B16, V1.B16, V2.B16, V3.B16], 64(R1)
	VST1.P [V4.B16, V5.B16, V6.B16, V7.B16], 64(R1)
	SUBS $8, R2, R2
	BNE loop
	// Wipe the block states, the counters and the key-derived schedule
	// from the register file before returning.
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16
	VEOR V9.B16, V9.B16, V9.B16
	VEOR V10.B16, V10.B16, V10.B16
	VEOR V11.B16, V11.B16, V11.B16
	VEOR V12.B16, V12.B16, V12.B16
	VEOR V13.B16, V13.B16, V13.B16
	VEOR V14.B16, V14.B16, V14.B16
	VEOR V16.B16, V16.B16, V16.B16
	VEOR V17.B16, V17.B16, V17.B16
	VEOR V18.B16, V18.B16, V18.B16
	VEOR V19.B16, V19.B16, V19.B16
	VEOR V20.B16, V20.B16, V20.B16
	VEOR V21.B16, V21.B16, V21.B16
	VEOR V22.B16, V22.B16, V22.B16
	VEOR V23.B16, V23.B16, V23.B16
	RET
