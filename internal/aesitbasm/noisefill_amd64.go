//go:build amd64 && !purego && !noitbasm

package aesitbasm

// noiseFillZMM arms the VAES ZMM noise-filler kernel. applyHashTier
// sets it only when ITB_FORCE_HASH_TIER=avx512 is honoured; auto-dispatch
// leaves it false, so the filler runs the VAES YMM kernel on every VAES
// host, AVX-512 hosts included. The ZMM kernel's throughput matches the
// YMM kernel within run-to-run spread on the hosts measured (Rocket
// Lake, Sapphire Rapids, Zen 4), and the YMM kernel keeps the noise fill
// off the ZMM register file.
var noiseFillZMM bool

// noiseFillGran reports the block group width of the noise-filler
// kernel the fused-cascade tier flags select, so ITB_FORCE_HASH_TIER
// governs the filler with no variable of its own: VAES ZMM (sixteen
// blocks per iteration) when noiseFillZMM is armed alongside the ZMM
// flag, otherwise VAES YMM (sixteen blocks per iteration) on any VAES
// host, then the VEX-encoded XMM kernel, then the legacy-SSE XMM kernel
// for AES-NI hosts without AVX (eight blocks each), else 0: no kernel,
// and the Go path over the hardware single round runs the whole fill.
// Auto-dispatch selects YMM over ZMM on AVX-512 hosts because the two
// match within run-to-run spread on the hosts measured and YMM keeps
// the fill off the ZMM register file. The flags are read on every call
// so a forced or test-mutated tier is honoured.
func noiseFillGran() int {
	switch {
	case FusedHasVAESAVX512, FusedHasVAESAVX2:
		return 16
	case FusedHasAVXAESNI, FusedHasAESNI:
		return 8
	}
	return 0
}

// noiseFillKernel runs the selected kernel on nblk blocks from counter
// (lo, hi); nblk is a multiple of the width noiseFillGran reports and
// the run never crosses a 64-bit carry. The ZMM kernel runs only when
// noiseFillZMM is armed (ITB_FORCE_HASH_TIER=avx512); the VAES YMM
// kernel serves every VAES host otherwise, for the reasons given at
// noiseFillZMM. The kernels are called
// directly (not through a func value) so the schedule the caller holds
// on its stack does not escape.
func noiseFillKernel(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64) {
	switch {
	case noiseFillZMM && FusedHasVAESAVX512:
		noiseFillX16Avx512Asm(sched, dst, nblk, lo, hi)
	case FusedHasVAESAVX512, FusedHasVAESAVX2:
		noiseFillX16VaesAvx2Asm(sched, dst, nblk, lo, hi)
	case FusedHasAVXAESNI:
		noiseFillX8VexAsm(sched, dst, nblk, lo, hi)
	default:
		noiseFillX8AesNiAsm(sched, dst, nblk, lo, hi)
	}
}

// Noise-filler kernels (aesitb_noisefill_x8_aesni_amd64.s,
// aesitb_noisefill_x8_vex_amd64.s, aesitb_noisefill_x16_vaesavx2_amd64.s,
// aesitb_noisefill_x16_avx512_amd64.s).
//
//go:noescape
func noiseFillX8AesNiAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)

//go:noescape
func noiseFillX8VexAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)

//go:noescape
func noiseFillX16VaesAvx2Asm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)

//go:noescape
func noiseFillX16Avx512Asm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
