//go:build amd64 && !purego && !noitbasm

package aesitbasm

// noiseFillGran reports the block group width of the noise-filler
// kernel the fused-cascade tier flags select, so ITB_FORCE_HASH_TIER
// governs the filler with no variable of its own: VAES YMM (sixteen
// blocks per iteration) on any VAES host — the ZMM flag maps to the
// YMM kernel because the filler ships no ZMM tier — then the
// VEX-encoded XMM kernel, then the legacy-SSE XMM kernel for AES-NI
// hosts without AVX (eight blocks each), else 0: no kernel, and the Go
// path over the hardware single round runs the whole fill. The flags
// are read on every call so a forced or test-mutated tier is honoured.
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
// the run never crosses a 64-bit carry. The kernels are called
// directly (not through a func value) so the schedule the caller holds
// on its stack does not escape.
func noiseFillKernel(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64) {
	switch {
	case FusedHasVAESAVX512, FusedHasVAESAVX2:
		noiseFillX16VaesAvx2Asm(sched, dst, nblk, lo, hi)
	case FusedHasAVXAESNI:
		noiseFillX8VexAsm(sched, dst, nblk, lo, hi)
	default:
		noiseFillX8AesNiAsm(sched, dst, nblk, lo, hi)
	}
}

// Noise-filler kernels (aesitb_noisefill_x8_aesni_amd64.s,
// aesitb_noisefill_x8_vex_amd64.s, aesitb_noisefill_x16_vaesavx2_amd64.s).
//
//go:noescape
func noiseFillX8AesNiAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)

//go:noescape
func noiseFillX8VexAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)

//go:noescape
func noiseFillX16VaesAvx2Asm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
