//go:build arm64 && !purego && !noitbasm

package aesitbasm

// noiseFillGran reports eight — the block group width of the NEON
// crypto-extension kernel — when the fused-cascade flag is armed, so
// ITB_FORCE_HASH_TIER governs the filler on arm64 as it does on amd64;
// otherwise 0, and the Go path over the hardware single round runs the
// whole fill. The flag is read on every call so a forced or
// test-mutated tier is honoured.
func noiseFillGran() int {
	if FusedHasARMAES {
		return 8
	}
	return 0
}

// noiseFillKernel runs the NEON kernel on nblk blocks from counter
// (lo, hi); nblk is a multiple of eight and the run never crosses a
// 64-bit carry.
func noiseFillKernel(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64) {
	noiseFillX8NeonAsm(sched, dst, nblk, lo, hi)
}

// Noise-filler kernel (aesitb_noisefill_x8_neon_arm64.s).
//
//go:noescape
func noiseFillX8NeonAsm(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
