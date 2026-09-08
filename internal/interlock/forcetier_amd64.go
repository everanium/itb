//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_INTERLOCK_TIER to the 48-bit interlock
// dispatch flags.
//
//	avx512 — requires AVX-512F silicon; keeps the batched AVX-512
//	         rank-unrank kernel selected. HasBMI2 keeps its auto
//	         value: the PEXT/PDEP apply micro-kernel is orthogonal to
//	         the rank-mask kernel choice.
//	avx512x8 — requires AVX-512F silicon; keeps the AVX-512 rank-unrank
//	           kernel selected but clears UseUnrank16, so every 16-chunk
//	           superblock runs as two 8-lane passes instead of the one
//	           16-lane pass. Makes the x8×2 geometry reachable end-to-end
//	           on a host whose auto-dispatch selects the 16-lane kernel.
//	           HasBMI2 keeps its auto value.
//	avx2   — requires AVX2 + BMI2 silicon; selects the 4-lane AVX2
//	         rank-unrank kernel, disabling the AVX-512 kernel so the
//	         AVX2 arm is reachable on AVX-512F hosts. HasBMI2 keeps
//	         its auto value (orthogonal, as above); the batched
//	         chunk-apply kernel is cleared so the per-chunk apply
//	         path is reproduced for cross-tier parity checks
//	         (production BMI2 hosts default to the batched kernel).
//	scalar — disables the AVX-512 and AVX2 rank-mask kernels, the
//	         BMI2 PEXT/PDEP kernels and the batched chunk-apply
//	         kernel, so the pure-Go softPEXT48 / softPDEP48 and
//	         scalar rankToMaskTriple48 paths run.
//
// Production auto-dispatch is unaffected when the variable is unset: a
// CPU with BMI2 keeps its BMI2 rank-mask and batched chunk-apply fast
// path exactly as auto-selection would set them.
func init() {
	switch forcetier.InterlockTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("interlock: avx512 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512RankMask = true
	case "avx512x8":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("interlock: avx512x8 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512RankMask = true
		UseUnrank16 = false
	case "avx2":
		if !cpu.X86.HasAVX2 || !cpu.X86.HasBMI2 {
			forcetier.Warnf("interlock: avx2 tier needs AVX2+BMI2 silicon; keeping auto-dispatch")
			return
		}
		HasAVX2RankMask = true
		HasAVX512RankMask = false
		HasChunk48Batch = false
	case "scalar":
		HasAVX512RankMask = false
		HasAVX2RankMask = false
		HasBMI2 = false
		HasChunk48Batch = false
	}
}
