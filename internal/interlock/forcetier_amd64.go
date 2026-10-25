//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_INTERLOCK_TIER to the 48-bit and 168-bit
// interlock dispatch flags.
//
//	avx512 — requires AVX-512F + BMI2 silicon; keeps the batched AVX-512
//	         rank-unrank kernels selected. HasBMI2 keeps its auto
//	         value: the PEXT/PDEP apply micro-kernel is orthogonal to
//	         the rank-mask kernel choice.
//	avx512x8 — requires AVX-512F + BMI2 silicon; keeps the AVX-512 rank-unrank
//	           kernels selected but clears UseUnrank16, so every 16-chunk
//	           48-bit superblock runs as two 8-lane passes instead of the one
//	           16-lane pass. Makes the x8×2 geometry reachable end-to-end
//	           on a host whose auto-dispatch selects the 16-lane kernel.
//	           HasBMI2 keeps its auto value.
//	avx2   — requires AVX2 + BMI2 silicon; selects the 4-lane AVX2
//	         rank-unrank kernels, disabling the AVX-512 kernels so the
//	         AVX2 arm is reachable on AVX-512F hosts. HasBMI2 keeps
//	         its auto value (orthogonal, as above); the batched
//	         chunk-apply kernels are cleared so the per-chunk apply
//	         path is reproduced for cross-tier parity checks
//	         (production BMI2 hosts default to the batched kernels).
//	bmi2   — requires BMI2 silicon; disables the AVX-512 and AVX2
//	         rank-unrank kernels and the batched chunk-apply kernels
//	         while keeping HasBMI2 set, so scalar rank-unrank runs
//	         paired with the per-chunk BMI2 PEXT/PDEP apply kernels.
//	scalar — disables the AVX-512 and AVX2 rank-mask kernels, the
//	         BMI2 PEXT/PDEP kernels and the batched chunk-apply
//	         kernels, so the pure-Go softPEXT / softPDEP and
//	         scalar rankToMaskTriple paths run.
//
// Production auto-dispatch is unaffected when the variable is unset: a
// CPU with BMI2 keeps its BMI2 rank-mask and batched chunk-apply fast
// path exactly as auto-selection would set them.
func init() {
	switch forcetier.InterlockTier() {
	case "avx512":
		if !cpuid.AVX512F || !cpuid.BMI2 {
			forcetier.Warnf("interlock: avx512 tier needs AVX-512F+BMI2 silicon; keeping auto-dispatch")
			return
		}
		HasAVX512RankMask = true
	case "avx512x8":
		if !cpuid.AVX512F || !cpuid.BMI2 {
			forcetier.Warnf("interlock: avx512x8 tier needs AVX-512F+BMI2 silicon; keeping auto-dispatch")
			return
		}
		HasAVX512RankMask = true
		UseUnrank16 = false
	case "avx2":
		if !cpuid.AVX2 || !cpuid.BMI2 {
			forcetier.Warnf("interlock: avx2 tier needs AVX2+BMI2 silicon; keeping auto-dispatch")
			return
		}
		HasAVX2RankMask = true
		HasAVX512RankMask = false
		HasChunk48Batch = false
		HasChunk168Batch = false
	case "bmi2":
		if !cpuid.BMI2 {
			forcetier.Warnf("interlock: bmi2 tier needs BMI2 silicon; keeping auto-dispatch")
			return
		}
		HasAVX512RankMask = false
		HasAVX2RankMask = false
		HasBMI2 = true
		HasChunk48Batch = false
		HasChunk168Batch = false
	case "scalar":
		HasAVX512RankMask = false
		HasAVX2RankMask = false
		HasBMI2 = false
		HasChunk48Batch = false
		HasChunk168Batch = false
	case "sve2", "sve", "neon":
		forcetier.Warnf("interlock: %s tier is arm64-only; keeping auto-dispatch", forcetier.InterlockTier())
	}
}
