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
//	avx2   — requires AVX2 + BMI2 silicon; selects the 4-lane AVX2
//	         rank-unrank kernel, disabling the AVX-512 kernel so the
//	         AVX2 arm is reachable on AVX-512F hosts. HasBMI2 keeps
//	         its auto value (orthogonal, as above).
//	scalar — disables the AVX-512 and AVX2 rank-mask kernels and the
//	         BMI2 PEXT/PDEP kernels, so the pure-Go softPEXT48 /
//	         softPDEP48 and scalar rankToMaskTriple48 paths run.
//
// Production auto-dispatch is unaffected when the variable is unset: a
// CPU with BMI2 but no AVX-512 keeps its BMI2 fast path exactly as
// before.
func init() {
	switch forcetier.InterlockTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("interlock: avx512 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512RankMask = true
	case "avx2":
		if !cpu.X86.HasAVX2 || !cpu.X86.HasBMI2 {
			forcetier.Warnf("interlock: avx2 tier needs AVX2+BMI2 silicon; keeping auto-dispatch")
			return
		}
		HasAVX2RankMask = true
		HasAVX512RankMask = false
	case "scalar":
		HasAVX512RankMask = false
		HasAVX2RankMask = false
		HasBMI2 = false
	}
}
