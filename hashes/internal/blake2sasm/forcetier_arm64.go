//go:build arm64 && !purego && !noitbasm

package blake2sasm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to the fused cascade flag and the batch-16 fill flag, then
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16 flag alone.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER on arm64.
//
//	neon   — selects the NEON kernels of both families; requires
//	         Advanced SIMD (every ARMv8-A host), otherwise a stderr note
//	         is emitted and auto-dispatch is kept.
//	sve2   — reserved for a future SVE2 kernel family; routes to the
//	         NEON kernels today.
//	sve    — the same reservation for an SVE-only slice; a NEON alias.
//	scalar — disables every kernel so the pure-Go paths run end to end.
//
// Every amd64 tier token keeps auto-dispatch with a stderr note.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		if !cpu.ARM64.HasASIMD {
			forcetier.Warnf("blake2sasm: %s tier needs Advanced SIMD; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		FusedHasNEON, HasNEONX16 = true, true
	case "scalar":
		FusedHasNEON, HasNEONX16 = false, false
		FusedHasGPR, HasGPRX16 = false, false
	default:
		forcetier.Warnf("blake2sasm: %s tier is amd64-only; keeping auto-dispatch", forcetier.HashTier())
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// to the batch-16 fill flag (HasNEONX16), accepting "neon" and "scalar";
// every amd64 token keeps auto-dispatch with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "":
	case "neon":
		if !cpu.ARM64.HasASIMD {
			forcetier.Warnf("blake2sasm: neon batch-16 tier needs Advanced SIMD; keeping auto-dispatch")
			return
		}
		HasNEONX16 = true
	case "scalar":
		HasNEONX16 = false
		HasGPRX16 = false
	default:
		forcetier.Warnf("blake2sasm: %s batch-16 tier is amd64-only; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
	}
}
