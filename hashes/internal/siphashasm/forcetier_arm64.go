//go:build arm64 && !purego && !noitbasm

package siphashasm

import "github.com/everanium/itb/internal/forcetier"

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every SipHash-2-4 dispatch family, then ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// to the batch-16 family alone. Each variable is handled by its own
// function so an unsatisfiable token in one cannot skip the other.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER on arm64.
//
//	neon   — selects the NEON four-lane kernels, the GPR single-lane
//	         kernel and the NEON batch-16 arm (the baseline selection).
//	sve2   — reserved for a future SVE2 kernel family; today a NEON
//	         alias, identical flag-wise. When SVE2-native kernels land,
//	         this token remaps.
//	sve    — the same reservation for an SVE-only slice; today a NEON
//	         alias for diagnostic simulation.
//	scalar — disables the kernels of every family so the pure-Go
//	         reference runs end to end.
//
// Every amd64 tier token keeps auto-dispatch with a stderr note.
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER, applied afterwards, can re-arm the
// batch-16 NEON arm on its own.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		FusedHasNEON = true
		HasNEONX16 = true
	case "scalar":
		FusedHasNEON = false
		HasNEONX16 = false
		FusedHasGPR, HasGPRX16 = false, false
	default:
		forcetier.Warnf("siphashasm: %s tier is amd64-only; keeping auto-dispatch", forcetier.HashTier())
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 dispatch flag (HasNEONX16), accepting "neon" and
// "scalar"; every amd64 token keeps auto-dispatch with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "":
	case "neon":
		HasNEONX16 = true
	case "scalar":
		HasNEONX16 = false
		HasGPRX16 = false
	default:
		forcetier.Warnf("siphashasm: %s batch-16 tier is amd64-only; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
	}
}
