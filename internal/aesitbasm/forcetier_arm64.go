//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every AES-ITB dispatch family, then ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// to the batch-16 family alone. Each variable is handled by its own
// function so an unsatisfiable token in one cannot skip the other.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER on arm64.
//
//	neon   — selects the NEON crypto-extension kernels of every family
//	         (fused cascade and batch-16); requires the ARM crypto
//	         extension, otherwise a stderr note is emitted and
//	         auto-dispatch is kept.
//	sve2   — reserved for a future SVE2 aesitb128 kernel family. An
//	         SVE2 arm only pays off on silicon with a fused AES round
//	         (FEAT_SVE_AES2) or a vector length above 128 bits with SVE
//	         AES; no shipping Graviton part has either, so the token
//	         routes to the NEON kernels — identical to neon flag-wise.
//	         When SVE2-native kernels land, this token remaps.
//	sve    — the same reservation for an SVE-only slice; today a NEON
//	         alias for diagnostic simulation.
//	scalar — disables the NEON kernels of every family so the pure-Go
//	         reference runs end to end.
//
// Every amd64 tier token keeps auto-dispatch with a stderr note.
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER, applied afterwards, can re-arm the
// batch-16 NEON kernel on its own.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		if !aes.CPU.HasARMCrypto {
			forcetier.Warnf("aesitbasm: %s tier needs the ARM crypto extension; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		FusedHasARMAES = true
		HasARMAESX16 = true
	case "scalar":
		FusedHasARMAES = false
		HasARMAESX16 = false
	default:
		forcetier.Warnf("aesitbasm: %s tier is amd64-only; keeping auto-dispatch", forcetier.HashTier())
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 dispatch flag (HasARMAESX16), accepting "neon" and
// "scalar"; every amd64 token keeps auto-dispatch with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "":
	case "neon":
		if !aes.CPU.HasARMCrypto {
			forcetier.Warnf("aesitbasm: neon batch-16 tier needs ARM crypto; keeping auto-dispatch")
			return
		}
		HasARMAESX16 = true
	case "scalar":
		HasARMAESX16 = false
	default:
		forcetier.Warnf("aesitbasm: %s batch-16 tier is amd64-only; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
	}
}
