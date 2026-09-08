//go:build arm64 && !purego && !noitbasm

package areionasm

import (
	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every Areion dispatch family on arm64 — the batched-permute arm
// flag, the fused cascade flag and the batch-16 fill flag — then
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16 family alone.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER on arm64.
//
//	neon   — selects the ARM crypto-extension kernels of every family
//	         (batched permutation, fused cascade, batch-16 fill);
//	         requires the extension, otherwise a stderr note is emitted
//	         and auto-dispatch is kept.
//	sve2   — reserved for a future SVE2 kernel family; routes to the
//	         NEON kernels today (see the aesitbasm counterpart for the
//	         silicon rationale).
//	sve    — the same reservation for an SVE-only slice; a NEON alias.
//	scalar — disables every kernel so the pure-Go paths run end to end.
//
// Every amd64 tier token keeps auto-dispatch with a stderr note.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		if !aes.CPU.HasARMCrypto {
			forcetier.Warnf("areionasm: %s tier needs the ARM crypto extension; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		HasARMAESBatched, FusedHasARMAES, HasARMAESX16 = true, true, true
	case "scalar":
		HasARMAESBatched, FusedHasARMAES, HasARMAESX16 = false, false, false
	default:
		forcetier.Warnf("areionasm: %s tier is amd64-only; keeping auto-dispatch", forcetier.HashTier())
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 fill flag (HasARMAESX16), accepting "neon" and "scalar";
// every amd64 token keeps auto-dispatch with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "":
	case "neon":
		if !aes.CPU.HasARMCrypto {
			forcetier.Warnf("areionasm: neon batch-16 tier needs the ARM crypto extension; keeping auto-dispatch")
			return
		}
		HasARMAESX16 = true
	case "scalar":
		HasARMAESX16 = false
	default:
		forcetier.Warnf("areionasm: %s batch-16 tier is amd64-only; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
	}
}
