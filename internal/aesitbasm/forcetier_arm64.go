//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_HASH_TIER on arm64: only "scalar" is meaningful
// (it disables the NEON kernels so the pure-Go reference runs end to
// end); every amd64 tier token keeps auto-dispatch with a stderr note.
// Also applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to batch-16 dispatch
// (HasARMAESX16), accepting "neon" and "scalar".
func init() {
	switch forcetier.HashTier() {
	case "":
	case "scalar":
		HasARMAESBatched = false
		FusedHasARMAES = false
	default:
		forcetier.Warnf("aesitbasm: %s tier is amd64-only; keeping auto-dispatch", forcetier.HashTier())
	}

	// Apply batch-16 tier forcing (ITB_FORCE_INTERLOCK_PRF_FILL_TIER).
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
