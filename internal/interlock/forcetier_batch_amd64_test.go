//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceInterlockTierChunkBatch asserts the batched chunk-apply flags
// follow ITB_FORCE_INTERLOCK_TIER: cleared under avx2, bmi2, and scalar (the
// per-chunk apply path of those tiers is reproduced), untouched under
// the AVX-512 tokens (auto value). Skips when the variable is unset.
func TestForceInterlockTierChunkBatch(t *testing.T) {
	switch tier := forcetier.InterlockTier(); tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_TIER unset; auto-dispatch")
	case "avx2", "bmi2", "scalar":
		if HasChunk48Batch || HasChunk168Batch {
			t.Fatalf("%s: HasChunk48Batch=%v HasChunk168Batch=%v; the batched chunk-apply kernel would run",
				tier, HasChunk48Batch, HasChunk168Batch)
		}
	case "avx512", "avx512x8":
		if HasAVX512RankMask && (!HasChunk48Batch || !HasChunk168Batch) {
			t.Fatalf("%s: HasChunk48Batch=%v HasChunk168Batch=%v on an AVX-512F host",
				tier, HasChunk48Batch, HasChunk168Batch)
		}
	}
}
