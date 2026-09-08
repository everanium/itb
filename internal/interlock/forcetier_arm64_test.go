//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceInterlockTierApplied asserts that the arm64 dispatch flags
// carry the state ITB_FORCE_INTERLOCK_TIER names, for every token the
// arm64 init honours. Skips when the variable is unset (auto-dispatch)
// or when the host / build cannot honour the token, so it is a no-op in
// an ordinary test run and becomes the probe when a forced-tier sweep
// sets the variable.
func TestForceInterlockTierApplied(t *testing.T) {
	tier := forcetier.InterlockTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_TIER unset; auto-dispatch")
	case "sve2":
		if !HasSVE2Interlock {
			t.Skip("sve2 tier not executable on this host / build")
		}
		if !HasNEONInterlock || !HasChunk48Batch {
			t.Fatalf("sve2: HasNEONInterlock=%v HasChunk48Batch=%v, want both true", HasNEONInterlock, HasChunk48Batch)
		}
	case "neon", "sve":
		if !HasNEONInterlock || !HasChunk48Batch || HasSVE2Interlock {
			t.Fatalf("%s: HasNEONInterlock=%v HasChunk48Batch=%v HasSVE2Interlock=%v, want true/true/false",
				tier, HasNEONInterlock, HasChunk48Batch, HasSVE2Interlock)
		}
	case "scalar":
		if HasNEONInterlock || HasChunk48Batch || HasSVE2Interlock {
			t.Fatalf("scalar: HasNEONInterlock=%v HasChunk48Batch=%v HasSVE2Interlock=%v, want all false",
				HasNEONInterlock, HasChunk48Batch, HasSVE2Interlock)
		}
	case "avx512", "avx512x8", "avx2":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
