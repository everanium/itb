//go:build arm64 && !purego && !noitbasm

package siphashasm

import (
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the arm64 dispatch flags carry
// the state ITB_FORCE_HASH_TIER names: neon, sve2 and sve are
// equivalent (all select the NEON kernels of both families), scalar
// clears them, and the amd64 tokens keep auto-dispatch. Skips when the
// variable is unset. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set
// the batch-16 flag belongs to that variable and is not checked here.
func TestForceHashTierApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "neon", "sve2", "sve":
		if !FusedHasNEON {
			t.Fatalf("%s: FusedHasNEON is false", tier)
		}
		if x16Owned && !HasNEONX16 {
			t.Fatalf("%s: HasNEONX16 is false", tier)
		}
	case "scalar":
		if FusedHasNEON {
			t.Fatal("scalar: FusedHasNEON is still set")
		}
		if x16Owned && HasNEONX16 {
			t.Fatal("scalar: HasNEONX16 is still set")
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16 flag
// carries the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER names on arm64.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "neon":
		if !HasNEONX16 {
			t.Fatal("neon: HasNEONX16 is false")
		}
	case "scalar":
		if HasNEONX16 {
			t.Fatal("scalar: HasNEONX16 is still set")
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s batch-16 tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
