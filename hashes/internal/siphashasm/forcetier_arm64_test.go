//go:build arm64 && !purego && !noitbasm

package siphashasm

import (
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the arm64 dispatch flags carry
// the state ITB_FORCE_HASH_TIER names: neon, sve2 and sve are
// equivalent (all select the NEON kernels of both families), gpr clears
// the NEON flags and arms the GPR kernels of both families, scalar
// clears every kernel flag, and the amd64 tokens keep auto-dispatch.
// Skips when the variable is unset. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set
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
	case "gpr":
		if FusedHasNEON {
			t.Fatal("gpr: FusedHasNEON is still set")
		}
		if x16Owned && HasNEONX16 {
			t.Fatal("gpr: HasNEONX16 is still set")
		}
		if !FusedHasGPR || (x16Owned && !HasGPRX16) {
			t.Fatalf("gpr: GPR arms disarmed (fused=%v fill=%v)", FusedHasGPR, HasGPRX16)
		}
	case "scalar":
		if FusedHasNEON {
			t.Fatal("scalar: FusedHasNEON is still set")
		}
		if x16Owned && HasNEONX16 {
			t.Fatal("scalar: HasNEONX16 is still set")
		}
		if FusedHasGPR || (x16Owned && HasGPRX16) {
			t.Fatalf("scalar: GPR arms armed (fused=%v fill=%v)", FusedHasGPR, HasGPRX16)
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16 flag
// carries the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER names on arm64:
// neon arms the NEON batch-16 arm, gpr selects the GPR batch-16 arm
// alone, and scalar clears both.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "neon":
		if !HasNEONX16 {
			t.Fatal("neon: HasNEONX16 is false")
		}
	case "gpr":
		if HasNEONX16 {
			t.Fatal("gpr: HasNEONX16 is still set")
		}
		if !HasGPRX16 {
			t.Fatal("gpr: batch-16 GPR arm disarmed")
		}
	case "scalar":
		if HasNEONX16 {
			t.Fatal("scalar: HasNEONX16 is still set")
		}
		if HasGPRX16 {
			t.Fatal("scalar: batch-16 GPR arm armed")
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s batch-16 tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceTiersKeepGPR asserts that every token other than scalar
// leaves the single-lane GPR arms armed: the GPR kernels are the
// single-lane arm of every tier.
func TestForceTiersKeepGPR(t *testing.T) {
	if forcetier.HashTier() == "scalar" {
		t.Skip("scalar clears the GPR arms; asserted by TestForceHashTierApplied")
	}
	if !FusedHasGPR {
		t.Fatalf("ITB_FORCE_HASH_TIER=%q cleared FusedHasGPR", forcetier.HashTier())
	}
	if forcetier.InterlockPRFFillTier() != "scalar" && !HasGPRX16 {
		t.Fatalf("ITB_FORCE_INTERLOCK_PRF_FILL_TIER=%q cleared HasGPRX16", forcetier.InterlockPRFFillTier())
	}
}
