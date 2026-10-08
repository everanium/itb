//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the arm64 dispatch flags carry
// the state ITB_FORCE_HASH_TIER names: neon, sve2 and sve are
// equivalent (all select the NEON kernels of both families), scalar
// clears them, and gpr and the amd64 tokens keep auto-dispatch (this
// family has no gpr arm on arm64). Skips when the variable is unset or
// when the host cannot honour the token. When
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set the batch-16 flag
// belongs to that variable and is checked by
// TestForceInterlockPRFFillTierApplied instead.
func TestForceHashTierApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "neon", "sve2", "sve":
		if !cpuid.ARMAES {
			t.Skipf("%s tier not executable on this host", tier)
		}
		if !FusedHasARMAES {
			t.Fatalf("%s: FusedHasARMAES is false", tier)
		}
		if x16Owned && !HasARMAESX16 {
			t.Fatalf("%s: HasARMAESX16 is false", tier)
		}
	case "scalar":
		if FusedHasARMAES {
			t.Fatal("scalar: FusedHasARMAES is still set")
		}
		if x16Owned && HasARMAESX16 {
			t.Fatal("scalar: HasARMAESX16 is still set")
		}
	case "gpr":
		if FusedHasARMAES != cpuid.ARMAES {
			t.Fatalf("gpr: FusedHasARMAES=%v, want %v (no arm in this family; auto-dispatch kept)", FusedHasARMAES, cpuid.ARMAES)
		}
		if x16Owned && HasARMAESX16 != cpuid.ARMAES {
			t.Fatalf("gpr: HasARMAESX16=%v, want %v (no arm in this family; auto-dispatch kept)", HasARMAESX16, cpuid.ARMAES)
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16 flag
// carries the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER names on arm64 —
// regardless of what ITB_FORCE_HASH_TIER is set to, since the batch-16
// variable is applied after and independently of the hash tier
// variable. neon arms the NEON batch-16 arm, scalar clears it, and gpr
// and the amd64 tokens name no arm of this family and keep the state the
// hash tier left. Skips when the variable is unset or the host cannot
// honour the token.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "neon":
		if !cpuid.ARMAES {
			t.Skip("neon batch-16 tier not executable on this host")
		}
		if !HasARMAESX16 {
			t.Fatal("neon: HasARMAESX16 is false")
		}
	case "scalar":
		if HasARMAESX16 {
			t.Fatal("scalar: HasARMAESX16 is still set")
		}
	case "gpr", "avx512", "vaesavx2", "avx2", "vex", "aesni":
		if want := fillFlagFromHashTier(); HasARMAESX16 != want {
			t.Fatalf("%s: HasARMAESX16=%v, want %v (no arm in this family; hash tier state kept)", tier, HasARMAESX16, want)
		}
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// fillFlagFromHashTier returns the batch-16 flag ITB_FORCE_HASH_TIER
// leaves behind on arm64 — the state a batch-16 token that names no arm
// of this family keeps.
func fillFlagFromHashTier() bool {
	if forcetier.HashTier() == "scalar" {
		return false
	}
	return cpuid.ARMAES
}
