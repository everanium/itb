//go:build arm64 && !purego && !noitbasm

package areionasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the arm64 dispatch flags carry
// the state ITB_FORCE_HASH_TIER names: neon, sve2 and sve select the
// crypto-extension kernels of every family, scalar clears them, and gpr
// and the amd64 tokens keep auto-dispatch (this family has no gpr arm
// on arm64). When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set the
// batch-16 flag belongs to that variable.
func TestForceHashTierApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "neon", "sve2", "sve":
		if !aes.CPU.HasARMCrypto {
			t.Skipf("%s tier not executable on this host", tier)
		}
		if !FusedHasARMAES || !HasARMAESBatched {
			t.Fatalf("%s: fused=%v batched=%v, want true/true", tier, FusedHasARMAES, HasARMAESBatched)
		}
		if x16Owned && !HasARMAESX16 {
			t.Fatalf("%s: HasARMAESX16 is false", tier)
		}
	case "scalar":
		if FusedHasARMAES || HasARMAESBatched {
			t.Fatal("scalar: a kernel flag is still set")
		}
		if x16Owned && HasARMAESX16 {
			t.Fatal("scalar: HasARMAESX16 is still set")
		}
	case "gpr":
		if FusedHasARMAES != aes.CPU.HasARMCrypto || HasARMAESBatched != aes.CPU.HasARMCrypto {
			t.Fatalf("gpr: fused=%v batched=%v, want %v/%v (no arm in this family; auto-dispatch kept)",
				FusedHasARMAES, HasARMAESBatched, aes.CPU.HasARMCrypto, aes.CPU.HasARMCrypto)
		}
		if x16Owned && HasARMAESX16 != aes.CPU.HasARMCrypto {
			t.Fatalf("gpr: HasARMAESX16=%v, want %v (no arm in this family; auto-dispatch kept)", HasARMAESX16, aes.CPU.HasARMCrypto)
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16 flag
// carries the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER names: neon arms
// the NEON batch-16 arm, scalar clears it, and gpr names no arm of this
// family and keeps the state the hash tier left.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "neon":
		if !aes.CPU.HasARMCrypto {
			t.Skip("neon batch-16 tier not executable on this host")
		}
		if !HasARMAESX16 {
			t.Fatal("neon: HasARMAESX16 is false")
		}
	case "scalar":
		if HasARMAESX16 {
			t.Fatal("scalar: HasARMAESX16 is still set")
		}
	case "gpr":
		if want := fillFlagFromHashTier(); HasARMAESX16 != want {
			t.Fatalf("gpr: HasARMAESX16=%v, want %v (no arm in this family; hash tier state kept)", HasARMAESX16, want)
		}
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s batch-16 tier keeps auto-dispatch on arm64", tier)
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
	return aes.CPU.HasARMCrypto
}
