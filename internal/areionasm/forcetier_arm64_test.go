//go:build arm64 && !purego && !noitbasm

package areionasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the arm64 dispatch flags carry
// the state ITB_FORCE_HASH_TIER names: neon, sve2 and sve select the
// crypto-extension kernels of every family, scalar clears them, and the
// amd64 tokens keep auto-dispatch. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// is also set the batch-16 flag belongs to that variable.
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
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16 flag
// carries the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER names.
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
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s batch-16 tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
