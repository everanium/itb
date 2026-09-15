//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the arm64 dispatch flags carry
// the state ITB_FORCE_HASH_TIER names: neon, sve2 and sve are
// equivalent (all select the NEON kernels of both families), scalar
// clears them, and the amd64 tokens keep auto-dispatch. Skips when the
// variable is unset or when the host cannot honour the token. When
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set the batch-16 flag
// belongs to that variable and is not checked here.
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
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		t.Skipf("%s tier keeps auto-dispatch on arm64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
