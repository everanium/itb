//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceInterlockTierApplied asserts that the dispatch flags carry
// the state ITB_FORCE_INTERLOCK_TIER names, for every recognised token,
// on silicon that can execute the forced arm. Skips when the variable
// is unset (auto-dispatch) or when the host cannot honour the token, so
// it is a no-op in an ordinary test run and becomes the probe when the
// parity harness or a forced-tier sweep sets the variable.
func TestForceInterlockTierApplied(t *testing.T) {
	tier := forcetier.InterlockTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_TIER unset; auto-dispatch")
	case "avx512":
		if !cpu.X86.HasAVX512F {
			t.Skip("avx512 tier not executable on this host")
		}
		if !HasAVX512RankMask {
			t.Fatal("avx512: HasAVX512RankMask is false")
		}
	case "avx512x8":
		if !cpu.X86.HasAVX512F {
			t.Skip("avx512x8 tier not executable on this host")
		}
		if !HasAVX512RankMask {
			t.Fatal("avx512x8: HasAVX512RankMask is false")
		}
		if UseUnrank16 {
			t.Fatal("avx512x8: UseUnrank16 is still set; the 16-chunk superblock would run the 16-lane kernel")
		}
	case "avx2":
		if !cpu.X86.HasAVX2 || !cpu.X86.HasBMI2 {
			t.Skip("avx2 tier not executable on this host")
		}
		if !HasAVX2RankMask || HasAVX512RankMask {
			t.Fatalf("avx2: HasAVX2RankMask=%v HasAVX512RankMask=%v, want true/false", HasAVX2RankMask, HasAVX512RankMask)
		}
	case "scalar":
		if HasAVX512RankMask || HasAVX2RankMask || HasBMI2 {
			t.Fatalf("scalar: HasAVX512RankMask=%v HasAVX2RankMask=%v HasBMI2=%v, want all false",
				HasAVX512RankMask, HasAVX2RankMask, HasBMI2)
		}
	case "sve2", "sve", "neon":
		t.Skipf("%s: arm64-only tier; not applicable on amd64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
