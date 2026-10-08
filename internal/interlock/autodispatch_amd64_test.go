//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"testing"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// TestAutoDispatchFollowsBMI2 asserts that every auto-selected arm
// executing PEXTQ / PDEPQ is gated on BMI2. Skips under
// ITB_FORCE_INTERLOCK_TIER, which overrides the auto values.
func TestAutoDispatchFollowsBMI2(t *testing.T) {
	if forcetier.InterlockTier() != "" {
		t.Skip("ITB_FORCE_INTERLOCK_TIER set; auto values overridden")
	}
	t.Logf("vendor=%q family=%#x BMI2=%v", cpuid.X86Vendor, cpuid.X86Family, cpuid.BMI2)
	checks := []struct {
		name      string
		got, want bool
	}{
		{"HasBMI2", HasBMI2, cpuid.BMI2},
		{"HasChunk48Batch", HasChunk48Batch, cpuid.BMI2},
		{"HasAVX512RankMask", HasAVX512RankMask, cpuid.AVX512F && cpuid.BMI2},
		{"HasAVX2RankMask", HasAVX2RankMask, cpuid.AVX2 && cpuid.BMI2 && !cpuid.AVX512F},
		{"UseUnrank16", UseUnrank16, cpuid.AVX512F && cpuid.BMI2},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
