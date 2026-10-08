//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"testing"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// TestAutoDispatchFollowsBMI2Fast asserts that every auto-selected arm
// executing PEXTQ / PDEPQ is gated on hardware BMI2: hosts that run the
// two instructions in microcode (AMD before Zen 3, Hygon) keep the
// pure-Go softPEXT48 / softPDEP48 and scalar rank-unrank paths. Skips
// under ITB_FORCE_INTERLOCK_TIER, which overrides the auto values.
func TestAutoDispatchFollowsBMI2Fast(t *testing.T) {
	if forcetier.InterlockTier() != "" {
		t.Skip("ITB_FORCE_INTERLOCK_TIER set; auto values overridden")
	}
	t.Logf("vendor=%q family=%#x BMI2=%v BMI2Fast=%v", cpuid.X86Vendor, cpuid.X86Family, cpuid.BMI2, cpuid.BMI2Fast)
	checks := []struct {
		name      string
		got, want bool
	}{
		{"HasBMI2", HasBMI2, cpuid.BMI2Fast},
		{"HasChunk48Batch", HasChunk48Batch, cpuid.BMI2Fast},
		{"HasAVX512RankMask", HasAVX512RankMask, cpuid.AVX512F && cpuid.BMI2Fast},
		{"HasAVX2RankMask", HasAVX2RankMask, cpuid.AVX2 && cpuid.BMI2Fast && !cpuid.AVX512F},
		{"UseUnrank16", UseUnrank16, cpuid.AVX512F && cpuid.BMI2Fast},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
