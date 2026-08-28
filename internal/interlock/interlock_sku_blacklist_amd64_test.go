//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/klauspost/cpuid/v2"
)

// TestIsSPRFamilyModel covers the family / model matcher directly so
// the blacklist table is verifiable without mocking the global cpuid
// state. Every entry that is or is not Sapphire Rapids / Emerald
// Rapids gets an assertion, plus representative negatives for
// adjacent Xeon Scalable generations so a future edit that widens
// the switch too far triggers a test failure.
func TestIsSPRFamilyModel(t *testing.T) {
	cases := []struct {
		name        string
		family      int
		model       int
		blacklisted bool
	}{
		// Blacklisted — same Golden Cove Server microarchitecture.
		{"SapphireRapidsSP", 6, 0x8F, true},
		{"EmeraldRapids", 6, 0xCF, true},

		// NOT blacklisted — different microarchitectures.
		{"IceLakeSP", 6, 0x6A, false},         // Sunny Cove Server
		{"CascadeLake", 6, 0x55, false},       // Skylake-X derivative
		{"RocketLake", 6, 0xA7, false},        // Cypress Cove
		{"AlderLakeP", 6, 0x97, false},        // Golden Cove client
		{"RaptorLakeP", 6, 0xB7, false},       // Raptor Cove
		{"GraniteRapids", 6, 0xAD, false},     // Redwood Cove Server (new P-core)
		{"MeteorLake", 6, 0xAA, false},        // Redwood Cove client
		{"TigerLake", 6, 0x8C, false},         // Willow Cove
		{"SapphireRapidsWSNear", 6, 0x8E, false}, // Client Kaby / Coffee — model close to 0x8F but different arch

		// Not family 6 — nothing modern here.
		{"NonFamily6_SPRModel", 15, 0x8F, false},
		{"NonFamily6_EMRModel", 5, 0xCF, false},

		// Zero / edge values.
		{"Zero", 0, 0, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := isSPRFamilyModel(tc.family, tc.model)
			if got != tc.blacklisted {
				t.Fatalf("isSPRFamilyModel(family=%d, model=0x%X) = %v; want %v",
					tc.family, tc.model, got, tc.blacklisted)
			}
		})
	}
}

// TestBlacklistFlagConsistencyOnCurrentCPU exercises the observable
// package-level flags on whatever silicon the test runs on. On a
// blacklisted CPU HasAVX512RankMask must be false and — if the CPU
// still carries AVX2 + BMI2 — HasAVX2RankMask must be true. On any
// non-blacklisted CPU the flags must equal the un-overridden CPUID
// derivation (HasAVX512RankMask == HasAVX512F, and HasAVX2RankMask
// == HasAVX2 && HasBMI2 && !HasAVX512F). Test is a sanity check for
// the init override behaviour on the CI host, complementing the
// table-driven unit test above.
func TestBlacklistFlagConsistencyOnCurrentCPU(t *testing.T) {
	if cpuid.CPU.VendorID == cpuid.Intel && isSPRFamilyModel(cpuid.CPU.Family, cpuid.CPU.Model) {
		if HasAVX512RankMask {
			t.Fatal("blacklisted SPR/EMR silicon must have HasAVX512RankMask=false")
		}
		if cpu.X86.HasAVX2 && cpu.X86.HasBMI2 && !HasAVX2RankMask {
			t.Fatal("blacklisted SPR/EMR silicon with AVX2+BMI2 must have HasAVX2RankMask=true")
		}
		return
	}
	// Non-blacklisted path: flags mirror CPUID.
	if HasAVX512RankMask != cpu.X86.HasAVX512F {
		t.Fatalf("non-blacklisted CPU: HasAVX512RankMask=%v, want cpu.X86.HasAVX512F=%v",
			HasAVX512RankMask, cpu.X86.HasAVX512F)
	}
	wantAVX2 := cpu.X86.HasAVX2 && cpu.X86.HasBMI2 && !cpu.X86.HasAVX512F
	if HasAVX2RankMask != wantAVX2 {
		t.Fatalf("non-blacklisted CPU: HasAVX2RankMask=%v, want %v",
			HasAVX2RankMask, wantAVX2)
	}
}
