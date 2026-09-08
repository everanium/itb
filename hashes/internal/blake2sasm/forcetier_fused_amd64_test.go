//go:build amd64 && !purego && !noitbasm

package blake2sasm

import (
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierFusedApplied asserts that the fused and batch-16
// dispatch flags carry the state ITB_FORCE_HASH_TIER names, for every
// recognised token, on silicon that can execute the forced arm. Skips
// when the variable is unset (auto-dispatch) or when the host cannot
// honour the token. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set
// the batch-16 flags belong to that variable and are checked by
// TestForceInterlockPRFFillTierApplied instead.
func TestForceHashTierFusedApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	want := func(avx512, avx2 bool) {
		t.Helper()
		if FusedHasAVX512 != avx512 || FusedHasAVX2 != avx2 {
			t.Fatalf("%s: fused flags avx512=%v avx2=%v, want %v/%v", tier, FusedHasAVX512, FusedHasAVX2, avx512, avx2)
		}
		if x16Owned && (HasAVX512X16 != avx512 || HasAVX2X16 != avx2) {
			t.Fatalf("%s: batch-16 flags avx512=%v avx2=%v, want %v/%v", tier, HasAVX512X16, HasAVX2X16, avx512, avx2)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !cpu.X86.HasAVX512F {
			t.Skip("avx512 tier not executable on this host")
		}
		want(true, false)
	case "avx2", "vex":
		if !cpu.X86.HasAVX2 {
			t.Skipf("%s tier not executable on this host", tier)
		}
		want(false, true)
	case "aesni", "scalar":
		want(false, false)
	case "vaesavx2":
		t.Skip("vaesavx2: not a BLAKE2s token; auto-dispatch kept")
	case "sve2", "sve", "neon":
		t.Skipf("%s: arm64-only tier; not applicable on amd64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16 dispatch
// flags carry the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER names, for every
// recognised token, on silicon that can execute the forced arm. Skips
// when the variable is unset or the host cannot honour the token.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	want := func(avx512, avx2 bool) {
		t.Helper()
		if HasAVX512X16 != avx512 || HasAVX2X16 != avx2 {
			t.Fatalf("%s: batch-16 flags avx512=%v avx2=%v, want %v/%v", tier, HasAVX512X16, HasAVX2X16, avx512, avx2)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "avx512":
		if !cpu.X86.HasAVX512F {
			t.Skip("avx512 batch-16 tier not executable on this host")
		}
		want(true, false)
	case "avx2", "vex", "vaesavx2":
		if !cpu.X86.HasAVX2 {
			t.Skipf("%s batch-16 tier not executable on this host", tier)
		}
		want(false, true)
	case "aesni", "scalar":
		want(false, false)
	case "neon":
		t.Skip("neon batch-16 tier is arm64-only")
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
