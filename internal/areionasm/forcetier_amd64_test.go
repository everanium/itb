//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"testing"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the fused and batch-16 dispatch
// flags carry the state ITB_FORCE_HASH_TIER names, for every recognised
// token, on silicon that can execute the forced arm. Skips when the
// variable is unset (auto-dispatch) or when the host cannot honour the
// token. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set the batch-16
// flags belong to that variable and are checked by
// TestForceInterlockPRFFillTierApplied instead.
func TestForceHashTierApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	want := func(zmm, ymm, vex, xmm bool) {
		t.Helper()
		if FusedHasVAESAVX512 != zmm || FusedHasVAESAVX2 != ymm || FusedHasAVXAESNI != vex || FusedHasAESNI != xmm {
			t.Fatalf("%s: fused flags zmm=%v ymm=%v vex=%v xmm=%v, want %v/%v/%v/%v",
				tier, FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI, zmm, ymm, vex, xmm)
		}
		if x16Owned && (HasVAESAVX512X16 != zmm || HasVAESAVX2X16 != ymm || HasAVXAESNIX16 != vex || HasAESNIX16 != xmm) {
			t.Fatalf("%s: batch-16 flags zmm=%v ymm=%v vex=%v xmm=%v, want %v/%v/%v/%v",
				tier, HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16, zmm, ymm, vex, xmm)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !cpuid.VAESZMM {
			t.Skip("avx512 tier not executable on this host")
		}
		want(true, false, false, false)
	case "vaesavx2":
		if !cpuid.VAESYMM {
			t.Skip("vaesavx2 tier not executable on this host")
		}
		want(false, true, false, false)
	case "avx2":
		if !cpuid.VAESYMM {
			t.Skip("avx2 tier not executable on this host")
		}
		// The arms-only probe: the YMM batched permutation, fused
		// cascade and batch-16 fill off.
		want(false, false, false, false)
		if !HasVAESAVX2NoAVX512 || HasVAESAVX512 {
			t.Fatalf("avx2: arm flags ymm=%v zmm=%v, want true/false", HasVAESAVX2NoAVX512, HasVAESAVX512)
		}
	case "vex":
		if !cpuid.AESNI || !cpuid.AVX2 {
			t.Skip("vex tier not executable on this host")
		}
		want(false, false, true, false)
	case "aesni":
		if !cpuid.AESNI {
			t.Skip("aesni tier not executable on this host")
		}
		want(false, false, false, true)
	case "scalar":
		want(false, false, false, false)
	case "gpr":
		t.Skip("gpr: no arm in this family; auto-dispatch kept (asserted by the hashes dispatch matrix)")
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
	want := func(zmm, ymm, vex, xmm bool) {
		t.Helper()
		if HasVAESAVX512X16 != zmm || HasVAESAVX2X16 != ymm || HasAVXAESNIX16 != vex || HasAESNIX16 != xmm {
			t.Fatalf("%s: batch-16 flags zmm=%v ymm=%v vex=%v xmm=%v, want %v/%v/%v/%v",
				tier, HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16, zmm, ymm, vex, xmm)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "avx512":
		if !cpuid.VAESZMM {
			t.Skip("avx512 batch-16 tier not executable on this host")
		}
		want(true, false, false, false)
	case "vaesavx2":
		if !cpuid.VAESYMM {
			t.Skip("vaesavx2 batch-16 tier not executable on this host")
		}
		want(false, true, false, false)
	case "vex":
		if !cpuid.AESNI || !cpuid.AVX2 {
			t.Skip("vex batch-16 tier not executable on this host")
		}
		want(false, false, true, false)
	case "aesni":
		if !cpuid.AESNI {
			t.Skip("aesni batch-16 tier not executable on this host")
		}
		want(false, false, false, true)
	case "avx2", "scalar":
		want(false, false, false, false)
	case "gpr":
		t.Skip("gpr: no batch-16 arm in this family; auto-dispatch kept")
	case "neon":
		t.Skip("neon batch-16 tier is arm64-only")
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
