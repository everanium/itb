//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the fused and batch-16
// dispatch flags carry the state ITB_FORCE_HASH_TIER names,
// for every recognised token, on silicon that can execute the forced
// arm. Skips when the variable is unset (auto-dispatch) or when the host
// cannot honour the token, so it is a no-op in an ordinary test run and
// becomes the probe when the parity harness or a forced-tier sweep sets
// the variable. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set the
// batch-16 flags belong to that variable and are checked by
// TestForceInterlockPRFFillTierApplied instead.
func TestForceHashTierApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	want := func(zmm, ymm, vex, aesni bool) {
		t.Helper()
		if FusedHasVAESAVX512 != zmm || FusedHasVAESAVX2 != ymm || FusedHasAVXAESNI != vex || FusedHasAESNI != aesni {
			t.Fatalf("%s: fused flags zmm=%v ymm=%v vex=%v aesni=%v, want %v/%v/%v/%v",
				tier, FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI, zmm, ymm, vex, aesni)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			t.Skip("avx512 tier not executable on this host")
		}
		want(true, false, false, false)
	case "vaesavx2", "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			t.Skip("vaesavx2 tier not executable on this host")
		}
		want(false, true, false, false)
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			t.Skip("vex tier not executable on this host")
		}
		want(false, false, true, false)
	case "aesni":
		if !aes.CPU.HasAESNI {
			t.Skip("aesni tier not executable on this host")
		}
		want(false, false, false, true)
	case "scalar":
		want(false, false, false, false)
		if x16Owned && (HasVAESAVX512X16 || HasVAESAVX2X16 || HasAVXAESNIX16 || HasAESNIX16) {
			t.Fatalf("scalar: batch-16 flags zmm=%v ymm=%v vex=%v aesni=%v, want all false",
				HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16)
		}
	case "sve2", "sve", "neon":
		t.Skipf("%s: arm64-only tier; not applicable on amd64", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16
// dispatch flags carry the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// names, for every recognised token, on silicon that can execute the
// forced arm — regardless of what ITB_FORCE_HASH_TIER is set to, since
// the batch-16 variable is applied after and independently of the hash
// tier variable. Skips when the variable is unset or the host cannot
// honour the token.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	want := func(zmm, ymm, vex, aesni bool) {
		t.Helper()
		if HasVAESAVX512X16 != zmm || HasVAESAVX2X16 != ymm || HasAVXAESNIX16 != vex || HasAESNIX16 != aesni {
			t.Fatalf("%s: batch-16 flags zmm=%v ymm=%v vex=%v aesni=%v, want %v/%v/%v/%v",
				tier, HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16, zmm, ymm, vex, aesni)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			t.Skip("avx512 batch-16 tier not executable on this host")
		}
		want(true, false, false, false)
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			t.Skip("vaesavx2 batch-16 tier not executable on this host")
		}
		want(false, true, false, false)
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			t.Skip("vex batch-16 tier not executable on this host")
		}
		want(false, false, true, false)
	case "aesni":
		if !aes.CPU.HasAESNI {
			t.Skip("aesni batch-16 tier not executable on this host")
		}
		want(false, false, false, true)
	case "neon":
		t.Skip("neon batch-16 tier is arm64-only")
	case "scalar":
		want(false, false, false, false)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
