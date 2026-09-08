//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"

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
	want := func(zmm, ymm, xmm bool) {
		t.Helper()
		if FusedHasVAESAVX512 != zmm || FusedHasVAESAVX2 != ymm || FusedHasAESNI != xmm {
			t.Fatalf("%s: fused flags zmm=%v ymm=%v xmm=%v, want %v/%v/%v",
				tier, FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI, zmm, ymm, xmm)
		}
		if x16Owned && (HasVAESAVX512X16 != zmm || HasVAESAVX2X16 != ymm || HasAESNIX16 != xmm) {
			t.Fatalf("%s: batch-16 flags zmm=%v ymm=%v xmm=%v, want %v/%v/%v",
				tier, HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16, zmm, ymm, xmm)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			t.Skip("avx512 tier not executable on this host")
		}
		want(true, false, false)
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			t.Skip("vaesavx2 tier not executable on this host")
		}
		want(false, true, false)
	case "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			t.Skip("avx2 tier not executable on this host")
		}
		// The arms-only probe: the YMM batched permutation, fused
		// cascade and batch-16 fill off.
		want(false, false, false)
		if !HasVAESAVX2NoAVX512 || HasVAESAVX512 {
			t.Fatalf("avx2: arm flags ymm=%v zmm=%v, want true/false", HasVAESAVX2NoAVX512, HasVAESAVX512)
		}
	case "vex", "aesni":
		if !aes.CPU.HasAESNI {
			t.Skipf("%s tier not executable on this host", tier)
		}
		want(false, false, true)
	case "scalar":
		want(false, false, false)
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
	want := func(zmm, ymm, xmm bool) {
		t.Helper()
		if HasVAESAVX512X16 != zmm || HasVAESAVX2X16 != ymm || HasAESNIX16 != xmm {
			t.Fatalf("%s: batch-16 flags zmm=%v ymm=%v xmm=%v, want %v/%v/%v",
				tier, HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16, zmm, ymm, xmm)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			t.Skip("avx512 batch-16 tier not executable on this host")
		}
		want(true, false, false)
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			t.Skip("vaesavx2 batch-16 tier not executable on this host")
		}
		want(false, true, false)
	case "vex", "aesni":
		if !aes.CPU.HasAESNI {
			t.Skipf("%s batch-16 tier not executable on this host", tier)
		}
		want(false, false, true)
	case "avx2", "scalar":
		want(false, false, false)
	case "neon":
		t.Skip("neon batch-16 tier is arm64-only")
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}
