//go:build arm64 && !purego && !noitbasm

package blake2sasm

import (
	"testing"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the fused and batch-16 dispatch
// flags carry the state ITB_FORCE_HASH_TIER names on arm64: neon, sve2
// and sve are equivalent (all select the NEON kernels of both families
// and keep the GPR kernels armed), gpr clears the NEON flags and arms
// the GPR kernels of both families, scalar clears every kernel flag,
// and the amd64 tokens keep auto-dispatch. The amd64 tier flags stay
// false under every token. Skips when the variable is unset
// (auto-dispatch) or when the host cannot honour the token. When
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set the batch-16 flags
// belong to that variable and are checked by
// TestForceInterlockPRFFillTierApplied instead.
func TestForceHashTierApplied(t *testing.T) {
	tier := forcetier.HashTier()
	x16Owned := forcetier.InterlockPRFFillTier() == ""
	want := func(neon, gpr bool) {
		t.Helper()
		if FusedHasAVX512 || FusedHasAVX2 || HasAVX512X16 || HasAVX2X16 {
			t.Fatalf("%s: amd64 flags armed on arm64 (fused avx512=%v avx2=%v, batch-16 avx512=%v avx2=%v)",
				tier, FusedHasAVX512, FusedHasAVX2, HasAVX512X16, HasAVX2X16)
		}
		if FusedHasNEON != neon || FusedHasGPR != gpr {
			t.Fatalf("%s: fused flags neon=%v gpr=%v, want %v/%v", tier, FusedHasNEON, FusedHasGPR, neon, gpr)
		}
		if x16Owned && (HasNEONX16 != neon || HasGPRX16 != gpr) {
			t.Fatalf("%s: batch-16 flags neon=%v gpr=%v, want %v/%v", tier, HasNEONX16, HasGPRX16, neon, gpr)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "neon", "sve2", "sve":
		if !cpuid.ASIMD {
			t.Skipf("%s tier not executable on this host", tier)
		}
		want(true, true)
	case "gpr":
		want(false, true)
	case "scalar":
		want(false, false)
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		want(cpuid.ASIMD, true)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceInterlockPRFFillTierApplied asserts that the batch-16
// dispatch flags carry the state ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// names on arm64 — regardless of what ITB_FORCE_HASH_TIER is set to,
// since the batch-16 variable is applied after and independently of the
// hash tier variable. neon arms the NEON batch-16 arm and leaves the GPR
// batch-16 arm as the hash tier left it, gpr selects the GPR batch-16
// arm alone, scalar clears both, and the amd64 tokens keep the state
// the hash tier left. Skips when the variable is unset or the host
// cannot honour the token.
func TestForceInterlockPRFFillTierApplied(t *testing.T) {
	tier := forcetier.InterlockPRFFillTier()
	want := func(neon, gpr bool) {
		t.Helper()
		if HasAVX512X16 || HasAVX2X16 {
			t.Fatalf("%s: amd64 batch-16 flags armed on arm64 (avx512=%v avx2=%v)", tier, HasAVX512X16, HasAVX2X16)
		}
		if HasNEONX16 != neon || HasGPRX16 != gpr {
			t.Fatalf("%s: batch-16 flags neon=%v gpr=%v, want %v/%v", tier, HasNEONX16, HasGPRX16, neon, gpr)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_TIER unset; auto-dispatch")
	case "neon":
		if !cpuid.ASIMD {
			t.Skip("neon batch-16 tier not executable on this host")
		}
		_, gpr := fillFlagsFromHashTier()
		want(true, gpr)
	case "gpr":
		want(false, true)
	case "scalar":
		want(false, false)
	case "avx512", "vaesavx2", "avx2", "vex", "aesni":
		want(fillFlagsFromHashTier())
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// fillFlagsFromHashTier returns the batch-16 flag pair
// ITB_FORCE_HASH_TIER leaves behind on arm64 — the state a batch-16
// token that names no arm of this family keeps.
func fillFlagsFromHashTier() (neon, gpr bool) {
	switch forcetier.HashTier() {
	case "gpr":
		return false, true
	case "scalar":
		return false, false
	}
	return cpuid.ASIMD, true
}

// TestForceTiersKeepGPR asserts that every token other than scalar
// leaves the single-lane GPR arms armed: the GPR kernels are the
// single-lane arm of every tier.
func TestForceTiersKeepGPR(t *testing.T) {
	if forcetier.HashTier() == "scalar" {
		t.Skip("scalar clears the GPR arms; asserted by TestForceHashTierApplied")
	}
	if !FusedHasGPR {
		t.Fatalf("ITB_FORCE_HASH_TIER=%q cleared FusedHasGPR", forcetier.HashTier())
	}
	if forcetier.InterlockPRFFillTier() != "scalar" && !HasGPRX16 {
		t.Fatalf("ITB_FORCE_INTERLOCK_PRF_FILL_TIER=%q cleared HasGPRX16", forcetier.InterlockPRFFillTier())
	}
}
