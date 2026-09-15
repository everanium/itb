//go:build amd64 && !purego && !noitbasm

package blake2sasm

import (
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// TestForceHashTierApplied asserts that the fused and batch-16
// dispatch flags carry the state ITB_FORCE_HASH_TIER names, for every
// recognised token, on silicon that can execute the forced arm. Skips
// when the variable is unset (auto-dispatch) or when the host cannot
// honour the token. When ITB_FORCE_INTERLOCK_PRF_FILL_TIER is also set
// the batch-16 flags belong to that variable and are checked by
// TestForceInterlockPRFFillTierApplied instead.
func TestForceHashTierApplied(t *testing.T) {
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
	case "gpr":
		want(false, false)
		if !FusedHasGPR || (x16Owned && !HasGPRX16) {
			t.Fatalf("gpr: GPR arms disarmed (fused=%v fill=%v)", FusedHasGPR, HasGPRX16)
		}
	case "scalar":
		want(false, false)
		if FusedHasGPR || (x16Owned && HasGPRX16) {
			t.Fatalf("scalar: GPR arms armed (fused=%v fill=%v)", FusedHasGPR, HasGPRX16)
		}
	case "aesni", "vaesavx2":
		want(cpu.X86.HasAVX512F, cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F)
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
	case "avx2", "vex":
		if !cpu.X86.HasAVX2 {
			t.Skipf("%s batch-16 tier not executable on this host", tier)
		}
		want(false, true)
	case "gpr":
		want(false, false)
		if !HasGPRX16 {
			t.Fatal("gpr: batch-16 GPR arm disarmed")
		}
	case "scalar":
		want(false, false)
		if HasGPRX16 {
			t.Fatal("scalar: batch-16 GPR arm armed")
		}
	case "aesni", "vaesavx2":
		want(fillFlagsFromHashTier())
	case "neon":
		t.Skip("neon batch-16 tier is arm64-only")
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// TestForceChainHashX4Applied asserts that ITB_FORCE_CHAINHASH_X4 disarms
// the eight-lane per-pixel arm: the flag is false and the eight-lane
// dispatchers run the four-lane kernels. Skips when the variable is
// unset.
func TestForceChainHashX4Applied(t *testing.T) {
	if !forcetier.ChainHashX4() {
		t.Skip("ITB_FORCE_CHAINHASH_X4 unset")
	}
	if FusedHasAVX512X8 || FusedX8Active() {
		t.Fatalf("ITB_FORCE_CHAINHASH_X4: eight-lane arm armed (flag=%v active=%v)", FusedHasAVX512X8, FusedX8Active())
	}
}

// fillFlagsFromHashTier returns the batch-16 flag pair
// ITB_FORCE_HASH_TIER leaves behind — the state a batch-16 token that
// names no arm of this family keeps.
func fillFlagsFromHashTier() (avx512, avx2 bool) {
	switch forcetier.HashTier() {
	case "avx512":
		if cpu.X86.HasAVX512F {
			return true, false
		}
	case "avx2", "vex":
		if cpu.X86.HasAVX2 {
			return false, true
		}
	case "scalar":
		return false, false
	}
	return cpu.X86.HasAVX512F, cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F
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
