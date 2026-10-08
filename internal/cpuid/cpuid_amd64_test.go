//go:build amd64

package cpuid

import (
	"testing"

	kcpuid "github.com/klauspost/cpuid/v2"
	"golang.org/x/sys/cpu"
)

// TestDetectionNotEmpty fails when the amd64 backend reports no feature
// at all. SSE2 is architectural on amd64, so a false value means the
// detection was compiled out (the klauspost/cpuid noasm, gccgo and
// appengine tags zero every flag) and every kernel family would fall
// back to scalar Go without notice.
func TestDetectionNotEmpty(t *testing.T) {
	if !SSE2 {
		t.Fatal("SSE2 reported false on amd64: CPU feature detection is compiled out (is the build using the noasm tag?)")
	}
}

// TestMatchesXSys checks every field against golang.org/x/sys/cpu,
// which reads the same CPUID / XGETBV state independently. VAESZMM is
// the x/sys HasAVX512VAES field (set only under AVX-512 OS state);
// VAESYMM has no x/sys counterpart and is checked against the raw bit.
func TestMatchesXSys(t *testing.T) {
	pairs := []struct {
		name      string
		got, want bool
	}{
		{"SSE2", SSE2, cpu.X86.HasSSE2},
		{"AESNI", AESNI, cpu.X86.HasAES},
		{"AVX2", AVX2, cpu.X86.HasAVX2},
		{"AVX512F", AVX512F, cpu.X86.HasAVX512F},
		{"AVX512BW", AVX512BW, cpu.X86.HasAVX512BW},
		{"AVX512VL", AVX512VL, cpu.X86.HasAVX512VL},
		{"AVX512DQ", AVX512DQ, cpu.X86.HasAVX512DQ},
		{"VAESZMM", VAESZMM, cpu.X86.HasAVX512VAES},
		{"BMI2", BMI2, cpu.X86.HasBMI2},
		{"VAESYMM", VAESYMM, kcpuid.CPU.Supports(kcpuid.VAES) && cpu.X86.HasAVX2},
		{"ASIMD", ASIMD, false},
		{"ARMAES", ARMAES, false},
		{"SVE2BitPerm", SVE2BitPerm, false},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("%s = %v, x/sys reference = %v", p.name, p.got, p.want)
		}
	}
}

// TestVendorNames pins the vendor spellings bmi2Fast compares against.
func TestVendorNames(t *testing.T) {
	if kcpuid.AMD.String() != vendorAMD || kcpuid.Hygon.String() != vendorHygon {
		t.Fatalf("vendor names changed: %q %q", kcpuid.AMD.String(), kcpuid.Hygon.String())
	}
	if want := bmi2Fast(BMI2, kcpuid.CPU.VendorID.String(), kcpuid.CPU.Family); BMI2Fast != want {
		t.Fatalf("BMI2Fast = %v, want %v", BMI2Fast, want)
	}
}
