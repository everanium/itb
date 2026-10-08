//go:build arm64

package cpuid

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestMatchesXSys checks the arm64 fields against golang.org/x/sys/cpu.
func TestMatchesXSys(t *testing.T) {
	if ASIMD != cpu.ARM64.HasASIMD {
		t.Errorf("ASIMD = %v, x/sys = %v", ASIMD, cpu.ARM64.HasASIMD)
	}
	if ARMAES != cpu.ARM64.HasAES {
		t.Errorf("ARMAES = %v, x/sys = %v", ARMAES, cpu.ARM64.HasAES)
	}
	if SVE2BitPerm && !cpu.ARM64.HasSVE2 {
		t.Error("SVE2BitPerm without x/sys HasSVE2")
	}
	if SSE2 || AESNI || AVX2 || AVX512F || VAESYMM || VAESZMM || BMI2 {
		t.Error("x86 field set on arm64")
	}
}
