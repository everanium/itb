package cpuid

import "testing"

// TestVAESUsable pins that the raw VAES bit never stands alone.
func TestVAESUsable(t *testing.T) {
	for _, c := range []struct{ vaes, state, want bool }{
		{true, true, true}, {true, false, false}, {false, true, false}, {false, false, false},
	} {
		if got := vaesUsable(c.vaes, c.state); got != c.want {
			t.Errorf("vaesUsable(%v, %v) = %v, want %v", c.vaes, c.state, got, c.want)
		}
	}
}

// TestFieldImplications checks the relations every host must satisfy.
func TestFieldImplications(t *testing.T) {
	if VAESYMM && !AVX2 {
		t.Error("VAESYMM without AVX2")
	}
	if VAESZMM && !AVX512F {
		t.Error("VAESZMM without AVX512F")
	}
	if VAESZMM && !VAESYMM {
		t.Error("VAESZMM without VAESYMM")
	}
	if (AVX512BW || AVX512VL || AVX512DQ) && !AVX512F {
		t.Error("AVX-512 subset without AVX512F")
	}
	t.Logf("SSE2=%v AESNI=%v AVX2=%v AVX512F=%v BW=%v VL=%v DQ=%v VAESYMM=%v VAESZMM=%v BMI2=%v vendor=%q family=%#x ASIMD=%v ARMAES=%v SVE2BitPerm=%v",
		SSE2, AESNI, AVX2, AVX512F, AVX512BW, AVX512VL, AVX512DQ, VAESYMM, VAESZMM, BMI2, X86Vendor, X86Family, ASIMD, ARMAES, SVE2BitPerm)
}
