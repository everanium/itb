package cpuid

import "testing"

// TestBMI2Fast pins the microcoded-PEXT exclusion: AMD and Hygon parts
// below family 0x19 report false, everything else with BMI2 reports true.
func TestBMI2Fast(t *testing.T) {
	cases := []struct {
		bmi2   bool
		vendor string
		family int
		want   bool
	}{
		{true, "Intel", 0x6, true},
		{true, "AMD", 0x15, false}, // Excavator
		{true, "AMD", 0x17, false}, // Zen 1 / Zen 2
		{true, "Hygon", 0x18, false},
		{true, "AMD", 0x19, true}, // Zen 3 / Zen 4
		{true, "AMD", 0x1A, true}, // Zen 5
		{true, "VendorUnknown", 0x17, true},
		{false, "Intel", 0x6, false},
		{false, "AMD", 0x19, false},
	}
	for _, c := range cases {
		if got := bmi2Fast(c.bmi2, c.vendor, c.family); got != c.want {
			t.Errorf("bmi2Fast(%v, %q, %#x) = %v, want %v", c.bmi2, c.vendor, c.family, got, c.want)
		}
	}
}

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
	if BMI2Fast && !BMI2 {
		t.Error("BMI2Fast without BMI2")
	}
	if (AVX512BW || AVX512VL || AVX512DQ) && !AVX512F {
		t.Error("AVX-512 subset without AVX512F")
	}
	t.Logf("SSE2=%v AESNI=%v AVX2=%v AVX512F=%v BW=%v VL=%v DQ=%v VAESYMM=%v VAESZMM=%v BMI2=%v BMI2Fast=%v vendor=%q family=%#x ASIMD=%v ARMAES=%v SVE2BitPerm=%v",
		SSE2, AESNI, AVX2, AVX512F, AVX512BW, AVX512VL, AVX512DQ, VAESYMM, VAESZMM, BMI2, BMI2Fast, X86Vendor, X86Family, ASIMD, ARMAES, SVE2BitPerm)
}
