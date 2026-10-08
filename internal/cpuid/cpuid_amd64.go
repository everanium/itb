//go:build amd64

package cpuid

import kcpuid "github.com/klauspost/cpuid/v2"

func init() {
	c := &kcpuid.CPU
	SSE2 = c.Supports(kcpuid.SSE2)
	AESNI = c.Supports(kcpuid.AESNI)
	AVX2 = c.Supports(kcpuid.AVX2)
	AVX512F = c.Supports(kcpuid.AVX512F)
	AVX512BW = c.Supports(kcpuid.AVX512BW)
	AVX512VL = c.Supports(kcpuid.AVX512VL)
	AVX512DQ = c.Supports(kcpuid.AVX512DQ)
	vaes := c.Supports(kcpuid.VAES)
	VAESYMM = vaesUsable(vaes, AVX2)
	VAESZMM = vaesUsable(vaes, AVX512F)
	BMI2 = c.Supports(kcpuid.BMI2)
	X86Vendor = c.VendorID.String()
	X86Family = c.Family
	BMI2Fast = bmi2Fast(BMI2, X86Vendor, X86Family)
}
