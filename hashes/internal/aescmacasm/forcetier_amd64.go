//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every AES-CMAC dispatch family (fused cascade and the batch-16
// interlock fill), then ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the
// batch-16 family alone, so the second variable can re-select a
// batch-16 arm after the first has scalarised everything. Each variable
// is handled by its own function; a forced arm the silicon cannot
// execute keeps that family's auto-dispatch with a stderr note without
// affecting the other variable.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER. The fused flags are
// assigned as one consistent set. "vaesavx2" and "avx2" both select the
// VAES YMM kernels; "vex" selects the VEX-encoded XMM kernels
// (AVX-encoded AES-NI, one lane per XMM); "aesni" selects the
// legacy-SSE-encoded XMM kernels on AES-NI hosts without AVX. "scalar"
// means no assembly anywhere in this package's dispatch, so it also
// disarms the batch-16 flags; ITB_FORCE_INTERLOCK_PRF_FILL_TIER, applied
// afterwards, can re-arm a batch-16 tier on its own.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("aescmacasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = true, false, false, false
	case "vaesavx2", "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("aescmacasm: %s tier needs VAES+AVX2; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, true, false, false
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			forcetier.Warnf("aescmacasm: vex tier needs AES-NI+AVX2; keeping auto-dispatch")
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, true, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("aescmacasm: aesni tier needs AES-NI; keeping auto-dispatch")
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, true
	case "scalar":
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 dispatch flags (HasVAESAVX512X16, HasVAESAVX2X16,
// HasAVXAESNIX16, HasAESNIX16), assigned as one consistent set.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("aescmacasm: avx512 batch-16 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = true, false, false, false
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("aescmacasm: vaesavx2 batch-16 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, true, false, false
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			forcetier.Warnf("aescmacasm: vex batch-16 tier needs AES-NI+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, true, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("aescmacasm: aesni batch-16 tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, true
	case "neon":
		forcetier.Warnf("aescmacasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	}
}
