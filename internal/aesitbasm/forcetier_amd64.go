//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every AES-ITB dispatch family (fused cascade and the batch-16
// interlock fill), then ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 family alone, so the second variable can re-select a
// batch-16 arm after the first has scalarised everything. Each variable
// is handled by its own function; a forced arm the silicon cannot
// execute keeps that family's auto-dispatch with a stderr note without
// affecting the other variable.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER. The fused flags are
// assigned as one consistent set. "vex" selects the VEX-encoded XMM
// kernels (AVX-encoded AES-NI, one lane per XMM); "aesni" selects the
// legacy-SSE-encoded XMM kernels on AES-NI hosts without AVX. "scalar"
// means no assembly anywhere in this package's dispatch, so it also
// disarms the batch-16 flags; ITB_FORCE_INTERLOCK_PRF_FILL_TIER, applied
// afterwards, can re-arm a batch-16 tier on its own.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("aesitbasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = true, false, false, false
	case "vaesavx2", "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("aesitbasm: %s tier needs VAES+AVX2; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, true, false, false
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			forcetier.Warnf("aesitbasm: vex tier needs AES-NI+AVX2; keeping auto-dispatch")
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, true, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("aesitbasm: aesni tier needs AES-NI; keeping auto-dispatch")
			return
		}
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, true
	case "gpr":
		forcetier.Warnf("aesitbasm: no gpr arm; keeping auto-dispatch")
	case "neon", "sve2", "sve":
		forcetier.Warnf("aesitbasm: %s tier is arm64-only; keeping auto-dispatch", forcetier.HashTier())
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
			forcetier.Warnf("aesitbasm: avx512 batch-16 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = true, false, false, false
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("aesitbasm: vaesavx2 batch-16 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, true, false, false
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			forcetier.Warnf("aesitbasm: vex batch-16 tier needs AES-NI+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, true, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("aesitbasm: aesni batch-16 tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, true
	case "avx2":
		forcetier.Warnf("aesitbasm: no avx2 batch-16 arm (the VAES / AES-NI YMM arms are vaesavx2 / vex); keeping auto-dispatch")
	case "gpr":
		forcetier.Warnf("aesitbasm: no gpr batch-16 arm; keeping auto-dispatch")
	case "neon":
		forcetier.Warnf("aesitbasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	}
}
