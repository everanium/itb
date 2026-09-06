//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_HASH_TIER to the AES-ITB batched-dispatch flags.
// The four flags are assigned as one consistent set; a forced arm the
// silicon cannot execute keeps auto-dispatch with a stderr note. The
// shared value set has no token for the VEX-encoded XMM tier, so
// "aesni" selects the legacy-SSE kernels and the VEX kernels are reached
// only through auto-dispatch and the direct-call parity tests.
//
// Also applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16 dispatch
// flags (HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16).
func init() {
	switch forcetier.HashTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("aesitbasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched = true, false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = true, false, false, false
	case "vaesavx2", "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("aesitbasm: %s tier needs VAES+AVX2; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched = false, true, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, true, false, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("aesitbasm: aesni tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched = false, false, false, true
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, true
	case "scalar":
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched = false, false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, false
	}

	// Apply batch-16 tier forcing (ITB_FORCE_INTERLOCK_PRF_FILL_TIER).
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
		if !aes.CPU.HasAVX2 || !aes.CPU.HasAESNI {
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
	case "neon":
		forcetier.Warnf("aesitbasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	}
}
