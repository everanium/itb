//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_HASH_TIER to the Areion batched-dispatch
// flags. Every flag in the family is assigned explicitly as one
// consistent set: the derived HasAESNIBatched expression in
// areionasm_amd64.go has already been evaluated by the time any init
// runs (package var initialisation precedes init functions), so a
// partial override cannot leave the flag family contradictory.
//
// A forced arm the silicon cannot execute keeps auto-dispatch with a
// stderr note — forcing selects among runnable kernels, it cannot
// conjure an instruction set. On hosts whose widest tier exceeds the
// forced arm (e.g. VAES + AVX-512 silicon forced to avx2 or aesni),
// the narrower kernels become the active dispatch target, which is
// exactly the parity-harness use case.
func init() {
	switch forcetier.HashTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("areionasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasVAESAVX2Batched, HasARMAESBatched, HasAESNIBatched = true, false, false, false, false
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("areionasm: vaesavx2 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		// Width-specialised YMM VAES chain-absorb kernels for the hot
		// {13,20,36,68} shapes; the base Areion*Permutex4Avx2 + Go SoEM
		// loop (HasVAESAVX2NoAVX512) stays enabled for any other shape.
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasVAESAVX2Batched, HasARMAESBatched, HasAESNIBatched = false, true, true, false, false
	case "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("areionasm: avx2 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		// Base 4-way permutation + Go-side SoEM absorb loop only; the
		// width-specialised YMM kernels stay off so this arm exercises
		// the general (non-width-specialised) VAES-on-YMM path.
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasVAESAVX2Batched, HasARMAESBatched, HasAESNIBatched = false, true, false, false, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("areionasm: aesni tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasVAESAVX2Batched, HasARMAESBatched, HasAESNIBatched = false, false, false, false, true
	case "scalar":
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasVAESAVX2Batched, HasARMAESBatched, HasAESNIBatched = false, false, false, false, false
	}
}
