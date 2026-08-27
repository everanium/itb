//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_HASH_TIER to the AES-CMAC batched-dispatch
// flags. Both flags are assigned explicitly as one consistent set (the
// derived HasAESNIBatched expression in aescmacasm_amd64.go has
// already been evaluated by the time this init runs). A forced arm the
// silicon cannot execute keeps auto-dispatch with a stderr note.
//
// AES-CMAC deliberately carries no YMM tier (see the package comment
// in aescmacasm_amd64.go), so an avx2 force disables both batched
// arms — the scalar reference path runs — with a stderr note. The
// parity script's skip matrix avoids the (aescmac, avx2) pairing so
// the fallback never masquerades as AVX2-arm coverage.
func init() {
	switch forcetier.HashTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("aescmacasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasAESNIBatched = true, false
	case "avx2":
		forcetier.Warnf("aescmacasm: no avx2 arm; forcing scalar")
		HasVAESAVX512, HasAESNIBatched = false, false
	case "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("aescmacasm: aesni tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasAESNIBatched = false, true
	case "scalar":
		HasVAESAVX512, HasAESNIBatched = false, false
	}
}
