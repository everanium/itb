//go:build amd64 && !purego && !noitbasm

package aescmacasm

import "github.com/everanium/itb/internal/cpuid"

// Batch-16 tier flags: auto-select the widest VAES tier the host offers.
// The flags are package variables so the forcetier init and the
// in-package dispatch tests can override the auto-selection. Only one
// flag is true; the cascade keeps the "one consistent set" invariant the
// forcetier init relies on. The flags select the arm of FusedChain13x16
// (aescmacasm_fused_amd64.go), the Interlocked Barrier fill kernel.
var (
	HasVAESAVX512X16 = cpuid.VAESZMM
	HasVAESAVX2X16   = cpuid.VAESYMM && !HasVAESAVX512X16

	// HasAVXAESNIX16 selects the VEX-encoded XMM batch-16 kernel on
	// AES-NI + AVX hosts without VAES (AVX2 is used as the detection
	// superset); HasAESNIX16 selects the legacy-SSE-encoded XMM batch-16
	// kernel on AES-NI hosts without AVX.
	HasAVXAESNIX16 = cpuid.AESNI && cpuid.AVX2 && !HasVAESAVX512X16 && !HasVAESAVX2X16
	HasAESNIX16    = cpuid.AESNI && !cpuid.AVX2

	// HasARMAESX16 is always false on amd64 builds.
	HasARMAESX16 = false
)
