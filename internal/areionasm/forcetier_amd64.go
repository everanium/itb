//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every Areion dispatch family — the batched-permute / chain-absorb
// arm flags, the fused cascade flags and the batch-16 fill flags — then
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16 family alone. Each
// variable is handled by its own function so an unsatisfiable token in
// one cannot skip the other.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER. Every flag in every family
// is assigned explicitly as one consistent set, so a partial override
// cannot leave a flag family contradictory.
//
// A forced arm the silicon cannot execute keeps auto-dispatch with a
// stderr note — forcing selects among runnable kernels, it cannot
// conjure an instruction set. On hosts whose widest tier exceeds the
// forced arm (e.g. VAES + AVX-512 silicon forced to avx2 or aesni),
// the narrower kernels become the active dispatch target, which is
// exactly the parity-harness use case.
//
//	avx512   — ZMM: fused cascade and batch-16 fill; the ZMM batched
//	           permutation of the arms
//	vaesavx2 — YMM VAES: fused cascade and batch-16 fill; the YMM
//	           batched permutation of the arms
//	avx2     — arms-only probe on VAES + AVX2 silicon: the YMM batched
//	           permutation with the fused cascade and batch-16 fill
//	           off, so the arms alone are reachable end to end
//	vex      — no VEX-encoded XMM arm exists for Areion; the token
//	           selects the AES-NI XMM kernels with a stderr note
//	aesni    — XMM AES-NI fused cascade and batch-16 fill; the batched
//	           arm runs the single-lane XMM cascade kernel per lane
//	           and the single arm the Go permutation
//	scalar   — every kernel off
//
// The arm64 tokens (neon / sve2 / sve) keep auto-dispatch with a note.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("areionasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasARMAESBatched = true, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = true, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = true, false, false
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("areionasm: vaesavx2 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasARMAESBatched = false, true, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = false, true, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, true, false
	case "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("areionasm: avx2 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasARMAESBatched = false, true, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = false, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, false, false
	case "vex", "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("areionasm: %s tier needs AES-NI; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		if forcetier.HashTier() == "vex" {
			forcetier.Warnf("areionasm: no vex arm; selecting the AES-NI XMM kernels")
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasARMAESBatched = false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = false, false, true
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, false, true
	case "neon", "sve2", "sve":
		forcetier.Warnf("areionasm: %s tier is arm64-only; keeping auto-dispatch", forcetier.HashTier())
	case "scalar":
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasARMAESBatched = false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = false, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, false, false
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the fill flags (HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 — the
// batch-16 hooks and the width-512 batch-32 hook), assigned as one
// consistent set. avx2 and vex have no
// batch-16 arm of their own: avx2 disarms the fill (the arms-only probe),
// vex selects the AES-NI XMM arm, each with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			forcetier.Warnf("areionasm: avx512 batch-16 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = true, false, false
	case "vaesavx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			forcetier.Warnf("areionasm: vaesavx2 batch-16 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, true, false
	case "avx2":
		forcetier.Warnf("areionasm: no avx2 batch-16 arm; forcing scalar")
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, false, false
	case "vex", "aesni":
		if !aes.CPU.HasAESNI {
			forcetier.Warnf("areionasm: %s batch-16 tier needs AES-NI; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
			return
		}
		if forcetier.InterlockPRFFillTier() == "vex" {
			forcetier.Warnf("areionasm: no vex batch-16 arm; selecting the AES-NI XMM arm")
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, false, true
	case "neon":
		forcetier.Warnf("areionasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = false, false, false
	}
}
