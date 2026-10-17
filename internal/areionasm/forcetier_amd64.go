//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"github.com/everanium/itb/internal/cpuid"
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
//	vex      — 3-operand VEX XMM (AVX + AES-NI): fused cascade and
//	           batch-16 fill; the VEX XMM batched permutation of the arms
//	aesni    — XMM AES-NI fused cascade and batch-16 fill; the batched
//	           arm runs the single-lane XMM cascade kernel per lane at
//	           the kernel shapes and the XMM fused SoEM kernel at every
//	           other length, and the single arm the Go permutation
//	scalar   — every kernel off
//
// The arm64 tokens (neon / sve2 / sve) keep auto-dispatch with a note.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !cpuid.VAESZMM {
			forcetier.Warnf("areionasm: avx512 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched, HasARMAESBatched = true, false, false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = true, false, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = true, false, false, false
	case "vaesavx2":
		if !cpuid.VAESYMM {
			forcetier.Warnf("areionasm: vaesavx2 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched, HasARMAESBatched = false, true, false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, true, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, true, false, false
	case "avx2":
		if !cpuid.VAESYMM {
			forcetier.Warnf("areionasm: avx2 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched, HasARMAESBatched = false, true, false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	case "vex":
		if !cpuid.AESNI || !cpuid.AVX2 {
			forcetier.Warnf("areionasm: vex tier needs AVX+AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched, HasARMAESBatched = false, false, true, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, true, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, true, false
	case "aesni":
		if !cpuid.AESNI {
			forcetier.Warnf("areionasm: aesni tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched, HasARMAESBatched = false, false, false, true, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, true
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, true
	case "gpr":
		forcetier.Warnf("areionasm: no gpr arm; keeping auto-dispatch")
	case "neon", "sve2", "sve":
		forcetier.Warnf("areionasm: %s tier is arm64-only; keeping auto-dispatch", forcetier.HashTier())
	case "scalar":
		HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched, HasARMAESBatched = false, false, false, false, false
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = false, false, false, false
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the fill flags (HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16,
// HasAESNIX16 — the batch-16 hooks and the width-512 batch-32 hook),
// assigned as one consistent set. avx2 has no batch-16 arm of its own
// and disarms the fill (the arms-only probe) with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "avx512":
		if !cpuid.VAESZMM {
			forcetier.Warnf("areionasm: avx512 batch-16 tier needs VAES+AVX-512; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = true, false, false, false
	case "vaesavx2":
		if !cpuid.VAESYMM {
			forcetier.Warnf("areionasm: vaesavx2 batch-16 tier needs VAES+AVX2; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, true, false, false
	case "avx2":
		forcetier.Warnf("areionasm: no avx2 batch-16 arm; forcing scalar")
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	case "vex":
		if !cpuid.AESNI || !cpuid.AVX2 {
			forcetier.Warnf("areionasm: vex batch-16 tier needs AVX+AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, true, false
	case "aesni":
		if !cpuid.AESNI {
			forcetier.Warnf("areionasm: aesni batch-16 tier needs AES-NI; keeping auto-dispatch")
			return
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, true
	case "gpr":
		forcetier.Warnf("areionasm: no gpr batch-16 arm; keeping auto-dispatch")
	case "neon":
		forcetier.Warnf("areionasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, false
	}
}
