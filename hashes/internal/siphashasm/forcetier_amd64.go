//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to every SipHash-2-4 dispatch family (fused cascade and the batch-16
// interlock fill), then ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16
// family alone, so the second variable can re-select a batch-16 arm
// after the first has scalarised everything. Each variable is handled by
// its own function; a forced arm the silicon cannot execute keeps that
// family's auto-dispatch with a stderr note without affecting the other
// variable.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER. The fused flags are
// assigned as one consistent set: "avx512" selects the EVEX kernels,
// "avx2" the VEX kernels. SipHash has no AES-based arm, so "vaesavx2",
// "vex" and "aesni" disable both batched arms (scalar behaviour) with a
// stderr note; the parity script's skip matrix avoids those pairings.
// "scalar" means no assembly anywhere in this package's dispatch, so it
// also disarms the batch-16 flags; ITB_FORCE_INTERLOCK_PRF_FILL_TIER,
// applied afterwards, can re-arm a batch-16 tier on its own.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("siphashasm: avx512 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		FusedHasAVX512, FusedHasAVX2 = true, false
		HasAVX512X16, HasAVX2X16 = true, false
	case "avx2":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("siphashasm: avx2 tier needs AVX2; keeping auto-dispatch")
			return
		}
		FusedHasAVX512, FusedHasAVX2 = false, true
		HasAVX512X16, HasAVX2X16 = false, true
	case "vaesavx2", "vex", "aesni":
		forcetier.Warnf("siphashasm: no %s arm; forcing scalar", forcetier.HashTier())
		FusedHasAVX512, FusedHasAVX2 = false, false
		HasAVX512X16, HasAVX2X16 = false, false
	case "scalar":
		FusedHasAVX512, FusedHasAVX2 = false, false
		HasAVX512X16, HasAVX2X16 = false, false
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 dispatch flags (HasAVX512X16, HasAVX2X16), assigned as one
// consistent set. The AES-only tokens ("vaesavx2", "vex", "aesni")
// disarm the batch-16 kernels with a stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("siphashasm: avx512 batch-16 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512X16, HasAVX2X16 = true, false
	case "avx2":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("siphashasm: avx2 batch-16 tier needs AVX2; keeping auto-dispatch")
			return
		}
		HasAVX512X16, HasAVX2X16 = false, true
	case "vaesavx2", "vex", "aesni":
		forcetier.Warnf("siphashasm: no %s batch-16 arm; forcing scalar", forcetier.InterlockPRFFillTier())
		HasAVX512X16, HasAVX2X16 = false, false
	case "neon":
		forcetier.Warnf("siphashasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasAVX512X16, HasAVX2X16 = false, false
	}
}
