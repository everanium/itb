//go:build amd64 && !purego && !noitbasm

package blake2sasm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables to the fused cascade flag
// families in order: ITB_FORCE_HASH_TIER to both — the fused cascade
// flags and the batch-16 fill flags — then
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16 family alone. Each
// variable is handled by its own function so an unsatisfiable token in
// one cannot skip the other. The chain-absorb flags of forcetier_amd64.go
// are assigned by their own init.
func init() {
	applyFusedHashTier()
	applyFusedInterlockPRFFillTier()
}

// applyFusedHashTier applies ITB_FORCE_HASH_TIER. Every flag in every
// family is assigned explicitly as one consistent set, so a partial
// override cannot leave a flag family contradictory. A forced arm the
// silicon cannot execute keeps auto-dispatch with a stderr note.
//
//	avx512 — EVEX fused cascade and the YMM batch-16 fill
//	avx2   — VEX XMM fused cascade and batch-16 fill
//	vex    — the VEX XMM kernels are the avx2 tier; the token selects
//	         them with a stderr note
//	aesni  — BLAKE2s has no AES-based arm; the token forces scalar with
//	         a stderr note (the parity script's skip matrix avoids the
//	         pairing)
//	scalar — every kernel off
//
// The arm64 tokens (neon / sve2 / sve) keep auto-dispatch with a note.
func applyFusedHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("blake2sasm: avx512 fused tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		FusedHasAVX512, FusedHasAVX2 = true, false
		HasAVX512X16, HasAVX2X16 = true, false
	case "avx2", "vex":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("blake2sasm: %s fused tier needs AVX2; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		if forcetier.HashTier() == "vex" {
			forcetier.Warnf("blake2sasm: no vex fused arm; selecting the AVX2 kernels")
		}
		FusedHasAVX512, FusedHasAVX2 = false, true
		HasAVX512X16, HasAVX2X16 = false, true
	case "aesni":
		forcetier.Warnf("blake2sasm: no aesni fused arm; forcing scalar")
		FusedHasAVX512, FusedHasAVX2 = false, false
		HasAVX512X16, HasAVX2X16 = false, false
	case "neon", "sve2", "sve":
		forcetier.Warnf("blake2sasm: %s tier is arm64-only; keeping auto-dispatch", forcetier.HashTier())
	case "scalar":
		FusedHasAVX512, FusedHasAVX2 = false, false
		HasAVX512X16, HasAVX2X16 = false, false
	}
}

// applyFusedInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER
// to the batch-16 fill flags (HasAVX512X16, HasAVX2X16), assigned as one
// consistent set. vex selects the AVX2 arm and aesni forces scalar, each
// with a stderr note.
func applyFusedInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("blake2sasm: avx512 batch-16 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512X16, HasAVX2X16 = true, false
	case "avx2", "vex", "vaesavx2":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("blake2sasm: %s batch-16 tier needs AVX2; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
			return
		}
		if forcetier.InterlockPRFFillTier() != "avx2" {
			forcetier.Warnf("blake2sasm: no %s batch-16 arm; selecting the AVX2 arm", forcetier.InterlockPRFFillTier())
		}
		HasAVX512X16, HasAVX2X16 = false, true
	case "aesni":
		forcetier.Warnf("blake2sasm: no aesni batch-16 arm; forcing scalar")
		HasAVX512X16, HasAVX2X16 = false, false
	case "neon":
		forcetier.Warnf("blake2sasm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasAVX512X16, HasAVX2X16 = false, false
	}
}
