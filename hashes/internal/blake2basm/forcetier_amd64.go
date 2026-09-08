//go:build amd64 && !purego && !noitbasm

package blake2basm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies the two forcing variables in order: ITB_FORCE_HASH_TIER
// to both BLAKE2b dispatch families — the fused cascade flags and the
// batch-16 fill flags — then
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER to the batch-16 family alone. Each
// variable is handled by its own function so an unsatisfiable token in
// one cannot skip the other.
func init() {
	applyHashTier()
	applyInterlockPRFFillTier()
}

// applyHashTier applies ITB_FORCE_HASH_TIER. Every flag in every family
// is assigned explicitly as one consistent set, so a partial override
// cannot leave a flag family contradictory. A forced arm the silicon
// cannot execute keeps auto-dispatch with a stderr note.
//
//	avx512 — EVEX YMM fused cascade and the ZMM batch-16 fill
//	avx2   — VEX YMM fused cascade and batch-16 fill
//	vex    — no VEX XMM arm exists for BLAKE2b; the token selects the
//	         AVX2 kernels with a stderr note
//	aesni / vaesavx2 — BLAKE2b has no AES-based arm; the token names no
//	         arm of this family and keeps auto-dispatch with a stderr
//	         note (the parity script's skip matrix avoids the pairing)
//	scalar — every kernel off
//
// The arm64 tokens (neon / sve2 / sve) keep auto-dispatch with a note.
func applyHashTier() {
	switch forcetier.HashTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("blake2basm: avx512 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		FusedHasAVX512, FusedHasAVX2 = true, false
		HasAVX512X16, HasAVX2X16 = true, false
	case "avx2", "vex":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("blake2basm: %s tier needs AVX2; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		if forcetier.HashTier() == "vex" {
			forcetier.Warnf("blake2basm: no vex arm; selecting the AVX2 kernels")
		}
		FusedHasAVX512, FusedHasAVX2 = false, true
		HasAVX512X16, HasAVX2X16 = false, true
	case "aesni", "vaesavx2":
		forcetier.Warnf("blake2basm: no %s arm; keeping auto-dispatch", forcetier.HashTier())
	case "neon", "sve2", "sve":
		forcetier.Warnf("blake2basm: %s tier is arm64-only; keeping auto-dispatch", forcetier.HashTier())
	case "scalar":
		FusedHasAVX512, FusedHasAVX2 = false, false
		HasAVX512X16, HasAVX2X16 = false, false
	}
}

// applyInterlockPRFFillTier applies ITB_FORCE_INTERLOCK_PRF_FILL_TIER to
// the batch-16 fill flags (HasAVX512X16, HasAVX2X16), assigned as one
// consistent set. vex selects the AVX2 arm with a stderr note; aesni and
// vaesavx2 name no arm of this family and keep auto-dispatch with a
// stderr note.
func applyInterlockPRFFillTier() {
	switch forcetier.InterlockPRFFillTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("blake2basm: avx512 batch-16 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512X16, HasAVX2X16 = true, false
	case "avx2", "vex":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("blake2basm: %s batch-16 tier needs AVX2; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
			return
		}
		if forcetier.InterlockPRFFillTier() == "vex" {
			forcetier.Warnf("blake2basm: no vex batch-16 arm; selecting the AVX2 arm")
		}
		HasAVX512X16, HasAVX2X16 = false, true
	case "aesni", "vaesavx2":
		forcetier.Warnf("blake2basm: no %s batch-16 arm; keeping auto-dispatch", forcetier.InterlockPRFFillTier())
	case "neon":
		forcetier.Warnf("blake2basm: neon batch-16 tier is arm64-only; keeping auto-dispatch")
	case "scalar":
		HasAVX512X16, HasAVX2X16 = false, false
	}
}
