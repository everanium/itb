//go:build arm64 && !purego && !noitbasm

package interlock

import "github.com/everanium/itb/internal/forcetier"

// init applies ITB_FORCE_INTERLOCK_TIER to the arm64 48-bit interlock
// dispatch flags.
//
//	sve2   — requires SVE2 bit-permute silicon; keeps the SVE2
//	         BEXT / BDEP batched chunk-apply and the NEON rank-unrank
//	         kernel selected. Otherwise a stderr note is emitted and
//	         auto-dispatch is kept.
//	neon   — NEON rank-unrank kernel plus the software batched
//	         chunk-apply loop: HasSVE2Interlock is cleared so the arm
//	         every ARMv8-A host runs is reproduced on SVE2 silicon.
//	scalar — disables the NEON rank-unrank kernel, the SVE2 kernel and
//	         the batched chunk-apply, so the pure-Go softPEXT48 /
//	         softPDEP48 and scalar rankToMaskTriple48 paths run.
//	sve    — SVE (VL-agnostic, no BitPerm) tier: routes to the NEON
//	         rank-unrank kernel and the software batched chunk-apply,
//	         identical to the neon token flag-wise. Exists as a
//	         diagnostic label for simulating an SVE-only host slice
//	         (Neoverse V1 / Graviton 3) on SVE2 silicon. No SVE-specific
//	         kernel is written: SVE without BitPerm has no chunk-apply
//	         instruction beyond NEON, and its rank-unrank lane density
//	         does not exceed the NEON 8-lane kernel at the 128-bit
//	         vector length of the shipping Graviton parts.
//
// The amd64 tokens (avx512, avx512x8, avx2) keep auto-dispatch with a
// stderr note. Production auto-dispatch is unaffected when the variable
// is unset.
func init() {
	switch tier := forcetier.InterlockTier(); tier {
	case "":
	case "sve2":
		if !HasSVE2Interlock {
			forcetier.Warnf("interlock: sve2 tier needs SVE2 bit-permute silicon; keeping auto-dispatch")
			return
		}
		HasNEONInterlock = true
		HasChunk48Batch = true
	case "neon", "sve":
		// Both tokens select the same arm: SVE without BitPerm adds
		// nothing over NEON for these operations, so the sve label
		// simulates the SVE-only fleet slice on SVE2 silicon.
		HasNEONInterlock = true
		HasChunk48Batch = true
		HasSVE2Interlock = false
	case "scalar":
		HasNEONInterlock = false
		HasChunk48Batch = false
		HasSVE2Interlock = false
	default:
		forcetier.Warnf("interlock: %s tier is amd64-only; keeping auto-dispatch", tier)
	}
}
