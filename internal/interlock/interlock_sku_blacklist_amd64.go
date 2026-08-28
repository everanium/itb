//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
	"github.com/klauspost/cpuid/v2"
)

// init runs after the default HasAVX512RankMask / HasAVX2RankMask
// variable initialisations and after the ITB_FORCE_INTERLOCK_TIER init
// (file-alphabetical order: forcetier_amd64.go, interlock_sku_...,
// interlockasm48_amd64.go), applying a narrow SKU blacklist that
// disables only the AVX-512 rankToMaskTripleUnrank48 kernel on
// microarchitectures where its mask-heavy scalar-to-SIMD-bridge cluster
// runs pathologically slow.
//
// Empirical driver: on Intel Sapphire Rapids-SP (Xeon Platinum 8488C,
// AWS c7i.4xlarge) the natural-dispatch AVX-512 kernel reaches
// 27 MB/s single-thread on the ExtProduction 64 MiB encrypt bench,
// versus 141 MB/s under ITB_FORCE_INTERLOCK_TIER=avx2 on the same
// silicon — a 5.1x lift. A perf-record capture on the same host
// attributes 93.5% of runtime to rankToMaskTripleUnrank48AVX512 with
// IPC 0.137 (pipeline stalled ~85% of cycles); the four hottest
// instructions (VPORQ predicated, VPCMPUQ, VPBROADCASTQ scalar-to-ZMM,
// VPBROADCASTQ predicated) each take 14-25% of samples — the uniform
// distribution characteristic of Golden Cove Server pipeline back-
// pressure, not a specific slow instruction. Frequency during the
// bench is normal (~3.72 GHz sustained turbo), so the stall is not a
// heavy-AVX-512 downclock. The healthy comparison host — Intel Rocket
// Lake 11700K — dispatches into the same kernel and reaches
// 258 MB/s single-thread, so the regression is silicon-specific to
// the Golden Cove Server microarchitecture, not universal AVX-512
// pathology.
//
// Emerald Rapids (5th generation Xeon Scalable) is a die-shrink
// revision of Sapphire Rapids on the same Golden Cove Server P-core
// and mesh topology; it inherits the regression by construction and
// is blacklisted preventively. Granite Rapids (6th generation, model
// 0xAD, Redwood Cove Server) uses a different P-core and different
// pipeline layout and is NOT blacklisted — no evidence of the same
// pattern there.
//
// Scope of the blacklist is deliberately narrow. Only
// HasAVX512RankMask is flipped off; the parallel AVX2 rank-mask arm
// is enabled in its place. Every other AVX-512 code path in the
// module continues to dispatch normally on affected silicon: the
// Areion / BLAKE / ChaCha20 / SipHash / AES-CMAC chain-absorb AVX-512
// kernels, the pixel encoder Tier A (AVX-512 + GFNI + VBMI 8-pixel
// ZMM), and every other AVX-512 helper. A 27-cell hash x nonce matrix
// on the same c7i.4xlarge (with INTERLOCK_TIER=avx2 to remove the
// broken interlock bottleneck) confirmed all shipped hash chain-
// absorb kernels reach 71-83% of the 11700K baseline uniformly — no
// hash-specific SPR regression.
//
// Bypass: ITB_FORCE_INTERLOCK_TIER=avx512 continues to force the
// AVX-512 arm on affected silicon (with the standard "auto-dispatch
// keeps up if the tier is unusable" behaviour) so paper reviewers can
// reproduce the natural-dispatch slow path.
func init() {
	if forcetier.InterlockTier() != "" {
		return
	}
	if !cpu.X86.HasAVX512F {
		return
	}
	if cpuid.CPU.VendorID != cpuid.Intel {
		return
	}
	if !isSPRFamilyModel(cpuid.CPU.Family, cpuid.CPU.Model) {
		return
	}
	HasAVX512RankMask = false
	HasAVX2RankMask = cpu.X86.HasAVX2 && cpu.X86.HasBMI2
}

// isSPRFamilyModel reports whether an Intel CPUID family / model pair
// identifies a Golden Cove Server microarchitecture affected by the
// AVX-512 rank-mask kernel regression: Sapphire Rapids-SP (family 6,
// model 0x8F) or Emerald Rapids (family 6, model 0xCF, the SPR die-
// shrink revision on the same P-core). Split out from the init call
// site as a pure function so the mapping is unit-testable without
// mocking the global cpuid.CPU state.
//
// Granite Rapids (family 6, model 0xAD) is intentionally NOT
// blacklisted: it uses the Redwood Cove Server P-core, not Golden
// Cove, and has no empirical or architectural reason to inherit the
// regression. If Granite Rapids or a later Xeon Scalable generation
// later turns out to share the pattern, extend this switch.
func isSPRFamilyModel(family, model int) bool {
	if family != 6 {
		return false
	}
	switch model {
	case 0x8F, 0xCF:
		return true
	}
	return false
}
