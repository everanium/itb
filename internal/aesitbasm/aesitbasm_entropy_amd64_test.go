//go:build amd64 && !purego && !noitbasm

package aesitbasm

import "testing"

// aesitbasm_entropy_amd64_test.go — the input-entropy differential audit
// of every amd64 kernel by direct call, independent of the dispatch
// flags, and of the dispatchers under every dispatch state the host can
// execute.

// TestInputEntropyKernelsAmd64 audits every kernel the host can execute:
// the four-lane kernels of every tier, the single-lane kernels of the
// aesni and vex tiers, the eight-lane ZMM kernels and the batch-16 fill
// kernel of every tier.
func TestInputEntropyKernelsAmd64(t *testing.T) {
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range shapes {
				auditX4(t, tier.name, n, tier.x4[n])
				if tier.x1 != nil {
					auditX1(t, tier.name, n, tier.x1[n])
				}
			}
		})
	}
	t.Run("avx512-x8", func(t *testing.T) {
		if !hostHasZMMFused() {
			t.Skip("requires VAES + AVX-512")
		}
		for n, f := range avx512X8Kernels() {
			auditX8(t, "avx512", n, f)
		}
	})
	for _, tier := range amd64FusedX16Tiers() {
		if tier.k == nil {
			continue
		}
		t.Run(tier.name+"-x16", func(t *testing.T) {
			if !tier.ok() {
				t.Skip("tier not executable on this host")
			}
			auditX16(t, tier.name, tier.k)
		})
	}
}

// TestInputEntropyDispatcherTiersAmd64 installs every dispatch state the
// host can execute — the fused and batch-16 flag families as one set
// per tier, plus the scalar state — and audits the dispatchers under
// each.
func TestInputEntropyDispatcherTiersAmd64(t *testing.T) {
	zmm, ymm, vex, aesni := FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI
	t.Cleanup(func() {
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = zmm, ymm, vex, aesni
	})
	saveFusedX16Flags(t)
	for _, tier := range amd64FusedX16Tiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok() {
				t.Skip("tier not executable on this host")
			}
			FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = tier.zmm, tier.ymm, tier.vex, tier.aesni
			HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = tier.zmm, tier.ymm, tier.vex, tier.aesni
			auditDispatchers(t, "dispatch-"+tier.name)
		})
	}
}
