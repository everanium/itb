//go:build amd64 && !purego && !noitbasm

package blake3asm

import "testing"

// blake3asm_entropy_amd64_test.go — the input-entropy differential
// audit of every amd64 kernel by direct call, independent of the
// dispatch flags, and of the dispatchers under every dispatch state the
// host can execute.

// TestInputEntropyKernelsAmd64 audits every kernel the host can execute:
// the four-lane kernels of both tiers, the single-lane GPR kernels, the
// eight-lane YMM kernels and the eight-lane YMM fill kernel.
func TestInputEntropyKernelsAmd64(t *testing.T) {
	for _, tier := range amd64CascadeTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range Shapes {
				audit256X4(t, tier.name, n, kernels256x4[tier.name][n])
			}
		})
	}
	t.Run("gpr", func(t *testing.T) {
		for _, n := range Shapes {
			audit256X1(t, "gpr", n, kernels256x1[n])
		}
	})
	t.Run("avx512-wide", func(t *testing.T) {
		if !hasEVEX() {
			t.Skip("requires AVX-512F")
		}
		for _, n := range []int{20, 36, 68} {
			audit256X8(t, "avx512", n, kernels256x8[n])
		}
		audit256Fill8(t, "avx512", fill256x8Kernel)
	})
}

// TestInputEntropyDispatcherTiersAmd64 installs every dispatch state the
// host can execute — the fused and batch-16 flag families as one set
// per tier, plus the scalar state — and audits the dispatchers under
// each.
func TestInputEntropyDispatcherTiersAmd64(t *testing.T) {
	saveCascadeFlags(t)
	for _, tier := range append(amd64CascadeTiers(), cascadeTier{name: "scalar", ok: true}) {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			setCascadeTier(tier)
			auditDispatchers(t, "dispatch-"+tier.name)
		})
	}
}
