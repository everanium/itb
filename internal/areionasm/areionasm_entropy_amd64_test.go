//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// areionasm_entropy_amd64_test.go — the input-entropy differential audit
// of every amd64 kernel by direct call, independent of the dispatch
// flags, and of the dispatchers under every dispatch state the host can
// execute.

func fill256x8Kernel(k *[32]byte, c []uint64, base uint64, o *[8][4]uint64) {
	areion256FusedChain13x8Avx512Asm(k, &c[0], len(c)/4, base, o)
}

// TestInputEntropyKernelsAmd64 audits every kernel the host can execute:
// the four-lane kernels of every tier at both widths, the single-lane
// AES-NI kernels, the eight-lane ZMM kernels and the eight-lane ZMM fill
// kernels of both widths.
func TestInputEntropyKernelsAmd64(t *testing.T) {
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range Shapes {
				audit256X4(t, tier.name, n, kernels256x4[tier.name][n])
				audit512X4(t, tier.name, n, kernels512x4[tier.name][n])
			}
		})
	}
	t.Run("aesni-x1", func(t *testing.T) {
		if !aes.CPU.HasAESNI {
			t.Skip("requires AES-NI")
		}
		for _, n := range Shapes {
			audit256X1(t, "aesni", n, kernels256x1[n])
			audit512X1(t, "aesni", n, kernels512x1[n])
		}
	})
	t.Run("avx512-wide", func(t *testing.T) {
		if !hasZMM() {
			t.Skip("requires VAES + AVX-512")
		}
		for _, n := range []int{20, 36, 68} {
			audit256X8(t, "avx512", n, kernels256x8[n])
			audit512X8(t, "avx512", n, kernels512x8[n])
		}
		audit256Fill8(t, "avx512", fill256x8Kernel)
		audit512Fill8(t, "avx512", fill512x8Kernel)
	})
}

// TestInputEntropyDispatcherTiersAmd64 installs every dispatch state the
// host can execute — the fused and batch-16 flag families as one set
// per tier, plus the scalar state — and audits the dispatchers under
// each.
func TestInputEntropyDispatcherTiersAmd64(t *testing.T) {
	saveFusedFlags(t)
	for _, tier := range append(amd64FusedTiers(), fusedTier{name: "scalar", ok: true}) {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			setTier(tier)
			auditDispatchers(t, "dispatch-"+tier.name)
		})
	}
}
