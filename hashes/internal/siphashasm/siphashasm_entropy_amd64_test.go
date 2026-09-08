//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// siphashasm_entropy_amd64_test.go — the input-entropy differential
// audit of every amd64 kernel by direct call, independent of the
// dispatch flags, and of the dispatchers under every dispatch state the
// host can execute.

// TestInputEntropyKernelsAmd64 audits every kernel the host can execute:
// the four-lane kernels of the avx512 and avx2 tiers, the single-lane
// GPR kernels, the eight-lane ZMM kernels, the ZMM batch-16 fill kernel
// and the YMM eight-lane fill kernel (two calls per batch).
func TestInputEntropyKernelsAmd64(t *testing.T) {
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range shapes {
				auditX4(t, tier.name, n, tier.x4[n])
			}
		})
	}
	t.Run("gpr", func(t *testing.T) {
		for n, f := range gprX1Kernels() {
			auditX1(t, "gpr", n, f)
		}
	})
	t.Run("avx512-x8", func(t *testing.T) {
		if !cpu.X86.HasAVX512F {
			t.Skip("requires AVX-512F")
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
	saveFusedFlags(t)
	saveFusedX16Flags(t)
	for _, tier := range amd64FusedX16Tiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok() {
				t.Skip("tier not executable on this host")
			}
			FusedHasAVX512, FusedHasAVX2 = tier.avx512, tier.avx2
			HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
			FusedHasGPR, HasGPRX16 = tier.name != "scalar", tier.name != "scalar"
			auditDispatchers(t, "dispatch-"+tier.name)
		})
	}
}
