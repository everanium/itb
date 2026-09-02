//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// fusedTier names one dispatch arm of the batched chain-absorb entry
// points together with the capability-flag state that selects it.
type fusedTier struct {
	name   string
	avx512 bool
	avx2   bool
}

// runnableFusedTiers enumerates the dispatch arms the current silicon
// can execute: the scalar reference always, the AVX2 fused kernels
// when AVX2 is present, the AVX-512 fused kernels when AVX-512F is
// present.
func runnableFusedTiers() []fusedTier {
	tiers := []fusedTier{{name: "scalar"}}
	if cpu.X86.HasAVX2 {
		tiers = append(tiers, fusedTier{name: "avx2", avx2: true})
	}
	if cpu.X86.HasAVX512F {
		tiers = append(tiers, fusedTier{name: "avx512", avx512: true})
	}
	return tiers
}

// setFusedTier overrides the fused-dispatch capability flags for one
// test and restores the saved values on cleanup. The flags are
// process-global, so tests using this helper must not run in parallel.
func setFusedTier(t *testing.T, tier fusedTier) {
	t.Helper()
	saved512, saved2 := HasAVX512Fused, HasAVX2Fused
	HasAVX512Fused, HasAVX2Fused = tier.avx512, tier.avx2
	t.Cleanup(func() { HasAVX512Fused, HasAVX2Fused = saved512, saved2 })
}

// TestChainAbsorbDispatcherTierParity drives every batched
// SipHash-2-4-128 chain-absorb dispatcher (13/20/36/68-byte data
// shapes) through each runnable dispatch arm — AVX-512 fused, AVX2
// fused, scalar — and requires bit-exact agreement with the scalar
// batched reference on identical inputs.
func TestChainAbsorbDispatcherTierParity(t *testing.T) {
	var seeds [4][2]uint64
	var data [4][68]byte
	var dataPtrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = uint64(lane+1) * 0x736F6D6570736575
		seeds[lane][1] = uint64(lane+1) * 0x646F72616E646F6D
		for i := range data[lane] {
			data[lane][i] = byte(lane*97 + i*23 + 11)
		}
		dataPtrs[lane] = &data[lane][0]
	}

	shapes := []struct {
		name     string
		dispatch func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)
		scalar   func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)
	}{
		{"absorb13", SipHash24Chain128Absorb13x4, scalarBatch128ChainAbsorb13},
		{"absorb20", SipHash24Chain128Absorb20x4, scalarBatch128ChainAbsorb20},
		{"absorb36", SipHash24Chain128Absorb36x4, scalarBatch128ChainAbsorb36},
		{"absorb68", SipHash24Chain128Absorb68x4, scalarBatch128ChainAbsorb68},
	}

	for _, shape := range shapes {
		var want [4][2]uint64
		shape.scalar(&seeds, &dataPtrs, &want)
		for _, tier := range runnableFusedTiers() {
			t.Run(shape.name+"/"+tier.name, func(t *testing.T) {
				setFusedTier(t, tier)
				var got [4][2]uint64
				shape.dispatch(&seeds, &dataPtrs, &got)
				if got != want {
					t.Fatalf("%s %s arm diverges from scalar reference:\n got %#x\nwant %#x",
						shape.name, tier.name, got, want)
				}
			})
		}
	}
}
