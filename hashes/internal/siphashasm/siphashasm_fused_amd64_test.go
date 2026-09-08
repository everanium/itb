//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

type fusedAsmX4 func(*uint64, int, *[4]*byte, *[4][2]uint64)
type fusedAsmX1 func(*uint64, int, *byte, *[2]uint64)

func wrapX4(f fusedAsmX4) fusedX4Fn {
	return func(comps []uint64, ptrs *[4]*byte, out *[4][2]uint64) {
		f(&comps[0], len(comps)/2, ptrs, out)
	}
}

func wrapX1(f fusedAsmX1) fusedX1Fn {
	return func(comps []uint64, data *byte, out *[2]uint64) {
		f(&comps[0], len(comps)/2, data, out)
	}
}

// fusedTier describes one fused dispatch state: the silicon it needs,
// its four-lane kernels and the flag pair that selects it. The
// single-lane GPR kernel belongs to every assembly tier.
type fusedTier struct {
	name         string
	ok           bool
	skipMsg      string
	x4           map[int]fusedX4Fn
	avx512, avx2 bool
}

func amd64FusedTiers() []fusedTier {
	return []fusedTier{
		{
			name: "avx2", ok: cpu.X86.HasAVX2, skipMsg: "requires AVX2",
			x4: map[int]fusedX4Fn{13: wrapX4(sipHash24FusedChain13x4Avx2Asm), 20: wrapX4(sipHash24FusedChain20x4Avx2Asm),
				36: wrapX4(sipHash24FusedChain36x4Avx2Asm), 68: wrapX4(sipHash24FusedChain68x4Avx2Asm)},
			avx2: true,
		},
		{
			name: "avx512", ok: cpu.X86.HasAVX512F, skipMsg: "requires AVX-512F",
			x4: map[int]fusedX4Fn{13: wrapX4(sipHash24FusedChain13x4Avx512Asm), 20: wrapX4(sipHash24FusedChain20x4Avx512Asm),
				36: wrapX4(sipHash24FusedChain36x4Avx512Asm), 68: wrapX4(sipHash24FusedChain68x4Avx512Asm)},
			avx512: true,
		},
	}
}

// gprX1Kernels maps each shape to its single-lane GPR kernel.
func gprX1Kernels() map[int]fusedX1Fn {
	return map[int]fusedX1Fn{13: wrapX1(sipHash24FusedChain13x1GprAsm), 20: wrapX1(sipHash24FusedChain20x1GprAsm),
		36: wrapX1(sipHash24FusedChain36x1GprAsm), 68: wrapX1(sipHash24FusedChain68x1GprAsm)}
}

// saveFusedFlags snapshots the fused dispatch flags and registers a
// Cleanup that restores them.
func saveFusedFlags(t *testing.T) {
	t.Helper()
	a512, a2 := FusedHasAVX512, FusedHasAVX2
	t.Cleanup(func() { FusedHasAVX512, FusedHasAVX2 = a512, a2 })
}

// TestFusedKernelParityAmd64 pins every fused kernel the host can execute
// to the pure-Go cascade by direct call, independent of the dispatch
// flags: the four-lane kernels of each tier and the single-lane GPR
// kernels.
func TestFusedKernelParityAmd64(t *testing.T) {
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range shapes {
				t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, tier.name+"-x4", n, tier.x4[n]) })
			}
		})
	}
	t.Run("gpr", func(t *testing.T) {
		x1 := gprX1Kernels()
		for _, n := range shapes {
			t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "gpr-x1", n, x1[n]) })
		}
	})
}

// TestFusedDispatcherTiers installs each fused dispatch state the host
// can execute — both flags set atomically per tier, plus the scalar
// state — and pins the public dispatchers' output to the reference.
func TestFusedDispatcherTiers(t *testing.T) {
	saveFusedFlags(t)
	tiers := append(amd64FusedTiers(), fusedTier{name: "scalar", ok: true})
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	x1 := map[int]fusedX1Fn{13: FusedChain13x1, 20: FusedChain20x1, 36: FusedChain36x1, 68: FusedChain68x1}
	for _, tier := range tiers {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			FusedHasAVX512, FusedHasAVX2 = tier.avx512, tier.avx2
			for _, n := range shapes {
				t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "dispatch-"+tier.name+"-x4", n, x4[n]) })
				t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "dispatch-"+tier.name+"-x1", n, x1[n]) })
			}
		})
	}
}

// TestFusedCrossTier requires every assembly tier the host can execute
// to agree with each other byte for byte on the same inputs.
func TestFusedCrossTier(t *testing.T) {
	saveFusedFlags(t)
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	tiers := append(amd64FusedTiers(), fusedTier{name: "scalar", ok: true})
	for _, n := range shapes {
		for _, pairs := range pairCounts {
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			for lane := range bufs {
				binary.LittleEndian.PutUint32(bufs[lane], uint32(pairs*8+lane))
			}
			var first [4][2]uint64
			firstName := ""
			for _, tier := range tiers {
				if !tier.ok {
					continue
				}
				FusedHasAVX512, FusedHasAVX2 = tier.avx512, tier.avx2
				var out [4][2]uint64
				x4[n](comps, &ptrs, &out)
				if firstName == "" {
					first, firstName = out, tier.name
					continue
				}
				if out != first {
					t.Fatalf("n=%d pairs=%d: %s differs from %s", n, pairs, tier.name, firstName)
				}
			}
		}
	}
}

// TestFusedFlagsExclusive pins the fused auto-selection to at most one tier.
func TestFusedFlagsExclusive(t *testing.T) {
	if FusedHasAVX512 && FusedHasAVX2 {
		t.Fatal("both fused tier flags active")
	}
	if FusedAvailable() != (FusedHasAVX512 || FusedHasAVX2) {
		t.Fatal("FusedAvailable disagrees with the flags")
	}
}

// BenchmarkFusedTier times every fused tier the host can execute, per
// shape and per cascade length (4 and 8 pairs = 512- and 1024-bit keys),
// plus the single-lane GPR kernel, with a component ring so no store
// lands immediately ahead of the kernel's first components load.
func BenchmarkFusedTier(b *testing.B) {
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range shapes {
			for _, pairs := range []int{4, 8} {
				k := tier.x4[n]
				b.Run(fmt.Sprintf("%s/x4/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					var ring [8][]uint64
					for i := range ring {
						ring[i] = randomComponents(pairs)
					}
					_, ptrs := makeLaneData(n)
					var out [4][2]uint64
					b.SetBytes(int64(4 * n))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						k(ring[i&7], &ptrs, &out)
					}
				})
			}
		}
	}
	x1 := gprX1Kernels()
	for _, n := range shapes {
		for _, pairs := range []int{4, 8} {
			b.Run(fmt.Sprintf("gpr/x1/shape%d/pairs%d", n, pairs), func(b *testing.B) {
				var ring [8][]uint64
				for i := range ring {
					ring[i] = randomComponents(pairs)
				}
				_, ptrs := makeLaneData(n)
				var out [2]uint64
				b.SetBytes(int64(n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					x1[n](ring[i&7], ptrs[0], &out)
				}
			})
			b.Run(fmt.Sprintf("scalar/x1/shape%d/pairs%d", n, pairs), func(b *testing.B) {
				var ring [8][]uint64
				for i := range ring {
					ring[i] = randomComponents(pairs)
				}
				bufs, _ := makeLaneData(n)
				var out [2]uint64
				b.SetBytes(int64(n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out[0], out[1] = ScalarFusedChain(ring[i&7], bufs[0])
				}
			})
		}
	}
}

// BenchmarkFusedTierPix times every fused tier under the production
// call pattern of Seed128.blockHash128x4 -> BatchFusedChain: a 4-byte
// pixel-index store into offset 0 of every lane buffer immediately ahead
// of the kernel call, components stable across calls.
func BenchmarkFusedTierPix(b *testing.B) {
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range []int{20, 36, 68} {
			for _, pairs := range []int{4, 8} {
				k := tier.x4[n]
				b.Run(fmt.Sprintf("%s/x4/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					comps := randomComponents(pairs)
					bufs, ptrs := makeLaneData(n)
					var out [4][2]uint64
					b.SetBytes(int64(4 * n))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for l := 0; l < 4; l++ {
							binary.LittleEndian.PutUint32(bufs[l], uint32(4*i+l))
						}
						k(comps, &ptrs, &out)
					}
				})
			}
		}
	}
}

// TestFusedDispatchersZeroAllocTiers runs the allocation check under
// every dispatch state the host can execute: each fused tier with its
// batch-16 arm, the eight-lane arm armed and disarmed on the AVX-512
// tier, and the scalar state.
func TestFusedDispatchersZeroAllocTiers(t *testing.T) {
	saveFusedFlags(t)
	x16, x8 := [2]bool{HasAVX512X16, HasAVX2X16}, FusedHasAVX512X8
	t.Cleanup(func() { HasAVX512X16, HasAVX2X16, FusedHasAVX512X8 = x16[0], x16[1], x8 })
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, armX8 := range []bool{false, true} {
			if armX8 && !tier.avx512 {
				continue
			}
			label := tier.name
			if tier.avx512 {
				label += map[bool]string{false: "-x4", true: "-x8"}[armX8]
			}
			FusedHasAVX512, FusedHasAVX2 = tier.avx512, tier.avx2
			HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
			FusedHasAVX512X8 = armX8
			checkDispatchersZeroAlloc(t, label)
		}
	}
	FusedHasAVX512, FusedHasAVX2, HasAVX512X16, HasAVX2X16, FusedHasAVX512X8 = false, false, false, false, false
	checkDispatchersZeroAlloc(t, "scalar")
}
