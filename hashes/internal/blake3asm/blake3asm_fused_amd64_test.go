//go:build amd64 && !purego && !noitbasm

package blake3asm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

// cascadeTier describes one amd64 fused dispatch state: the silicon it
// needs and the flag values that select it.
type cascadeTier struct {
	name    string
	ok      bool
	skipMsg string
	avx512  bool
	avx2    bool
}

func amd64CascadeTiers() []cascadeTier {
	return []cascadeTier{
		{name: "avx2", ok: cpu.X86.HasAVX2, skipMsg: "requires AVX2", avx2: true},
		{name: "avx512", ok: cpu.X86.HasAVX512F, skipMsg: "requires AVX-512F", avx512: true},
	}
}

func saveCascadeFlags(t *testing.T) {
	t.Helper()
	a, b := FusedHasAVX512, FusedHasAVX2
	x, y := HasAVX512X16, HasAVX2X16
	t.Cleanup(func() {
		FusedHasAVX512, FusedHasAVX2 = a, b
		HasAVX512X16, HasAVX2X16 = x, y
	})
}

func setCascadeTier(tier cascadeTier) {
	FusedHasAVX512, FusedHasAVX2 = tier.avx512, tier.avx2
	HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
}

func wrap4_256(f func(*[32]byte, *uint64, int, *[4]*byte, *[4][4]uint64)) x4fn256 {
	return func(k *[32]byte, c []uint64, p *[4]*byte, o *[4][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}

var kernels256x4 = map[string]map[int]x4fn256{
	"avx512": {13: wrap4_256(blake3FusedChain13x4Avx512Asm), 20: wrap4_256(blake3FusedChain20x4Avx512Asm), 36: wrap4_256(blake3FusedChain36x4Avx512Asm), 68: wrap4_256(blake3FusedChain68x4Avx512Asm)},
	"avx2":   {13: wrap4_256(blake3FusedChain13x4Avx2Asm), 20: wrap4_256(blake3FusedChain20x4Avx2Asm), 36: wrap4_256(blake3FusedChain36x4Avx2Asm), 68: wrap4_256(blake3FusedChain68x4Avx2Asm)},
}

// TestFusedKernelParityAmd64 pins every four-lane kernel the host can
// execute to the pure-Go cascade by direct call, independent of the
// dispatch flags.
func TestFusedKernelParityAmd64(t *testing.T) {
	for _, tier := range amd64CascadeTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range Shapes {
				t.Run("256x4/"+shapeName(n), func(t *testing.T) { checkX4_256(t, tier.name, n, kernels256x4[tier.name][n]) })
			}
		})
	}
}

// TestFusedDispatcherTiersAmd64 installs every executable dispatch state
// in turn and pins the dispatchers and the allocation guard under each,
// then the scalar state.
func TestFusedDispatcherTiersAmd64(t *testing.T) {
	saveCascadeFlags(t)
	for _, tier := range amd64CascadeTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			setCascadeTier(tier)
			checkDispatchers(t, tier.name)
			checkZeroAlloc(t, tier.name)
		})
	}
	t.Run("scalar", func(t *testing.T) {
		setCascadeTier(cascadeTier{})
		checkDispatchers(t, "scalar")
		checkZeroAlloc(t, "scalar")
	})
}

// TestFusedCrossTierAmd64 feeds the same inputs to every executable
// four-lane kernel of a shape and requires identical output.
func TestFusedCrossTierAmd64(t *testing.T) {
	for _, n := range Shapes {
		key256 := randomKey256()
		c256 := randomWords(16)
		_, ptrs := laneData(n)
		var ref256 *[4][4]uint64
		for _, tier := range amd64CascadeTiers() {
			if !tier.ok {
				continue
			}
			var o256 [4][4]uint64
			kernels256x4[tier.name][n](key256, c256, &ptrs, &o256)
			if ref256 == nil {
				ref256 = &o256
				continue
			}
			if o256 != *ref256 {
				t.Fatalf("shape %d: tier %s diverges from the first executable tier", n, tier.name)
			}
		}
	}
}

// TestFusedFlagsExclusiveAmd64 pins that auto-detection selects at most
// one fused tier and one fill tier.
func TestFusedFlagsExclusiveAmd64(t *testing.T) {
	if FusedHasAVX512 && FusedHasAVX2 {
		t.Fatal("fused flags not exclusive")
	}
	if HasAVX512X16 && HasAVX2X16 {
		t.Fatal("fill flags not exclusive")
	}
}

// BenchmarkFusedTier measures every executable tier's four-lane kernel
// at the four shapes and the three shipped key sizes.
func BenchmarkFusedTier(b *testing.B) {
	for _, tier := range amd64CascadeTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range Shapes {
			for _, g := range []int{2, 4, 8} {
				key256 := randomKey256()
				c256 := randomWords(4 * g)
				_, ptrs := laneData(n)
				var o256 [4][4]uint64
				f256 := kernels256x4[tier.name][n]
				b.Run(fmt.Sprintf("%s/256x4/%s/groups%d", tier.name, shapeName(n), g), func(b *testing.B) {
					b.SetBytes(int64(4 * n))
					for i := 0; i < b.N; i++ {
						f256(key256, c256, &ptrs, &o256)
					}
				})
			}
		}
	}
}

// BenchmarkFill measures the batch-16 fill hook under every executable
// fill tier.
func BenchmarkFill(b *testing.B) {
	x, y := HasAVX512X16, HasAVX2X16
	defer func() { HasAVX512X16, HasAVX2X16 = x, y }()
	for _, tier := range amd64CascadeTiers() {
		if !tier.ok {
			continue
		}
		HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
		for _, g := range []int{3, 5, 9} {
			key256 := randomKey256()
			c256 := randomWords(4 * g)
			var o8 [8][4]uint64
			b.Run(fmt.Sprintf("%s/fill256x8/groups%d", tier.name, g), func(b *testing.B) {
				b.SetBytes(8 * 13)
				for i := 0; i < b.N; i++ {
					Fused256Fill13x8(key256, c256, uint64(i)*8, &o8)
				}
			})
		}
	}
}
