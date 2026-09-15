//go:build amd64 && !purego && !noitbasm

package blake3asm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

func wrap8_256(f func(*[32]byte, *uint64, int, *[8]*byte, *[8][4]uint64)) x8fn256 {
	return func(k *[32]byte, c []uint64, p *[8]*byte, o *[8][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}

var kernels256x8 = map[int]x8fn256{20: wrap8_256(blake3FusedChain20x8Avx512Asm), 36: wrap8_256(blake3FusedChain36x8Avx512Asm), 68: wrap8_256(blake3FusedChain68x8Avx512Asm)}

func fill256x8Kernel(k *[32]byte, c []uint64, base uint64, o *[8][4]uint64) {
	blake3FusedChain13x8Avx512Asm(k, &c[0], len(c)/4, base, o)
}

func hasEVEX() bool { return cpu.X86.HasAVX512F }

// TestFusedWideKernelParityAmd64 pins every eight-lane YMM kernel to the
// pure-Go cascade by direct call, independent of the dispatch flags.
func TestFusedWideKernelParityAmd64(t *testing.T) {
	if !hasEVEX() {
		t.Skip("requires AVX-512F")
	}
	for n := range kernels256x8 {
		t.Run("256x8/"+shapeName(n), func(t *testing.T) { checkX8_256(t, "avx512", n, kernels256x8[n]) })
	}
	t.Run("fill256x8", func(t *testing.T) { checkFill256(t, "avx512-x8", fill256x8Kernel) })
}

// TestFusedWideDispatcherTiersAmd64 installs every executable dispatch
// state in turn — with the eight-lane per-pixel arm armed and disarmed
// — and pins the wide dispatchers and the allocation guard under each,
// then the scalar state.
func TestFusedWideDispatcherTiersAmd64(t *testing.T) {
	saveCascadeFlags(t)
	x8 := FusedHasAVX512X8
	t.Cleanup(func() { FusedHasAVX512X8 = x8 })
	for _, tier := range amd64CascadeTiers() {
		for _, arm := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/x8arm=%v", tier.name, arm), func(t *testing.T) {
				if !tier.ok {
					t.Skip(tier.skipMsg)
				}
				setCascadeTier(tier)
				FusedHasAVX512X8 = arm
				if FusedX8Active() != (arm && tier.avx512) {
					t.Fatalf("FusedX8Active=%v under tier %s arm=%v", FusedX8Active(), tier.name, arm)
				}
				checkWideDispatchers(t, tier.name)
				checkWideZeroAlloc(t, tier.name)
			})
		}
	}
	t.Run("scalar", func(t *testing.T) {
		setCascadeTier(cascadeTier{})
		FusedHasAVX512X8 = true
		if FusedX8Active() {
			t.Fatal("FusedX8Active under the scalar state")
		}
		checkWideDispatchers(t, "scalar")
		checkWideZeroAlloc(t, "scalar")
	})
}

// BenchmarkFillWide measures the batch-16 fill kernel of the EVEX tier
// against two four-lane calls over Go-synthesised blocks.
func BenchmarkFillWide(b *testing.B) {
	if !hasEVEX() {
		b.Skip("requires AVX-512F")
	}
	for _, g := range []int{2, 4, 8} {
		key256 := randomKey256()
		c256 := randomWords(4 * g)
		var o8 [8][4]uint64
		b.Run(fmt.Sprintf("fill256/x8/groups%d", g), func(b *testing.B) {
			b.SetBytes(8 * 13)
			for i := 0; i < b.N; i++ {
				fill256x8Kernel(key256, c256, uint64(i)*8, &o8)
			}
		})
		b.Run(fmt.Sprintf("fill256/2x4/groups%d", g), func(b *testing.B) {
			b.SetBytes(8 * 13)
			var blocks [4][13]byte
			for i := 0; i < b.N; i++ {
				for h := 0; h < 2; h++ {
					ptrs := fillPtrs4(&blocks, uint64(i)*8+uint64(4*h))
					blake3FusedChain13x4Avx512Asm(key256, &c256[0], g, &ptrs, out8x256Half(&o8, h))
				}
			}
		})
	}
}

// BenchmarkPixelWide measures the eight-lane per-pixel YMM kernels
// against two four-lane XMM calls over the same lanes.
func BenchmarkPixelWide(b *testing.B) {
	if !hasEVEX() {
		b.Skip("requires AVX-512F")
	}
	for _, n := range []int{20, 36, 68} {
		for _, g := range []int{2, 4, 8} {
			key256 := randomKey256()
			c256 := randomWords(4 * g)
			_, ptrs := laneData8(n)
			var o256 [8][4]uint64
			b.Run(fmt.Sprintf("256/x8/%s/groups%d", shapeName(n), g), func(b *testing.B) {
				b.SetBytes(int64(8 * n))
				for i := 0; i < b.N; i++ {
					kernels256x8[n](key256, c256, &ptrs, &o256)
				}
			})
			b.Run(fmt.Sprintf("256/2x4/%s/groups%d", shapeName(n), g), func(b *testing.B) {
				b.SetBytes(int64(8 * n))
				f := kernels256x4["avx512"][n]
				for i := 0; i < b.N; i++ {
					f(key256, c256, ptrs8Half(&ptrs, 0), out8x256Half(&o256, 0))
					f(key256, c256, ptrs8Half(&ptrs, 1), out8x256Half(&o256, 1))
				}
			})
		}
	}
}

func wrap1_256(f func(*[32]byte, *uint64, int, *byte, *[4]uint64)) x1fn256 {
	return func(k *[32]byte, c []uint64, d *byte, o *[4]uint64) { f(k, &c[0], len(c)/4, d, o) }
}

var kernels256x1 = map[int]x1fn256{13: wrap1_256(blake3FusedChain13x1GprAsm), 20: wrap1_256(blake3FusedChain20x1GprAsm), 36: wrap1_256(blake3FusedChain36x1GprAsm), 68: wrap1_256(blake3FusedChain68x1GprAsm)}

// TestFusedGprKernelParityAmd64 pins the single-lane general-purpose-
// register kernels to the pure-Go cascade by direct call.
func TestFusedGprKernelParityAmd64(t *testing.T) {
	for _, n := range Shapes {
		t.Run("256x1/"+shapeName(n), func(t *testing.T) { checkX1_256(t, "gpr", n, kernels256x1[n]) })
	}
}

// BenchmarkGprX1 measures the single-lane kernels against the four-lane
// kernels of both tiers run with the lane replicated and the pure-Go
// cascade.
func BenchmarkGprX1(b *testing.B) {
	for _, n := range Shapes {
		for _, g := range []int{2, 4, 8} {
			key256 := randomKey256()
			c256 := randomWords(4 * g)
			bufs, ptrs := laneData(n)
			var o256 [4]uint64
			var q256 [4][4]uint64
			rep := [4]*byte{ptrs[0], ptrs[0], ptrs[0], ptrs[0]}
			b.Run(fmt.Sprintf("256x1/gpr/%s/groups%d", shapeName(n), g), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					kernels256x1[n](key256, c256, ptrs[0], &o256)
				}
			})
			if hasEVEX() {
				b.Run(fmt.Sprintf("256x1/x4rep/%s/groups%d", shapeName(n), g), func(b *testing.B) {
					f := kernels256x4["avx512"][n]
					for i := 0; i < b.N; i++ {
						f(key256, c256, &rep, &q256)
					}
				})
			}
			if cpu.X86.HasAVX2 {
				b.Run(fmt.Sprintf("256x1/x4rep-avx2/%s/groups%d", shapeName(n), g), func(b *testing.B) {
					f := kernels256x4["avx2"][n]
					for i := 0; i < b.N; i++ {
						f(key256, c256, &rep, &q256)
					}
				})
			}
			b.Run(fmt.Sprintf("256x1/go/%s/groups%d", shapeName(n), g), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					o256 = ScalarFusedChain256(key256, c256, bufs[0])
				}
			})
		}
	}
}
