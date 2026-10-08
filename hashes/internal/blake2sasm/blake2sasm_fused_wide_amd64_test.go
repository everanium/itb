//go:build amd64 && !purego && !noitbasm

package blake2sasm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

func wrap8_256(f func(*[32]byte, *uint64, int, *[8]*byte, *[8][4]uint64)) x8fn256 {
	return func(k *[32]byte, c []uint64, p *[8]*byte, o *[8][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}

// kernels256x8 maps each tier to its eight-lane per-pixel kernels.
var kernels256x8 = map[string]map[int]x8fn256{
	"avx512": {20: wrap8_256(blake2sFusedChain20x8Avx512Asm), 36: wrap8_256(blake2sFusedChain36x8Avx512Asm), 68: wrap8_256(blake2sFusedChain68x8Avx512Asm)},
	"avx2":   {20: wrap8_256(blake2sFusedChain20x8Avx2Asm), 36: wrap8_256(blake2sFusedChain36x8Avx2Asm), 68: wrap8_256(blake2sFusedChain68x8Avx2Asm)},
}

type fill8fn256 func(*[32]byte, []uint64, uint64, *[8][4]uint64)

func wrapFill8_256(f func(*[32]byte, *uint64, int, uint64, *[8][4]uint64)) fill8fn256 {
	return func(k *[32]byte, c []uint64, base uint64, o *[8][4]uint64) { f(k, &c[0], len(c)/4, base, o) }
}

// fill256x8Kernels maps each tier to its eight-lane fill kernel.
var fill256x8Kernels = map[string]fill8fn256{
	"avx512": wrapFill8_256(blake2sFusedChain13x8Avx512Asm),
	"avx2":   wrapFill8_256(blake2sFusedChain13x8Avx2Asm),
}

func hasEVEX() bool { return cpu.X86.HasAVX512F }

// setX8Arm sets every eight-lane arm flag as one set.
func setX8Arm(arm bool) { FusedHasAVX512X8, FusedHasAVX2X8 = arm, arm }

// TestFusedWideKernelParityAmd64 pins every eight-lane YMM kernel of
// every tier the host can execute to the pure-Go cascade by direct
// call, independent of the dispatch flags.
func TestFusedWideKernelParityAmd64(t *testing.T) {
	for _, tier := range amd64CascadeTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for n := range kernels256x8[tier.name] {
				t.Run("256x8/"+shapeName(n), func(t *testing.T) { checkX8_256(t, tier.name, n, kernels256x8[tier.name][n]) })
			}
			t.Run("fill256x8", func(t *testing.T) { checkFill256(t, tier.name+"-x8", fill256x8Kernels[tier.name]) })
		})
	}
}

// TestFusedWideCrossTierAmd64 feeds the same inputs to every executable
// eight-lane kernel of a shape and to two calls of the same tier's
// four-lane kernel, and requires identical output.
func TestFusedWideCrossTierAmd64(t *testing.T) {
	for _, n := range []int{20, 36, 68} {
		key256 := randomKey256()
		c256 := randomWords(16)
		_, ptrs := laneData8(n)
		var ref *[8][4]uint64
		for _, tier := range amd64CascadeTiers() {
			if !tier.ok {
				continue
			}
			var o8, o4 [8][4]uint64
			kernels256x8[tier.name][n](key256, c256, &ptrs, &o8)
			f := kernels256x4[tier.name][n]
			f(key256, c256, ptrs8Half(&ptrs, 0), out8x256Half(&o4, 0))
			f(key256, c256, ptrs8Half(&ptrs, 1), out8x256Half(&o4, 1))
			if o8 != o4 {
				t.Fatalf("shape %d: tier %s eight-lane kernel diverges from two four-lane calls", n, tier.name)
			}
			if ref == nil {
				ref = &o8
				continue
			}
			if o8 != *ref {
				t.Fatalf("shape %d: tier %s eight-lane kernel diverges from the first executable tier", n, tier.name)
			}
		}
	}
	key256 := randomKey256()
	c256 := randomWords(16)
	var ref *[8][4]uint64
	for _, tier := range amd64CascadeTiers() {
		if !tier.ok {
			continue
		}
		var o [8][4]uint64
		fill256x8Kernels[tier.name](key256, c256, 0x0123456789ab, &o)
		if ref == nil {
			ref = &o
			continue
		}
		if o != *ref {
			t.Fatalf("fill: tier %s eight-lane kernel diverges from the first executable tier", tier.name)
		}
	}
}

// TestFusedWideDispatcherTiersAmd64 installs every executable dispatch
// state in turn — with the eight-lane per-pixel arm armed and disarmed
// — and pins the wide dispatchers and the allocation guard under each,
// then the scalar state.
func TestFusedWideDispatcherTiersAmd64(t *testing.T) {
	saveCascadeFlags(t)
	x8, x8avx2 := FusedHasAVX512X8, FusedHasAVX2X8
	t.Cleanup(func() { FusedHasAVX512X8, FusedHasAVX2X8 = x8, x8avx2 })
	for _, tier := range amd64CascadeTiers() {
		for _, arm := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/x8arm=%v", tier.name, arm), func(t *testing.T) {
				if !tier.ok {
					t.Skip(tier.skipMsg)
				}
				setCascadeTier(tier)
				setX8Arm(arm)
				if FusedX8Active() != (arm && (tier.avx512 || tier.avx2)) {
					t.Fatalf("FusedX8Active=%v under tier %s arm=%v", FusedX8Active(), tier.name, arm)
				}
				checkWideDispatchers(t, tier.name)
				checkWideZeroAlloc(t, tier.name)
			})
		}
	}
	t.Run("scalar", func(t *testing.T) {
		setCascadeTier(cascadeTier{})
		setX8Arm(true)
		if FusedX8Active() {
			t.Fatal("FusedX8Active under the scalar state")
		}
		checkWideDispatchers(t, "scalar")
		checkWideZeroAlloc(t, "scalar")
	})
}

// BenchmarkFillWide measures the batch-16 fill kernel of every
// executable tier against two four-lane calls of the same tier over
// Go-synthesised blocks.
func BenchmarkFillWide(b *testing.B) {
	for _, tier := range amd64CascadeTiers() {
		if !tier.ok {
			continue
		}
		for _, g := range []int{2, 4, 8} {
			key256 := randomKey256()
			c256 := randomWords(4 * g)
			var o8 [8][4]uint64
			b.Run(fmt.Sprintf("fill256/%s/x8/groups%d", tier.name, g), func(b *testing.B) {
				b.SetBytes(8 * 13)
				f := fill256x8Kernels[tier.name]
				for i := 0; i < b.N; i++ {
					f(key256, c256, uint64(i)*8, &o8)
				}
			})
			b.Run(fmt.Sprintf("fill256/%s/2x4/groups%d", tier.name, g), func(b *testing.B) {
				b.SetBytes(8 * 13)
				var blocks [4][13]byte
				f := kernels256x4[tier.name][13]
				for i := 0; i < b.N; i++ {
					for h := 0; h < 2; h++ {
						ptrs := fillPtrs4(&blocks, uint64(i)*8+uint64(4*h))
						f(key256, c256, &ptrs, out8x256Half(&o8, h))
					}
				}
			})
		}
	}
}

// BenchmarkPixelWide measures the eight-lane per-pixel YMM kernels of
// every executable tier against two four-lane XMM calls of the same
// tier over the same lanes.
func BenchmarkPixelWide(b *testing.B) {
	for _, tier := range amd64CascadeTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range []int{20, 36, 68} {
			for _, g := range []int{2, 4, 8} {
				key256 := randomKey256()
				c256 := randomWords(4 * g)
				_, ptrs := laneData8(n)
				var o256 [8][4]uint64
				b.Run(fmt.Sprintf("256/%s/x8/%s/groups%d", tier.name, shapeName(n), g), func(b *testing.B) {
					b.SetBytes(int64(8 * n))
					f := kernels256x8[tier.name][n]
					for i := 0; i < b.N; i++ {
						f(key256, c256, &ptrs, &o256)
					}
				})
				b.Run(fmt.Sprintf("256/%s/2x4/%s/groups%d", tier.name, shapeName(n), g), func(b *testing.B) {
					b.SetBytes(int64(8 * n))
					f := kernels256x4[tier.name][n]
					for i := 0; i < b.N; i++ {
						f(key256, c256, ptrs8Half(&ptrs, 0), out8x256Half(&o256, 0))
						f(key256, c256, ptrs8Half(&ptrs, 1), out8x256Half(&o256, 1))
					}
				})
			}
		}
	}
}

func wrap1_256(f func(*[32]byte, *uint64, int, *byte, *[4]uint64)) x1fn256 {
	return func(k *[32]byte, c []uint64, d *byte, o *[4]uint64) { f(k, &c[0], len(c)/4, d, o) }
}

var kernels256x1 = map[int]x1fn256{13: wrap1_256(blake2sFusedChain13x1GprAsm), 20: wrap1_256(blake2sFusedChain20x1GprAsm), 36: wrap1_256(blake2sFusedChain36x1GprAsm), 68: wrap1_256(blake2sFusedChain68x1GprAsm)}

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
