//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

func wrap8_256(f func(*[32]byte, *uint64, int, *[8]*byte, *[8][4]uint64)) x8fn256 {
	return func(k *[32]byte, c []uint64, p *[8]*byte, o *[8][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}
func wrap8_512(f func(*[64]byte, *uint64, int, *[8]*byte, *[8][8]uint64)) x8fn512 {
	return func(k *[64]byte, c []uint64, p *[8]*byte, o *[8][8]uint64) { f(k, &c[0], len(c)/8, p, o) }
}

var kernels256x8 = map[int]x8fn256{20: wrap8_256(areion256FusedChain20x8Avx512Asm), 36: wrap8_256(areion256FusedChain36x8Avx512Asm), 68: wrap8_256(areion256FusedChain68x8Avx512Asm)}
var kernels512x8 = map[int]x8fn512{20: wrap8_512(areion512FusedChain20x8Avx512Asm), 36: wrap8_512(areion512FusedChain36x8Avx512Asm), 68: wrap8_512(areion512FusedChain68x8Avx512Asm)}

func fill512x8Kernel(k *[64]byte, c []uint64, base uint64, o *[8][8]uint64) {
	areion512FusedChain13x8Avx512Asm(k, &c[0], len(c)/8, base, o)
}

func hasZMM() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX512 }

// TestFusedWideKernelParityAmd64 pins every wide ZMM kernel to the
// pure-Go cascade by direct call, independent of the dispatch flags.
func TestFusedWideKernelParityAmd64(t *testing.T) {
	if !hasZMM() {
		t.Skip("requires VAES+AVX-512")
	}
	for n := range kernels256x8 {
		t.Run("256x8/"+shapeName(n), func(t *testing.T) { checkX8_256(t, "avx512", n, kernels256x8[n]) })
		t.Run("512x8/"+shapeName(n), func(t *testing.T) { checkX8_512(t, "avx512", n, kernels512x8[n]) })
	}
	t.Run("fill512x8", func(t *testing.T) { checkFill512X8(t, "avx512-x8", fill512x8Kernel) })
}

// TestFusedWideDispatcherTiersAmd64 installs every executable dispatch
// state in turn — with the eight-lane per-pixel arm armed and disarmed
// — and pins the wide dispatchers and the allocation guard under each,
// then the scalar state.
func TestFusedWideDispatcherTiersAmd64(t *testing.T) {
	saveFusedFlags(t)
	x8 := FusedHasVAESAVX512X8
	t.Cleanup(func() { FusedHasVAESAVX512X8 = x8 })
	for _, tier := range amd64FusedTiers() {
		for _, arm := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/x8arm=%v", tier.name, arm), func(t *testing.T) {
				if !tier.ok {
					t.Skip(tier.skipMsg)
				}
				setTier(tier)
				FusedHasVAESAVX512X8 = arm
				if FusedX8Active() != (arm && tier.zmm) {
					t.Fatalf("FusedX8Active=%v under tier %s arm=%v", FusedX8Active(), tier.name, arm)
				}
				checkWideDispatchers(t, tier.name)
				checkWideZeroAlloc(t, tier.name)
			})
		}
	}
	t.Run("scalar", func(t *testing.T) {
		setTier(fusedTier{})
		FusedHasVAESAVX512X8 = true
		if FusedX8Active() {
			t.Fatal("FusedX8Active under the scalar state")
		}
		checkWideDispatchers(t, "scalar")
		checkWideZeroAlloc(t, "scalar")
	})
}

// BenchmarkFillWide measures the width-512 batch-32 fill kernel of the
// ZMM tier against two four-lane calls over Go-synthesised blocks.
func BenchmarkFillWide(b *testing.B) {
	if !hasZMM() {
		b.Skip("requires VAES+AVX-512")
	}
	for _, g := range []int{2, 4, 8} {
		key512 := randomKey512()
		c512 := randomWords(8 * g)
		var o8 [8][8]uint64
		b.Run(fmt.Sprintf("fill512/x8/groups%d", g), func(b *testing.B) {
			b.SetBytes(8 * 13)
			for i := 0; i < b.N; i++ {
				fill512x8Kernel(key512, c512, uint64(i)*8, &o8)
			}
		})
		b.Run(fmt.Sprintf("fill512/2x4/groups%d", g), func(b *testing.B) {
			b.SetBytes(8 * 13)
			var blocks [4][13]byte
			for i := 0; i < b.N; i++ {
				for h := 0; h < 2; h++ {
					ptrs := fillPtrs4(&blocks, uint64(i)*8+uint64(4*h))
					areion512FusedChain13x4Avx512Asm(key512, &c512[0], g, &ptrs, out8x512Half(&o8, h))
				}
			}
		})
	}
}

// BenchmarkPixelWide measures the eight-lane per-pixel ZMM kernels
// against two four-lane ZMM calls over the same lanes.
func BenchmarkPixelWide(b *testing.B) {
	if !hasZMM() {
		b.Skip("requires VAES+AVX-512")
	}
	for _, n := range []int{20, 36, 68} {
		for _, g := range []int{2, 4, 8} {
			key256, key512 := randomKey256(), randomKey512()
			c256, c512 := randomWords(4*g), randomWords(8*g)
			_, ptrs := laneData8(n)
			var o256 [8][4]uint64
			var o512 [8][8]uint64
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
			b.Run(fmt.Sprintf("512/x8/%s/groups%d", shapeName(n), g), func(b *testing.B) {
				b.SetBytes(int64(8 * n))
				for i := 0; i < b.N; i++ {
					kernels512x8[n](key512, c512, &ptrs, &o512)
				}
			})
			b.Run(fmt.Sprintf("512/2x4/%s/groups%d", shapeName(n), g), func(b *testing.B) {
				b.SetBytes(int64(8 * n))
				f := kernels512x4["avx512"][n]
				for i := 0; i < b.N; i++ {
					f(key512, c512, ptrs8Half(&ptrs, 0), out8x512Half(&o512, 0))
					f(key512, c512, ptrs8Half(&ptrs, 1), out8x512Half(&o512, 1))
				}
			})
		}
	}
}
