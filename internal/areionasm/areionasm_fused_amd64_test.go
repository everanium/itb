//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// fusedTier describes one amd64 fused dispatch state: the silicon it
// needs and the flag values that select it.
type fusedTier struct {
	name    string
	ok      bool
	skipMsg string
	zmm     bool
	ymm     bool
	xmm     bool
}

func amd64FusedTiers() []fusedTier {
	return []fusedTier{
		{name: "aesni", ok: aes.CPU.HasAESNI, skipMsg: "requires AES-NI", xmm: true},
		{name: "vaesavx2", ok: aes.CPU.HasVAES && aes.CPU.HasAVX2, skipMsg: "requires VAES+AVX2", ymm: true},
		{name: "avx512", ok: aes.CPU.HasVAES && aes.CPU.HasAVX512, skipMsg: "requires VAES+AVX-512", zmm: true},
	}
}

func saveFusedFlags(t *testing.T) {
	t.Helper()
	a, b, c := FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI
	x, y, z := HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16
	t.Cleanup(func() {
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = a, b, c
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = x, y, z
	})
}

func setTier(tier fusedTier) {
	FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI = tier.zmm, tier.ymm, tier.xmm
	HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = tier.zmm, tier.ymm, tier.xmm
}

func wrap4_256(f func(*[32]byte, *uint64, int, *[4]*byte, *[4][4]uint64)) x4fn256 {
	return func(k *[32]byte, c []uint64, p *[4]*byte, o *[4][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}
func wrap1_256(f func(*[32]byte, *uint64, int, *byte, *[4]uint64)) x1fn256 {
	return func(k *[32]byte, c []uint64, d *byte, o *[4]uint64) { f(k, &c[0], len(c)/4, d, o) }
}
func wrap4_512(f func(*[64]byte, *uint64, int, *[4]*byte, *[4][8]uint64)) x4fn512 {
	return func(k *[64]byte, c []uint64, p *[4]*byte, o *[4][8]uint64) { f(k, &c[0], len(c)/8, p, o) }
}
func wrap1_512(f func(*[64]byte, *uint64, int, *byte, *[8]uint64)) x1fn512 {
	return func(k *[64]byte, c []uint64, d *byte, o *[8]uint64) { f(k, &c[0], len(c)/8, d, o) }
}

var kernels256x4 = map[string]map[int]x4fn256{
	"avx512":   {13: wrap4_256(areion256FusedChain13x4Avx512Asm), 20: wrap4_256(areion256FusedChain20x4Avx512Asm), 36: wrap4_256(areion256FusedChain36x4Avx512Asm), 68: wrap4_256(areion256FusedChain68x4Avx512Asm)},
	"vaesavx2": {13: wrap4_256(areion256FusedChain13x4VaesAvx2Asm), 20: wrap4_256(areion256FusedChain20x4VaesAvx2Asm), 36: wrap4_256(areion256FusedChain36x4VaesAvx2Asm), 68: wrap4_256(areion256FusedChain68x4VaesAvx2Asm)},
	"aesni":    {13: wrap4_256(areion256FusedChain13x4AesNiAsm), 20: wrap4_256(areion256FusedChain20x4AesNiAsm), 36: wrap4_256(areion256FusedChain36x4AesNiAsm), 68: wrap4_256(areion256FusedChain68x4AesNiAsm)},
}

var kernels512x4 = map[string]map[int]x4fn512{
	"avx512":   {13: wrap4_512(areion512FusedChain13x4Avx512Asm), 20: wrap4_512(areion512FusedChain20x4Avx512Asm), 36: wrap4_512(areion512FusedChain36x4Avx512Asm), 68: wrap4_512(areion512FusedChain68x4Avx512Asm)},
	"vaesavx2": {13: wrap4_512(areion512FusedChain13x4VaesAvx2Asm), 20: wrap4_512(areion512FusedChain20x4VaesAvx2Asm), 36: wrap4_512(areion512FusedChain36x4VaesAvx2Asm), 68: wrap4_512(areion512FusedChain68x4VaesAvx2Asm)},
	"aesni":    {13: wrap4_512(areion512FusedChain13x4AesNiAsm), 20: wrap4_512(areion512FusedChain20x4AesNiAsm), 36: wrap4_512(areion512FusedChain36x4AesNiAsm), 68: wrap4_512(areion512FusedChain68x4AesNiAsm)},
}

var kernels256x1 = map[int]x1fn256{13: wrap1_256(areion256FusedChain13x1AesNiAsm), 20: wrap1_256(areion256FusedChain20x1AesNiAsm), 36: wrap1_256(areion256FusedChain36x1AesNiAsm), 68: wrap1_256(areion256FusedChain68x1AesNiAsm)}
var kernels512x1 = map[int]x1fn512{13: wrap1_512(areion512FusedChain13x1AesNiAsm), 20: wrap1_512(areion512FusedChain20x1AesNiAsm), 36: wrap1_512(areion512FusedChain36x1AesNiAsm), 68: wrap1_512(areion512FusedChain68x1AesNiAsm)}

// TestFusedKernelParityAmd64 pins every kernel the host can execute to
// the pure-Go cascade by direct call, independent of the dispatch flags.
func TestFusedKernelParityAmd64(t *testing.T) {
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range Shapes {
				t.Run("256x4/"+shapeName(n), func(t *testing.T) { checkX4_256(t, tier.name, n, kernels256x4[tier.name][n]) })
				t.Run("512x4/"+shapeName(n), func(t *testing.T) { checkX4_512(t, tier.name, n, kernels512x4[tier.name][n]) })
			}
			if tier.xmm {
				for _, n := range Shapes {
					t.Run("256x1/"+shapeName(n), func(t *testing.T) { checkX1_256(t, tier.name, n, kernels256x1[n]) })
					t.Run("512x1/"+shapeName(n), func(t *testing.T) { checkX1_512(t, tier.name, n, kernels512x1[n]) })
				}
			}
			if tier.zmm {
				t.Run("fill256x8", func(t *testing.T) {
					checkFill256(t, "avx512-x8", func(k *[32]byte, c []uint64, base uint64, o *[8][4]uint64) {
						areion256FusedChain13x8Avx512Asm(k, &c[0], len(c)/4, base, o)
					})
				})
			}
		})
	}
}

// TestFusedDispatcherTiersAmd64 installs every executable dispatch state
// in turn and pins the dispatchers and the allocation guard under each,
// then the scalar state.
func TestFusedDispatcherTiersAmd64(t *testing.T) {
	saveFusedFlags(t)
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			setTier(tier)
			checkDispatchers(t, tier.name)
			checkZeroAlloc(t, tier.name)
		})
	}
	t.Run("scalar", func(t *testing.T) {
		setTier(fusedTier{})
		checkDispatchers(t, "scalar")
		checkZeroAlloc(t, "scalar")
	})
}

// TestFusedCrossTierAmd64 feeds the same inputs to every executable
// four-lane kernel of a shape and requires identical output.
func TestFusedCrossTierAmd64(t *testing.T) {
	for _, n := range Shapes {
		key256, key512 := randomKey256(), randomKey512()
		c256, c512 := randomWords(16), randomWords(32)
		_, ptrs := laneData(n)
		var ref256 *[4][4]uint64
		var ref512 *[4][8]uint64
		for _, tier := range amd64FusedTiers() {
			if !tier.ok {
				continue
			}
			var o256 [4][4]uint64
			var o512 [4][8]uint64
			kernels256x4[tier.name][n](key256, c256, &ptrs, &o256)
			kernels512x4[tier.name][n](key512, c512, &ptrs, &o512)
			if ref256 == nil {
				ref256, ref512 = &o256, &o512
				continue
			}
			if o256 != *ref256 || o512 != *ref512 {
				t.Fatalf("shape %d: tier %s diverges from the first executable tier", n, tier.name)
			}
		}
	}
}

// TestFusedFlagsExclusiveAmd64 pins that auto-detection selects at most
// one fused tier and one fill tier.
func TestFusedFlagsExclusiveAmd64(t *testing.T) {
	count := func(b ...bool) int {
		n := 0
		for _, v := range b {
			if v {
				n++
			}
		}
		return n
	}
	if count(FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI) > 1 {
		t.Fatalf("fused flags not exclusive: zmm=%v ymm=%v xmm=%v", FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAESNI)
	}
	if count(HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16) > 1 {
		t.Fatalf("fill flags not exclusive: zmm=%v ymm=%v xmm=%v", HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16)
	}
}

// BenchmarkFusedTier measures every executable tier's four-lane kernel
// at the four shapes and the three shipped key sizes.
func BenchmarkFusedTier(b *testing.B) {
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range Shapes {
			for _, g := range []int{2, 4, 8} {
				key256, key512 := randomKey256(), randomKey512()
				c256, c512 := randomWords(4*g), randomWords(8*g)
				_, ptrs := laneData(n)
				var o256 [4][4]uint64
				var o512 [4][8]uint64
				f256, f512 := kernels256x4[tier.name][n], kernels512x4[tier.name][n]
				b.Run(fmt.Sprintf("%s/256x4/%s/groups%d", tier.name, shapeName(n), g), func(b *testing.B) {
					b.SetBytes(int64(4 * n))
					for i := 0; i < b.N; i++ {
						f256(key256, c256, &ptrs, &o256)
					}
				})
				b.Run(fmt.Sprintf("%s/512x4/%s/groups%d", tier.name, shapeName(n), g), func(b *testing.B) {
					b.SetBytes(int64(4 * n))
					for i := 0; i < b.N; i++ {
						f512(key512, c512, &ptrs, &o512)
					}
				})
			}
		}
	}
}

// BenchmarkFill measures the batch-16 fill hooks under every executable
// fill tier.
func BenchmarkFill(b *testing.B) {
	saveFlags := func() func() {
		x, y, z := HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16
		return func() { HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = x, y, z }
	}
	restore := saveFlags()
	defer restore()
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAESNIX16 = tier.zmm, tier.ymm, tier.xmm
		for _, g := range []int{3, 5, 9} {
			key256, key512 := randomKey256(), randomKey512()
			c256, c512 := randomWords(4*g), randomWords(8*g)
			var o8 [8][4]uint64
			var o4 [4][8]uint64
			b.Run(fmt.Sprintf("%s/fill256x8/groups%d", tier.name, g), func(b *testing.B) {
				b.SetBytes(8 * 13)
				for i := 0; i < b.N; i++ {
					Fused256Fill13x8(key256, c256, uint64(i)*8, &o8)
				}
			})
			b.Run(fmt.Sprintf("%s/fill512x4/groups%d", tier.name, g), func(b *testing.B) {
				b.SetBytes(4 * 13)
				for i := 0; i < b.N; i++ {
					Fused512Fill13x4(key512, c512, uint64(i)*4, &o4)
				}
			})
		}
	}
}
