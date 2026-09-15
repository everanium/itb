//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

type fusedAsmX4 func(*[176]byte, *uint64, int, *[4]*byte, *[4][2]uint64)
type fusedAsmX1 func(*[176]byte, *uint64, int, *byte, *[2]uint64)

func wrapX4(f fusedAsmX4) fusedX4Fn {
	return func(s *Schedule, comps []uint64, ptrs *[4]*byte, out *[4][2]uint64) {
		f(&s.roundKeys, &comps[0], len(comps)/2, ptrs, out)
	}
}

func wrapX1(f fusedAsmX1) fusedX1Fn {
	return func(s *Schedule, comps []uint64, data *byte, out *[2]uint64) {
		f(&s.roundKeys, &comps[0], len(comps)/2, data, out)
	}
}

// fusedTier describes one fused dispatch state: the silicon it needs,
// its kernels and the complete four-flag tuple that selects it.
type fusedTier struct {
	name                 string
	ok                   bool
	skipMsg              string
	x4                   map[int]fusedX4Fn
	x1                   map[int]fusedX1Fn
	zmm, ymm, vex, aesni bool
}

func amd64FusedTiers() []fusedTier {
	return []fusedTier{
		{
			name: "aesni", ok: aes.CPU.HasAESNI, skipMsg: "requires AES-NI",
			x4: map[int]fusedX4Fn{13: wrapX4(aesCMAC128FusedChain13x4AesNiAsm), 20: wrapX4(aesCMAC128FusedChain20x4AesNiAsm),
				36: wrapX4(aesCMAC128FusedChain36x4AesNiAsm), 68: wrapX4(aesCMAC128FusedChain68x4AesNiAsm)},
			x1: map[int]fusedX1Fn{13: wrapX1(aesCMAC128FusedChain13x1AesNiAsm), 20: wrapX1(aesCMAC128FusedChain20x1AesNiAsm),
				36: wrapX1(aesCMAC128FusedChain36x1AesNiAsm), 68: wrapX1(aesCMAC128FusedChain68x1AesNiAsm)},
			aesni: true,
		},
		{
			name: "vex", ok: aes.CPU.HasAESNI && aes.CPU.HasAVX2, skipMsg: "requires AES-NI + AVX",
			x4: map[int]fusedX4Fn{13: wrapX4(aesCMAC128FusedChain13x4VexAsm), 20: wrapX4(aesCMAC128FusedChain20x4VexAsm),
				36: wrapX4(aesCMAC128FusedChain36x4VexAsm), 68: wrapX4(aesCMAC128FusedChain68x4VexAsm)},
			x1: map[int]fusedX1Fn{13: wrapX1(aesCMAC128FusedChain13x1VexAsm), 20: wrapX1(aesCMAC128FusedChain20x1VexAsm),
				36: wrapX1(aesCMAC128FusedChain36x1VexAsm), 68: wrapX1(aesCMAC128FusedChain68x1VexAsm)},
			vex: true,
		},
		{
			name: "vaesavx2", ok: aes.CPU.HasVAES && aes.CPU.HasAVX2, skipMsg: "requires VAES + AVX2",
			x4: map[int]fusedX4Fn{13: wrapX4(aesCMAC128FusedChain13x4VaesAvx2Asm), 20: wrapX4(aesCMAC128FusedChain20x4VaesAvx2Asm),
				36: wrapX4(aesCMAC128FusedChain36x4VaesAvx2Asm), 68: wrapX4(aesCMAC128FusedChain68x4VaesAvx2Asm)},
			ymm: true,
		},
		{
			name: "avx512", ok: aes.CPU.HasVAES && aes.CPU.HasAVX512, skipMsg: "requires VAES + AVX-512",
			x4: map[int]fusedX4Fn{13: wrapX4(aesCMAC128FusedChain13x4Avx512Asm), 20: wrapX4(aesCMAC128FusedChain20x4Avx512Asm),
				36: wrapX4(aesCMAC128FusedChain36x4Avx512Asm), 68: wrapX4(aesCMAC128FusedChain68x4Avx512Asm)},
			zmm: true,
		},
	}
}

// saveFusedFlags snapshots the four fused dispatch flags and registers a
// Cleanup that restores them.
func saveFusedFlags(t *testing.T) {
	t.Helper()
	zmm, ymm, vex, aesni := FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI
	t.Cleanup(func() {
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = zmm, ymm, vex, aesni
	})
}

// TestFusedKernelParityAmd64 pins every fused kernel the host can execute
// to the pure-Go cascade by direct call, independent of the dispatch
// flags.
func TestFusedKernelParityAmd64(t *testing.T) {
	for _, tier := range amd64FusedTiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range shapes {
				if k, ok := tier.x4[n]; ok {
					t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, tier.name+"-x4", n, k) })
				}
				if k, ok := tier.x1[n]; ok {
					t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, tier.name+"-x1", n, k) })
				}
			}
		})
	}
}

// TestFusedDispatcherTiers installs each fused dispatch state the host
// can execute — all four flags set atomically per tier, plus the scalar
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
			FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = tier.zmm, tier.ymm, tier.vex, tier.aesni
			for _, n := range shapes {
				t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "dispatch-"+tier.name+"-x4", n, x4[n]) })
				t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "dispatch-"+tier.name+"-x1", n, x1[n]) })
			}
		})
	}
}

// TestFusedFlagsExclusive pins the fused auto-selection to at most one tier.
func TestFusedFlagsExclusive(t *testing.T) {
	active := 0
	for _, f := range []bool{FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI} {
		if f {
			active++
		}
	}
	if active > 1 {
		t.Fatalf("%d fused tier flags active, want at most 1", active)
	}
	if FusedAvailable() != (active == 1) {
		t.Fatalf("FusedAvailable() = %v with %d flags active", FusedAvailable(), active)
	}
}

// BenchmarkFusedTier times every fused tier the host can execute, per
// shape and per cascade length (4 and 8 pairs = 512- and 1024-bit keys).
// The components vary per call by rotating through a ring of component
// slices — no store lands immediately ahead of the kernel's first
// components load. The production call pattern, with a pixel-index store
// into every lane buffer ahead of each call, is measured by
// BenchmarkFusedTierPix.
func BenchmarkFusedTier(b *testing.B) {
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range shapes {
			for _, pairs := range []int{4, 8} {
				k := tier.x4[n]
				b.Run(fmt.Sprintf("%s/x4/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					s := NewSchedule(ascendingKey())
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
						k(s, ring[i&7], &ptrs, &out)
					}
				})
			}
		}
	}
}
