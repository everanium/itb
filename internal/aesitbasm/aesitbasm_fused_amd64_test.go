//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

type fusedAsmX4 func(*[16]byte, *uint64, int, *[4]*byte, *[4][2]uint64)
type fusedAsmX1 func(*[16]byte, *uint64, int, *byte, *[2]uint64)

func wrapX4(f fusedAsmX4) fusedX4Fn {
	return func(key *[16]byte, comps []uint64, ptrs *[4]*byte, out *[4][2]uint64) {
		f(key, &comps[0], len(comps)/2, ptrs, out)
	}
}

func wrapX1(f fusedAsmX1) fusedX1Fn {
	return func(key *[16]byte, comps []uint64, data *byte, out *[2]uint64) {
		f(key, &comps[0], len(comps)/2, data, out)
	}
}

type fusedTier struct {
	name    string
	ok      bool
	skipMsg string
	x4      map[int]fusedX4Fn
	x1      map[int]fusedX1Fn
}

func amd64FusedTiers() []fusedTier {
	return []fusedTier{
		{
			name: "aesni", ok: aes.CPU.HasAESNI, skipMsg: "requires AES-NI",
			x4: map[int]fusedX4Fn{13: wrapX4(aesITB128FusedChain13x4AesNiAsm), 20: wrapX4(aesITB128FusedChain20x4AesNiAsm),
				36: wrapX4(aesITB128FusedChain36x4AesNiAsm), 68: wrapX4(aesITB128FusedChain68x4AesNiAsm)},
			x1: map[int]fusedX1Fn{13: wrapX1(aesITB128FusedChain13x1AesNiAsm), 20: wrapX1(aesITB128FusedChain20x1AesNiAsm),
				36: wrapX1(aesITB128FusedChain36x1AesNiAsm), 68: wrapX1(aesITB128FusedChain68x1AesNiAsm)},
		},
		{
			name: "vex", ok: aes.CPU.HasAESNI && aes.CPU.HasAVX2, skipMsg: "requires AES-NI + AVX",
			x4: map[int]fusedX4Fn{13: wrapX4(aesITB128FusedChain13x4VexAsm), 20: wrapX4(aesITB128FusedChain20x4VexAsm),
				36: wrapX4(aesITB128FusedChain36x4VexAsm), 68: wrapX4(aesITB128FusedChain68x4VexAsm)},
			x1: map[int]fusedX1Fn{13: wrapX1(aesITB128FusedChain13x1VexAsm), 20: wrapX1(aesITB128FusedChain20x1VexAsm),
				36: wrapX1(aesITB128FusedChain36x1VexAsm), 68: wrapX1(aesITB128FusedChain68x1VexAsm)},
		},
		{
			name: "vaesavx2", ok: aes.CPU.HasVAES && aes.CPU.HasAVX2, skipMsg: "requires VAES + AVX2",
			x4: map[int]fusedX4Fn{13: wrapX4(aesITB128FusedChain13x4VaesAvx2Asm), 20: wrapX4(aesITB128FusedChain20x4VaesAvx2Asm),
				36: wrapX4(aesITB128FusedChain36x4VaesAvx2Asm), 68: wrapX4(aesITB128FusedChain68x4VaesAvx2Asm)},
		},
		{
			name: "avx512", ok: aes.CPU.HasVAES && aes.CPU.HasAVX512, skipMsg: "requires VAES + AVX-512",
			x4: map[int]fusedX4Fn{13: wrapX4(aesITB128FusedChain13x4Avx512Asm), 20: wrapX4(aesITB128FusedChain20x4Avx512Asm),
				36: wrapX4(aesITB128FusedChain36x4Avx512Asm), 68: wrapX4(aesITB128FusedChain68x4Avx512Asm)},
		},
	}
}

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
}

// BenchmarkFusedTier times every fused tier the host can execute, per
// shape and per cascade length (4 and 8 pairs = 512- and 1024-bit keys).
func BenchmarkFusedTier(b *testing.B) {
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range shapes {
			for _, pairs := range []int{4, 8} {
				k := tier.x4[n]
				b.Run(fmt.Sprintf("%s/x4/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					key := ascendingKey()
					comps := randomComponents(pairs)
					_, ptrs := makeLaneData(n)
					var out [4][2]uint64
					b.SetBytes(int64(4 * n))
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						comps[0] = uint64(i)
						k(&key, comps, &ptrs, &out)
					}
				})
			}
		}
	}
}
