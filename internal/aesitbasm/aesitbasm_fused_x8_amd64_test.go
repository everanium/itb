//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"encoding/binary"
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

type fusedAsmX8 func(*[16]byte, *uint64, int, *[8]*byte, *[8][2]uint64)

func wrapX8(f fusedAsmX8) fusedX8Fn {
	return func(key *[16]byte, comps []uint64, ptrs *[8]*byte, out *[8][2]uint64) {
		f(key, &comps[0], len(comps)/2, ptrs, out)
	}
}

// avx512X8Kernels maps each eight-lane shape to its ZMM kernel.
func avx512X8Kernels() map[int]fusedX8Fn {
	return map[int]fusedX8Fn{
		20: wrapX8(aesITB128FusedChain20x8Avx512Asm),
		36: wrapX8(aesITB128FusedChain36x8Avx512Asm),
		68: wrapX8(aesITB128FusedChain68x8Avx512Asm),
	}
}

func hostHasZMMFused() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX512 }

// x8Tier is one eight-lane kernel tier: its kernels, the four-lane
// kernels of the same tier and the silicon it needs.
type x8Tier struct {
	name string
	ok   bool
	x8   map[int]fusedX8Fn
	x4   map[int]fusedX4Fn
}

func amd64X8Tiers() []x8Tier {
	return []x8Tier{
		{"avx512", hostHasZMMFused(), avx512X8Kernels(), map[int]fusedX4Fn{20: wrapX4(aesITB128FusedChain20x4Avx512Asm),
			36: wrapX4(aesITB128FusedChain36x4Avx512Asm), 68: wrapX4(aesITB128FusedChain68x4Avx512Asm)}},
		{"vaesavx2", aes.CPU.HasVAES && aes.CPU.HasAVX2, map[int]fusedX8Fn{20: wrapX8(aesITB128FusedChain20x8VaesAvx2Asm),
			36: wrapX8(aesITB128FusedChain36x8VaesAvx2Asm), 68: wrapX8(aesITB128FusedChain68x8VaesAvx2Asm)},
			map[int]fusedX4Fn{20: wrapX4(aesITB128FusedChain20x4VaesAvx2Asm),
				36: wrapX4(aesITB128FusedChain36x4VaesAvx2Asm), 68: wrapX4(aesITB128FusedChain68x4VaesAvx2Asm)}},
		{"vex", aes.CPU.HasAESNI && aes.CPU.HasAVX2, map[int]fusedX8Fn{20: wrapX8(aesITB128FusedChain20x8VexAsm),
			36: wrapX8(aesITB128FusedChain36x8VexAsm), 68: wrapX8(aesITB128FusedChain68x8VexAsm)},
			map[int]fusedX4Fn{20: wrapX4(aesITB128FusedChain20x4VexAsm),
				36: wrapX4(aesITB128FusedChain36x4VexAsm), 68: wrapX4(aesITB128FusedChain68x4VexAsm)}},
		{"aesni", aes.CPU.HasAESNI, map[int]fusedX8Fn{20: wrapX8(aesITB128FusedChain20x8AesNiAsm),
			36: wrapX8(aesITB128FusedChain36x8AesNiAsm), 68: wrapX8(aesITB128FusedChain68x8AesNiAsm)},
			map[int]fusedX4Fn{20: wrapX4(aesITB128FusedChain20x4AesNiAsm),
				36: wrapX4(aesITB128FusedChain36x4AesNiAsm), 68: wrapX4(aesITB128FusedChain68x4AesNiAsm)}},
	}
}

// TestFusedX8KernelParityAmd64 pins every eight-lane kernel of every
// tier the host can execute to the pure-Go cascade by direct call
// (independent of the dispatch flags) and to two calls of its four-lane
// twin of the same tier on the lane halves.
func TestFusedX8KernelParityAmd64(t *testing.T) {
	for _, tier := range amd64X8Tiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip("tier not executable on this host")
			}
			for n, k := range tier.x8 {
				n, k := n, k
				t.Run("scalar/"+shapeName(n), func(t *testing.T) { runFusedX8Parity(t, tier.name+"-x8", n, k) })
				t.Run("x4twin/"+shapeName(n), func(t *testing.T) {
					for _, pairs := range x8PairCounts {
						for iter := 0; iter < 32; iter++ {
							key := ascendingKey()
							comps := randomComponentsN(pairs)
							bufs, ptrs := makeLaneData8(n)
							for lane := range bufs {
								binary.LittleEndian.PutUint32(bufs[lane], uint32(iter*8+lane))
							}
							var got, want [8][2]uint64
							k(&key, comps, &ptrs, &got)
							lo := [4]*byte{ptrs[0], ptrs[1], ptrs[2], ptrs[3]}
							hi := [4]*byte{ptrs[4], ptrs[5], ptrs[6], ptrs[7]}
							var o [4][2]uint64
							tier.x4[n](&key, comps, &lo, &o)
							copy(want[0:4], o[:])
							tier.x4[n](&key, comps, &hi, &o)
							copy(want[4:8], o[:])
							if got != want {
								t.Fatalf("n=%d pairs=%d iter %d: x8 %x != two x4 calls %x", n, pairs, iter, got, want)
							}
						}
					}
				})
			}
		})
	}
}

// TestFusedX8ActiveImpliesTier pins each eight-lane arm to its fused
// tier: the arm is selected only when the four-lane kernels of the same
// tier are, so a forced ITB_FORCE_HASH_TIER carries the eight-lane
// dispatchers with it.
func TestFusedX8ActiveImpliesTier(t *testing.T) {
	if FusedX8Active() && !(FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAVXAESNI || FusedHasAESNI) {
		t.Fatal("FusedX8Active without a fused tier")
	}
	if FusedHasVAESAVX512X8 && !hostHasZMMFused() {
		t.Fatal("FusedHasVAESAVX512X8 set on a host without VAES + AVX-512")
	}
	if FusedHasAESNIX8 && !aes.CPU.HasAESNI {
		t.Fatal("FusedHasAESNIX8 set on a host without AES-NI")
	}
}

// TestForceChainHashX4Applied asserts that ITB_FORCE_CHAINHASH_X4
// disarms both eight-lane flags at init; a no-op unless the variable is
// set.
func TestForceChainHashX4Applied(t *testing.T) {
	if !forcetier.ChainHashX4() {
		t.Skip("ITB_FORCE_CHAINHASH_X4 unset; auto-dispatch")
	}
	if FusedHasVAESAVX512X8 || FusedHasAESNIX8 || FusedX8Active() {
		t.Fatal("ITB_FORCE_CHAINHASH_X4 set but an eight-lane arm is armed")
	}
}

// BenchmarkFusedTierPixX8 times the eight-lane kernels of every
// executable tier under the production call pattern of the pixel
// pipeline at eight pixels per iteration: a 4-byte pixel-index store
// into offset 0 of every lane buffer immediately ahead of the kernel
// call, components stable across calls. The x4 cells run the four-lane
// kernel of the same tier twice per iteration (the stride the pipeline
// uses without the eight-lane hook), the x8 cells the eight-lane kernel
// once, so the two rows compare at equal work.
func BenchmarkFusedTierPixX8(b *testing.B) {
	for _, tier := range amd64X8Tiers() {
		if !tier.ok {
			continue
		}
		for _, n := range x8Shapes {
			for _, pairs := range []int{4, 8, 16} {
				b.Run(fmt.Sprintf("%s/x4/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					key := ascendingKey()
					comps := randomComponentsN(pairs)
					bufs, ptrs := makeLaneData8(n)
					lo := [4]*byte{ptrs[0], ptrs[1], ptrs[2], ptrs[3]}
					hi := [4]*byte{ptrs[4], ptrs[5], ptrs[6], ptrs[7]}
					var out [4][2]uint64
					b.SetBytes(int64(8 * n))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for l := 0; l < 4; l++ {
							binary.LittleEndian.PutUint32(bufs[l], uint32(8*i+l))
						}
						tier.x4[n](&key, comps, &lo, &out)
						for l := 4; l < 8; l++ {
							binary.LittleEndian.PutUint32(bufs[l], uint32(8*i+l))
						}
						tier.x4[n](&key, comps, &hi, &out)
					}
				})
				b.Run(fmt.Sprintf("%s/x8/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					key := ascendingKey()
					comps := randomComponentsN(pairs)
					bufs, ptrs := makeLaneData8(n)
					var out [8][2]uint64
					b.SetBytes(int64(8 * n))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for l := 0; l < 8; l++ {
							binary.LittleEndian.PutUint32(bufs[l], uint32(8*i+l))
						}
						tier.x8[n](&key, comps, &ptrs, &out)
					}
				})
			}
		}
	}
}
