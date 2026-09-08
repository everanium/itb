//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

type fusedAsmX8 func(*uint64, int, *[8]*byte, *[8][2]uint64)

func wrapX8(f fusedAsmX8) fusedX8Fn {
	return func(comps []uint64, ptrs *[8]*byte, out *[8][2]uint64) {
		f(&comps[0], len(comps)/2, ptrs, out)
	}
}

// avx512X8Kernels maps each eight-lane shape to its ZMM kernel.
func avx512X8Kernels() map[int]fusedX8Fn {
	return map[int]fusedX8Fn{
		20: wrapX8(sipHash24FusedChain20x8Avx512Asm),
		36: wrapX8(sipHash24FusedChain36x8Avx512Asm),
		68: wrapX8(sipHash24FusedChain68x8Avx512Asm),
	}
}

// TestFusedX8KernelParityAmd64 pins every eight-lane ZMM kernel to the
// pure-Go cascade by direct call (independent of the dispatch flags)
// and to two calls of its four-lane EVEX twin on the lane halves.
func TestFusedX8KernelParityAmd64(t *testing.T) {
	if !cpu.X86.HasAVX512F {
		t.Skip("requires AVX-512F")
	}
	x4 := map[int]fusedX4Fn{20: wrapX4(sipHash24FusedChain20x4Avx512Asm),
		36: wrapX4(sipHash24FusedChain36x4Avx512Asm), 68: wrapX4(sipHash24FusedChain68x4Avx512Asm)}
	for n, k := range avx512X8Kernels() {
		n, k := n, k
		t.Run("scalar/"+shapeName(n), func(t *testing.T) { runFusedX8Parity(t, "avx512-x8", n, k) })
		t.Run("x4twin/"+shapeName(n), func(t *testing.T) {
			for _, pairs := range x8PairCounts {
				for iter := 0; iter < 32; iter++ {
					comps := randomComponents(pairs)
					bufs, ptrs := makeLaneData8(n)
					for lane := range bufs {
						binary.LittleEndian.PutUint32(bufs[lane], uint32(iter*8+lane))
					}
					var got, want [8][2]uint64
					k(comps, &ptrs, &got)
					lo := [4]*byte{ptrs[0], ptrs[1], ptrs[2], ptrs[3]}
					hi := [4]*byte{ptrs[4], ptrs[5], ptrs[6], ptrs[7]}
					var o [4][2]uint64
					x4[n](comps, &lo, &o)
					copy(want[0:4], o[:])
					x4[n](comps, &hi, &o)
					copy(want[4:8], o[:])
					if got != want {
						t.Fatalf("n=%d pairs=%d iter %d: x8 %x != two x4 calls %x", n, pairs, iter, got, want)
					}
				}
			}
		})
	}
}

// TestFusedX8ActiveImpliesAVX512 pins the eight-lane arm to the AVX-512
// fused tier: the arm is selected only when the four-lane EVEX kernels
// are, so a forced narrower ITB_FORCE_HASH_TIER carries the eight-lane
// dispatchers with it.
func TestFusedX8ActiveImpliesAVX512(t *testing.T) {
	if FusedX8Active() && !FusedHasAVX512 {
		t.Fatal("FusedX8Active without the AVX-512 fused tier")
	}
	if FusedHasAVX512X8 && !cpu.X86.HasAVX512F {
		t.Fatal("FusedHasAVX512X8 set on a host without AVX-512F")
	}
}

// TestForceChainHashX4Applied asserts that ITB_FORCE_CHAINHASH_X4
// disarms the eight-lane flag at init; a no-op unless the variable is
// set.
func TestForceChainHashX4Applied(t *testing.T) {
	if !forcetier.ChainHashX4() {
		t.Skip("ITB_FORCE_CHAINHASH_X4 unset; auto-dispatch")
	}
	if FusedHasAVX512X8 || FusedX8Active() {
		t.Fatal("ITB_FORCE_CHAINHASH_X4 set but the eight-lane arm is armed")
	}
}

// BenchmarkFusedTierPixX8 times the ZMM eight-lane kernels against two
// calls of the four-lane EVEX kernel under the production call pattern
// (pixel-index store ahead of every call), at equal work per iteration.
func BenchmarkFusedTierPixX8(b *testing.B) {
	if !cpu.X86.HasAVX512F {
		b.Skip("requires AVX-512F")
	}
	x4 := map[int]fusedX4Fn{20: wrapX4(sipHash24FusedChain20x4Avx512Asm),
		36: wrapX4(sipHash24FusedChain36x4Avx512Asm), 68: wrapX4(sipHash24FusedChain68x4Avx512Asm)}
	x8 := avx512X8Kernels()
	for _, n := range x8Shapes {
		for _, pairs := range []int{4, 8, 16} {
			b.Run(fmt.Sprintf("avx512/x4/shape%d/pairs%d", n, pairs), func(b *testing.B) {
				comps := randomComponents(pairs)
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
					x4[n](comps, &lo, &out)
					for l := 4; l < 8; l++ {
						binary.LittleEndian.PutUint32(bufs[l], uint32(8*i+l))
					}
					x4[n](comps, &hi, &out)
				}
			})
			b.Run(fmt.Sprintf("avx512/x8/shape%d/pairs%d", n, pairs), func(b *testing.B) {
				comps := randomComponents(pairs)
				bufs, ptrs := makeLaneData8(n)
				var out [8][2]uint64
				b.SetBytes(int64(8 * n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for l := 0; l < 8; l++ {
						binary.LittleEndian.PutUint32(bufs[l], uint32(8*i+l))
					}
					x8[n](comps, &ptrs, &out)
				}
			})
		}
	}
}
