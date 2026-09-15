//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"encoding/binary"
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

type fusedAsmX8 func(*[176]byte, *uint64, int, *[8]*byte, *[8][2]uint64)

func wrapX8(f fusedAsmX8) fusedX8Fn {
	return func(s *Schedule, comps []uint64, ptrs *[8]*byte, out *[8][2]uint64) {
		f(&s.roundKeys, &comps[0], len(comps)/2, ptrs, out)
	}
}

// avx512X8Kernels maps each eight-lane shape to its ZMM kernel.
func avx512X8Kernels() map[int]fusedX8Fn {
	return map[int]fusedX8Fn{
		20: wrapX8(aesCMAC128FusedChain20x8Avx512Asm),
		36: wrapX8(aesCMAC128FusedChain36x8Avx512Asm),
		68: wrapX8(aesCMAC128FusedChain68x8Avx512Asm),
	}
}

func hostHasZMMFused() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX512 }

// TestFusedX8KernelParityAmd64 pins every eight-lane ZMM kernel to the
// pure-Go cascade by direct call (independent of the dispatch flags)
// and to two calls of its four-lane ZMM twin on the lane halves.
func TestFusedX8KernelParityAmd64(t *testing.T) {
	if !hostHasZMMFused() {
		t.Skip("requires VAES + AVX-512")
	}
	x4 := map[int]fusedX4Fn{20: wrapX4(aesCMAC128FusedChain20x4Avx512Asm),
		36: wrapX4(aesCMAC128FusedChain36x4Avx512Asm), 68: wrapX4(aesCMAC128FusedChain68x4Avx512Asm)}
	for n, k := range avx512X8Kernels() {
		n, k := n, k
		t.Run("scalar/"+shapeName(n), func(t *testing.T) { runFusedX8Parity(t, "avx512-x8", n, k) })
		t.Run("x4twin/"+shapeName(n), func(t *testing.T) {
			for _, pairs := range x8PairCounts {
				for iter := 0; iter < 32; iter++ {
					s := NewSchedule(ascendingKey())
					comps := randomComponentsN(pairs)
					bufs, ptrs := makeLaneData8(n)
					for lane := range bufs {
						binary.LittleEndian.PutUint32(bufs[lane], uint32(iter*8+lane))
					}
					var got, want [8][2]uint64
					k(s, comps, &ptrs, &got)
					lo := [4]*byte{ptrs[0], ptrs[1], ptrs[2], ptrs[3]}
					hi := [4]*byte{ptrs[4], ptrs[5], ptrs[6], ptrs[7]}
					var o [4][2]uint64
					x4[n](s, comps, &lo, &o)
					copy(want[0:4], o[:])
					x4[n](s, comps, &hi, &o)
					copy(want[4:8], o[:])
					if got != want {
						t.Fatalf("n=%d pairs=%d iter %d: x8 %x != two x4 calls %x", n, pairs, iter, got, want)
					}
				}
			}
		})
	}
}

// TestFusedX8ActiveImpliesZMM pins the eight-lane arm to the ZMM fused
// tier: the arm is selected only when the four-lane ZMM kernels are, so
// a forced narrower ITB_FORCE_HASH_TIER carries the eight-lane
// dispatchers with it.
func TestFusedX8ActiveImpliesZMM(t *testing.T) {
	if FusedX8Active() && !FusedHasVAESAVX512 {
		t.Fatal("FusedX8Active without the ZMM fused tier")
	}
	if FusedHasVAESAVX512X8 && !hostHasZMMFused() {
		t.Fatal("FusedHasVAESAVX512X8 set on a host without VAES + AVX-512")
	}
}

// TestForceChainHashX4Applied asserts that ITB_FORCE_CHAINHASH_X4
// disarms the eight-lane flag at init; a no-op unless the variable is
// set.
func TestForceChainHashX4Applied(t *testing.T) {
	if !forcetier.ChainHashX4() {
		t.Skip("ITB_FORCE_CHAINHASH_X4 unset; auto-dispatch")
	}
	if FusedHasVAESAVX512X8 || FusedX8Active() {
		t.Fatal("ITB_FORCE_CHAINHASH_X4 set but the eight-lane arm is armed")
	}
}

// BenchmarkFusedTierPixX8 times the ZMM fused kernels under the
// production call pattern of the pixel pipeline at eight pixels per
// iteration: a 4-byte pixel-index store into offset 0 of every lane
// buffer immediately ahead of the kernel call, components stable across
// calls. The x4 cells run the four-lane kernel twice per iteration (the
// stride the pipeline uses without the eight-lane hook), the x8 cells
// the eight-lane kernel once, so the two rows compare at equal work.
func BenchmarkFusedTierPixX8(b *testing.B) {
	if !hostHasZMMFused() {
		b.Skip("requires VAES + AVX-512")
	}
	x4 := map[int]fusedX4Fn{20: wrapX4(aesCMAC128FusedChain20x4Avx512Asm),
		36: wrapX4(aesCMAC128FusedChain36x4Avx512Asm), 68: wrapX4(aesCMAC128FusedChain68x4Avx512Asm)}
	x8 := avx512X8Kernels()
	for _, n := range x8Shapes {
		for _, pairs := range []int{4, 8, 16} {
			b.Run(fmt.Sprintf("avx512/x4/shape%d/pairs%d", n, pairs), func(b *testing.B) {
				s := NewSchedule(ascendingKey())
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
					x4[n](s, comps, &lo, &out)
					for l := 4; l < 8; l++ {
						binary.LittleEndian.PutUint32(bufs[l], uint32(8*i+l))
					}
					x4[n](s, comps, &hi, &out)
				}
			})
			b.Run(fmt.Sprintf("avx512/x8/shape%d/pairs%d", n, pairs), func(b *testing.B) {
				s := NewSchedule(ascendingKey())
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
					x8[n](s, comps, &ptrs, &out)
				}
			})
		}
	}
}
