//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// BenchmarkTier times every kernel tier the host can execute, per shape,
// by direct call (independent of the auto-selected dispatch).
func BenchmarkTier(b *testing.B) {
	for _, tier := range amd64Tiers() {
		if !tier.ok {
			continue
		}
		for _, n := range shapes {
			kernel := tier.k[n]
			b.Run(fmt.Sprintf("%s/shape%d", tier.name, n), func(b *testing.B) {
				benchKernel(b, n, kernel)
			})
		}
	}
}

// benchKernelX16 times one batch-16 fill kernel directly at the given
// cascade length. Components stay stable across calls (the production
// pattern: the prepended lock components are built once per container);
// the group base advances by 16 per call. Input: 16 lanes × 13 bytes =
// 208 bytes per iteration.
func benchKernelX16(b *testing.B, pairs int, kernel fusedX16Fn) {
	key := ascendingKey()
	comps := fusedX16Components(0x0102030405060708, 0x090a0b0c0d0e0f00, pairs)
	var out [16][2]uint64
	b.SetBytes(16 * 13)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kernel(&key, comps, uint64(i*16), &out)
	}
}

// BenchmarkTierX16 times every batch-16 Interlocked Barrier fill kernel
// the host silicon can execute, by direct call (independent of the
// dispatch flags), at one pair (the plain chain-absorb) and at the
// 5 / 9 / 17-pair cascades of the 512 / 1024 / 2048-bit lockSeeds.
// Kernel-level signal for the x16 tier auto-selection: the widest VAES
// tier the host offers wins on every measured CPU family, which is what
// the shipping dispatch selects. The full-stack matrix is too noisy to
// resolve small deltas when the fill is a few percent of total time —
// the kernel bench is what the auto-selection rests on.
func BenchmarkTierX16(b *testing.B) {
	tiers := amd64FusedX16Tiers()
	tiers[len(tiers)-1].k = FusedChain13x16 // scalar state: dispatcher default arm
	saved := [4]bool{HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16}
	b.Cleanup(func() {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = saved[0], saved[1], saved[2], saved[3]
	})
	for _, tier := range tiers {
		if !tier.ok() {
			continue
		}
		for _, pairs := range fusedX16PairCounts {
			b.Run(fmt.Sprintf("%s/pairs%d", tier.name, pairs), func(b *testing.B) {
				HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = tier.zmm, tier.ymm, tier.vex, tier.aesni
				benchKernelX16(b, pairs, tier.k)
			})
		}
	}
}

// copySeeds materialises seeds the way the batched hash closure receives
// them in production: a by-value [4][2]uint64 argument copied into the
// callee's frame immediately before the kernel call. The copy lands as
// four 16-byte stores that the kernel's seeds load must forward from.
//
//go:noinline
func copySeeds(src *[4][2]uint64) [4][2]uint64 { return *src }

// BenchmarkTierPix times every per-round x4 tier under the nonce-buf
// call pattern of Seed128.blockHash128x4: a 4-byte pixel-index store
// into offset 0 of every lane buffer immediately ahead of the kernel
// call, seeds copied by value into the callee frame. Shapes 20 / 36 / 68
// are the 128 / 256 / 512-bit nonce-buf shapes that reach the per-round
// kernels when the fused cascade is not attached.
func BenchmarkTierPix(b *testing.B) {
	for _, tier := range amd64Tiers() {
		if !tier.ok {
			continue
		}
		for _, n := range []int{20, 36, 68} {
			kernel := tier.k[n]
			b.Run(fmt.Sprintf("%s/shape%d", tier.name, n), func(b *testing.B) {
				key := ascendingKey()
				stable := [4][2]uint64{{1, 2}, {3, 4}, {5, 6}, {7, 8}}
				bufs, ptrs := makeLaneData(n)
				var seeds [4][2]uint64
				var out [4][2]uint64
				b.SetBytes(int64(4 * n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for l := 0; l < 4; l++ {
						binary.LittleEndian.PutUint32(bufs[l], uint32(4*i+l))
					}
					seeds = copySeeds(&stable)
					kernel(&key, &seeds, &ptrs, &out)
				}
			})
		}
	}
}

// BenchmarkTierFill times every per-round x4 tier at the 13-byte shape
// under the Interlocked Barrier x4 fill pattern (lockBatchPRF48.fillRanksX4):
// the domain-tagged fill block [0x03 | LE64(groupIdx) | 4×0x00] is
// written into every lane buffer immediately ahead of the kernel call,
// seeds copied by value into the callee frame. Two store shapes are
// timed: an 8-byte store at offset 0 plus a 4-byte store at offset 8
// (matching the kernel's 8 / 4 / 1-byte tail loads exactly), and a
// 1-byte store at offset 0 plus an 8-byte store at offset 1 (the
// shipped byte-oriented fill, which the kernel's 8-byte load at offset 0
// spans; the stores sit far enough ahead of the load that the failed
// forward is not on the critical path).
func BenchmarkTierFill(b *testing.B) {
	for _, tier := range amd64Tiers() {
		if !tier.ok {
			continue
		}
		kernel := tier.k[13]
		for _, split := range []bool{true, false} {
			label := "store8+4"
			if !split {
				label = "store1+8"
			}
			b.Run(fmt.Sprintf("%s/%s", tier.name, label), func(b *testing.B) {
				key := ascendingKey()
				stable := [4][2]uint64{{1, 2}, {1, 2}, {1, 2}, {1, 2}}
				bufs, ptrs := makeLaneData(13)
				for l := range bufs {
					for i := range bufs[l] {
						bufs[l][i] = 0
					}
				}
				var seeds [4][2]uint64
				var out [4][2]uint64
				b.SetBytes(4 * 13)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					groupIdx := uint64(4 * i)
					for l := 0; l < 4; l++ {
						gi := groupIdx + uint64(l)
						if split {
							binary.LittleEndian.PutUint64(bufs[l][0:8], 0x03|gi<<8)
							binary.LittleEndian.PutUint32(bufs[l][8:12], uint32(gi>>56))
						} else {
							bufs[l][0] = 0x03
							binary.LittleEndian.PutUint64(bufs[l][1:9], gi)
						}
					}
					seeds = copySeeds(&stable)
					kernel(&key, &seeds, &ptrs, &out)
				}
			})
		}
	}
}

// BenchmarkFusedTierPix times every fused tier under the production
// call pattern of Seed128.blockHash128x4 -> BatchFusedChain: a 4-byte
// pixel-index store into offset 0 of every lane buffer immediately ahead
// of the kernel call, components stable across calls. Shapes 20 / 36 /
// 68 (128 / 256 / 512-bit nonce bufs), 4 and 8 component pairs (512 /
// 1024-bit keys).
func BenchmarkFusedTierPix(b *testing.B) {
	for _, tier := range amd64FusedTiers() {
		if !tier.ok {
			continue
		}
		for _, n := range []int{20, 36, 68} {
			for _, pairs := range []int{4, 8} {
				k := tier.x4[n]
				b.Run(fmt.Sprintf("%s/x4/shape%d/pairs%d", tier.name, n, pairs), func(b *testing.B) {
					key := ascendingKey()
					comps := randomComponents(pairs)
					bufs, ptrs := makeLaneData(n)
					var out [4][2]uint64
					b.SetBytes(int64(4 * n))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for l := 0; l < 4; l++ {
							binary.LittleEndian.PutUint32(bufs[l], uint32(4*i+l))
						}
						k(&key, comps, &ptrs, &out)
					}
				})
			}
		}
	}
}
