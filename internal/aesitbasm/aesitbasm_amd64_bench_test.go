//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"encoding/binary"
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"
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

// benchKernelX16 times one x16 kernel directly. The 13-byte shape is the
// only x16 shape defined. Input: 16 lanes × 13 bytes = 208 bytes per iteration.
func benchKernelX16(b *testing.B, kernel func(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)) {
	key := ascendingKey()
	var out [16][2]uint64
	// Set bytes to 16 lanes × 13-byte shape
	b.SetBytes(16 * 13)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seed0 := uint64(i)
		seed1 := uint64(i + 1)
		groupIdxBase := uint64(i * 16)
		kernel(&key, seed0, seed1, groupIdxBase, &out)
	}
}

// BenchmarkTierX16 times every batch-16 interlock PRF fill kernel the
// host silicon can execute, by direct call (independent of the dispatch
// flags, which leave the VAES tiers unselected by policy). This is the
// kernel-level signal for the x16 tier decision: if one tier dominates
// the others, auto-selection should prefer it. The full-stack matrix is
// too noisy to resolve 2% deltas when x16 fill is <1% of total time.
func BenchmarkTierX16(b *testing.B) {
	type tier struct {
		name string
		ok   bool
		k    func(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)
	}

	tiers := []tier{
		{"aesni", aes.CPU.HasAESNI, aesITB128ChainAbsorb13x16AesNiAsm},
		{"vex", aes.CPU.HasAESNI && aes.CPU.HasAVX2, aesITB128ChainAbsorb13x16VexAsm},
		{"vaesavx2", aes.CPU.HasVAES && aes.CPU.HasAVX2, aesITB128ChainAbsorb13x16VaesAvx2Asm},
		{"avx512", aes.CPU.HasVAES && aes.CPU.HasAVX512, aesITB128ChainAbsorb13x16VaesAvx512Asm},
		// Scalar reference (always available)
		{"scalar", true, func(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64) {
			scalarBatchX16(key, groupIdxBase, seed0, seed1, out)
		}},
	}

	for _, tier := range tiers {
		if !tier.ok {
			continue
		}
		b.Run(tier.name, func(b *testing.B) {
			benchKernelX16(b, tier.k)
		})
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
