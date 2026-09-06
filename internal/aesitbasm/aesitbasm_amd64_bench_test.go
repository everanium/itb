//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
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
