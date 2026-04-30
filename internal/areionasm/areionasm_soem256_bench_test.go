//go:build amd64 && !purego

package areionasm

import (
	"testing"

	"github.com/jedisct1/go-aes"
)

// BenchmarkAreion256SoEM_TwoCallsPlusXor measures the baseline cost
// of two separate Areion256Permutex4 calls plus the post-permute SoEM
// XOR loop done in Go — the surface the fused kernel replaces.
func BenchmarkAreion256SoEM_TwoCallsPlusXor(b *testing.B) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var s1b0, s1b1, s2b0, s2b1 aes.Block4
	for i := 0; i < 64; i++ {
		s1b0[i] = byte(i)
		s1b1[i] = byte(i + 64)
		s2b0[i] = byte(i + 128)
		s2b1[i] = byte(i + 192)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256Permutex4(&s1b0, &s1b1)
		Areion256Permutex4(&s2b0, &s2b1)
		for j := 0; j < 64; j++ {
			s1b0[j] ^= s2b0[j]
			s1b1[j] ^= s2b1[j]
		}
	}
}

// BenchmarkAreion256SoEM_FusedKernel measures the fused VAES kernel
// running both half-state permutations interleaved + register XOR,
// so the speedup vs the baseline is the contribution of (a) ILP from
// interleaving, (b) one RC pre-load instead of two, (c) eliminating
// the Go-side XOR loop.
func BenchmarkAreion256SoEM_FusedKernel(b *testing.B) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var s1b0, s1b1, s2b0, s2b1 aes.Block4
	for i := 0; i < 64; i++ {
		s1b0[i] = byte(i)
		s1b1[i] = byte(i + 64)
		s2b0[i] = byte(i + 128)
		s2b1[i] = byte(i + 192)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256SoEMPermutex4Interleaved(&s1b0, &s1b1, &s2b0, &s2b1)
	}
}
