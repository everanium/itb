//go:build !amd64 || purego

package areionasm

import "github.com/jedisct1/go-aes"

// Areion256SoEMPermutex4Interleaved is the non-amd64 / purego fallback
// for the fused VAES kernel. On non-amd64 builds the parent itb
// package's Areion-SoEM-256 dispatcher routes through the portable Go
// fallback path before this function would ever be reached, so the
// body here is a callable-stub forwarding to the per-half
// `Areion256Permutex4` (itself a panic stub on non-amd64 — see
// `areionasm_other.go`). Kept so the import resolves cleanly across
// platforms.
func Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *aes.Block4) {
	Areion256Permutex4(s1b0, s1b1)
	Areion256Permutex4(s2b0, s2b1)
	for i := 0; i < 64; i++ {
		s1b0[i] ^= s2b0[i]
		s1b1[i] ^= s2b1[i]
	}
}
