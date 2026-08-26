//go:build !amd64 || purego || noitbasm

package areionasm

import "github.com/jedisct1/go-aes"

// Areion256SoEMPermutex4Interleaved is the non-amd64 / purego fallback
// for the fused VAES kernel. The parent itb package's Areion-SoEM-256
// dispatcher never reaches it on these builds — non-amd64/non-arm64
// hosts route through the portable Go fallback path, and arm64 hosts
// use the parent package's own per-half fold (`areion_arm64.go`) — so
// the body here is a callable-stub forwarding to the per-half
// `Areion256Permutex4` (the real NEON kernel on arm64; a panic stub
// otherwise — see `areionasm_other.go`). Kept so the import resolves
// cleanly across platforms.
func Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *aes.Block4) {
	Areion256Permutex4(s1b0, s1b1)
	Areion256Permutex4(s2b0, s2b1)
	for i := 0; i < 64; i++ {
		s1b0[i] ^= s2b0[i]
		s1b1[i] ^= s2b1[i]
	}
}
