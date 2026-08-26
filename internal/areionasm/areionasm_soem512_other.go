//go:build !amd64 || purego || noitbasm

package areionasm

import "github.com/jedisct1/go-aes"

// Areion512SoEMPermutex4Interleaved is the non-amd64 / purego fallback
// for the fused 512-bit kernel. Mirrors the Areion-SoEM-256 fallback
// shape: same callable-stub forwarding to `Areion512Permutex4` (the
// real NEON kernel on arm64; a panic stub otherwise — see
// `areionasm_other.go`); kept so the import resolves cleanly across
// platforms. The parent itb package's production dispatch never
// reaches it on these builds — non-amd64/non-arm64 hosts route through
// the portable Go fallback path, and arm64 hosts use the parent
// package's own per-half fold (`areion_arm64.go`).
func Areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4) {
	Areion512Permutex4(a1, b1, c1, d1)
	Areion512Permutex4(a2, b2, c2, d2)
	for i := 0; i < 64; i++ {
		a1[i] ^= a2[i]
		b1[i] ^= b2[i]
		c1[i] ^= c2[i]
		d1[i] ^= d2[i]
	}
}
