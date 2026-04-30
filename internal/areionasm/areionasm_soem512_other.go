//go:build !amd64 || purego

package areionasm

import "github.com/jedisct1/go-aes"

// Areion512SoEMPermutex4Interleaved is the non-amd64 / purego fallback
// for the fused 512-bit kernel. Mirrors the Areion-SoEM-256 fallback
// shape: same callable-stub forwarding to `Areion512Permutex4` (a
// panic stub on non-amd64 — see `areionasm_other.go`); kept so the
// import resolves cleanly across platforms. Production dispatch on
// non-amd64 routes through the parent itb package's portable Go
// fallback before this function would ever be reached.
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
