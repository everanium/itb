//go:build !amd64 || purego

package itb

import "github.com/jedisct1/go-aes"

// On non-amd64 platforms (or under the `purego` build tag) there is no
// VAES assembly; the 4-way batched permutations dispatch directly to
// the portable Go fallback.

// SoA-native shims for non-amd64: unpack to AoS, run default,
// repack. Falls back through the same path the amd64 default
// branch uses, so behaviour matches across platforms.
func areion256Permutex4SoA(b0, b1 *aes.Block4) {
	var states [4][32]byte
	unpack256x4SoA(b0, b1, &states)
	areion256Permutex4Default(&states)
	*b0, *b1 = pack256x4SoA(&states)
}

func areion512Permutex4SoA(b0, b1, b2, b3 *aes.Block4) {
	var states [4][64]byte
	unpack512x4SoA(b0, b1, b2, b3, &states)
	areion512Permutex4Default(&states)
	*b0, *b1, *b2, *b3 = pack512x4SoA(&states)
}

// areionSoEM512ChainAbsorbHot — non-amd64 stub. Always returns false.
func areionSoEM512ChainAbsorbHot(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	data *[4][]byte,
	commonLen int,
) (out [4][8]uint64, ok bool) {
	return out, false
}

// areionSoEM256ChainAbsorbHot — non-amd64 stub. Always returns false
// so the closure's general CBC-MAC chain path runs.
func areionSoEM256ChainAbsorbHot(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	data *[4][]byte,
	commonLen int,
) (out [4][4]uint64, ok bool) {
	return out, false
}

// areionSoEM256Permutex4SoA — non-amd64 fallback. Mirrors the AVX-2
// branch of the amd64 dispatcher: two separate per-half permutes (each
// dispatching to the platform's best available AES path inside
// areion256Permutex4SoA) plus a manual XOR loop. Bit-exact identical
// to the amd64 fused result by construction.
func areionSoEM256Permutex4SoA(s1b0, s1b1, s2b0, s2b1 *aes.Block4) {
	areion256Permutex4SoA(s1b0, s1b1)
	areion256Permutex4SoA(s2b0, s2b1)
	for i := 0; i < 64; i++ {
		s1b0[i] ^= s2b0[i]
		s1b1[i] ^= s2b1[i]
	}
}

// areionSoEM512Permutex4SoA — non-amd64 fallback for SoEM-512. Same
// shape as the SoEM-256 fallback, scaled to 4 Block4 buffers per
// state. Bit-exact identical to the amd64 fused result.
func areionSoEM512Permutex4SoA(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4) {
	areion512Permutex4SoA(a1, b1, c1, d1)
	areion512Permutex4SoA(a2, b2, c2, d2)
	for i := 0; i < 64; i++ {
		a1[i] ^= a2[i]
		b1[i] ^= b2[i]
		c1[i] ^= c2[i]
		d1[i] ^= d2[i]
	}
}
