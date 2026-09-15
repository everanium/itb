//go:build amd64 && !purego && !noitbasm

package itb

import (
	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/areionasm"
)

// areionSoEM256Permutex4SoA runs the Areion-SoEM-256 4-way batched PRF
// over caller-prepared SoA half-states. The SoEM construction is:
//
//	state1' = Areion256(input ⊕ key1)
//	state2' = Areion256(input ⊕ key2 ⊕ d)
//	output  = state1' ⊕ state2'
//
// The caller is responsible for the input ⊕ key setup (already done
// by the time s1b0/s1b1/s2b0/s2b1 reach here, in SoA Block4 layout).
// On exit, the SoEM XOR'd result lives in (s1b0, s1b1); (s2b0, s2b1)
// are scratch.
//
// On AVX-512 + VAES this dispatches to a single fused kernel
// (`Areion256SoEMPermutex4Interleaved`) that runs both 10-round
// permutations interleaved for ILP and computes the output XOR in
// registers. On AVX-2 + VAES, and on hosts without VAES, the function
// falls back to two separate permutex4 calls + a manual XOR loop —
// bit-exact identical result, just no interleave/fuse benefit.
func areionSoEM256Permutex4SoA(s1b0, s1b1, s2b0, s2b1 *aes.Block4) {
	switch {
	case areionasm.HasVAESAVX512:
		areionasm.Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1)
	case areionasm.HasVAESAVX2NoAVX512:
		areionasm.Areion256Permutex4Avx2(s1b0, s1b1)
		areionasm.Areion256Permutex4Avx2(s2b0, s2b1)
		for i := 0; i < 64; i++ {
			s1b0[i] ^= s2b0[i]
			s1b1[i] ^= s2b1[i]
		}
	default:
		var states1, states2 [4][32]byte
		unpack256x4SoA(s1b0, s1b1, &states1)
		unpack256x4SoA(s2b0, s2b1, &states2)
		areion256Permutex4Default(&states1)
		areion256Permutex4Default(&states2)
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 32; i++ {
				states1[lane][i] ^= states2[lane][i]
			}
		}
		*s1b0, *s1b1 = pack256x4SoA(&states1)
	}
}

// areionSoEM512Permutex4SoA runs the Areion-SoEM-512 4-way batched PRF
// over caller-prepared SoA half-states. Same dispatch shape as
// `areionSoEM256Permutex4SoA`, scaled to the 4 × Block4 SoA layout of
// Areion512 states.
//
// The caller is responsible for the input ⊕ key setup (already done
// by the time the 8 Block4 buffers reach here). On exit, the SoEM
// XOR'd result lives in (a1, b1, c1, d1); the (a2, b2, c2, d2) buffers
// are scratch.
//
// On AVX-512 + VAES this dispatches to `Areion512SoEMPermutex4Interleaved`,
// which interleaves both 15-round permutations and folds the final
// cyclic state rotation into the SoEM XOR. On AVX-2 + VAES, and on
// hosts without VAES, the function falls back to two separate
// permutex4 calls + a manual XOR loop — bit-exact identical result.
func areionSoEM512Permutex4SoA(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4) {
	switch {
	case areionasm.HasVAESAVX512:
		areionasm.Areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2)
	case areionasm.HasVAESAVX2NoAVX512:
		areionasm.Areion512Permutex4Avx2(a1, b1, c1, d1)
		areionasm.Areion512Permutex4Avx2(a2, b2, c2, d2)
		for i := 0; i < 64; i++ {
			a1[i] ^= a2[i]
			b1[i] ^= b2[i]
			c1[i] ^= c2[i]
			d1[i] ^= d2[i]
		}
	default:
		var states1, states2 [4][64]byte
		unpack512x4SoA(a1, b1, c1, d1, &states1)
		unpack512x4SoA(a2, b2, c2, d2, &states2)
		areion512Permutex4Default(&states1)
		areion512Permutex4Default(&states2)
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 64; i++ {
				states1[lane][i] ^= states2[lane][i]
			}
		}
		*a1, *b1, *c1, *d1 = pack512x4SoA(&states1)
	}
}
