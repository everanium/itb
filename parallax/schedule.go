package parallax

import (
	"encoding/binary"
	"fmt"

	"github.com/everanium/itb/ctr"
)

// buildPermutation extracts a 16-byte schedule seed by XORing the
// anchor cipher's keystream over a zero buffer under cs.scheduleSubkey
// and the per-message nonce, then expands the seed into a Fisher-Yates
// permutation of {0, …, N-1}. The expansion uses SplitMix64 seeded by
// the two 64-bit halves of the seed (lo, hi); SplitMix64 is a
// well-known full-period PRNG that yields a uniform unbiased
// permutation under standard Fisher-Yates.
func buildPermutation(s *Schedule, cs *Cipherset, nonce []byte) ([]int, error) {
	anchor := s.palette[0]
	sliceNonce, err := sliceNonceFor(anchor, nonce)
	if err != nil {
		return nil, err
	}
	ks, err := ctr.New(anchor, cs.scheduleSubkey, sliceNonce)
	if err != nil {
		return nil, fmt.Errorf("parallax: schedule keystream: %w", err)
	}
	var seed [scheduleSeedSize]byte
	ks.XORKeyStream(seed[:], seed[:])
	return fisherYates(seed[:], len(s.palette)), nil
}

// fisherYates returns a permutation of {0, …, n-1} from the 16-byte
// seed. The Fisher-Yates inner loop draws each swap index from a
// SplitMix64 stream initialised from seed[0:8] and reseeded with
// seed[8:16] after the halfway mark to ensure the entire 128-bit seed
// participates in the permutation. The result is deterministic in seed
// and uniformly distributed (modulo SplitMix64's 2^64 period, vastly
// larger than n!).
func fisherYates(seed []byte, n int) []int {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	lo := binary.LittleEndian.Uint64(seed[:8])
	hi := binary.LittleEndian.Uint64(seed[8:16])
	state := lo
	// Standard inward Fisher-Yates: for i from n-1 down to 1, swap
	// perm[i] with perm[j] where j is uniform in [0, i].
	half := n / 2
	for i := n - 1; i > 0; i-- {
		if i == half {
			// Fold the high half of the seed into the state so the
			// second half of the shuffle does not depend only on lo.
			state ^= hi
		}
		j := int(unbiasedRange(&state, uint64(i+1)))
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

// splitMix64 advances a 64-bit SplitMix64 PRNG state and returns the
// next 64-bit output.
func splitMix64(state *uint64) uint64 {
	*state += 0x9e3779b97f4a7c15
	z := *state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// unbiasedRange returns a uniform integer in [0, bound) by rejection
// sampling on the SplitMix64 stream. The rejection bound mod is the
// largest multiple of bound at or below 2^64; with N capped at 255 the
// rejection rate is negligible.
func unbiasedRange(state *uint64, bound uint64) uint64 {
	if bound == 0 {
		return 0
	}
	limit := (^uint64(0)/bound)*bound - 1
	for {
		v := splitMix64(state)
		if v <= limit {
			return v % bound
		}
	}
}

// sliceNonceFor truncates the on-wire 16-byte nonce to the named
// cipher's native nonce width. Every supported primitive's
// `ctr.NonceSize(name)` is at most the package-level `NonceSize` (16);
// a primitive that asks for a wider nonce is rejected here.
func sliceNonceFor(name string, nonce []byte) ([]byte, error) {
	nlen, err := ctr.NonceSize(name)
	if err != nil {
		return nil, err
	}
	if nlen > len(nonce) {
		return nil, fmt.Errorf("parallax: cipher %q wants %d-byte nonce, wire carries %d", name, nlen, len(nonce))
	}
	return nonce[:nlen], nil
}
