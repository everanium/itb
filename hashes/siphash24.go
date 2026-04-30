package hashes

import (
	"github.com/dchest/siphash"

	"github.com/everanium/itb"
)

// SipHash24 returns a SipHash-2-4 itb.HashFunc128 closure.
//
// SipHash-2-4 is a designed PRF whose 128-bit key is supplied per call
// as the (seed0, seed1) pair — exactly the shape ITB's Seed128
// ChainHash128 produces from the seed components. There is no
// pre-keyed state to cache (no fixed key, no internal hasher object,
// no scratch buffer) so the closure is a direct call into siphash.
//
// Returns: (low64, high64) of SipHash128(key=(seed0, seed1), data).
//
// No WithKey variant — the seed components are the entire SipHash key.
// Long-lived seed serialization is a matter of saving Components only.
func SipHash24() itb.HashFunc128 {
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		return siphash.Hash128(seed0, seed1, data)
	}
}
