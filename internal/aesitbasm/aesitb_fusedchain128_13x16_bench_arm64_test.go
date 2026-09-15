//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"fmt"
	"testing"
)

// BenchmarkTierX16 times the batch-16 Interlocked Barrier fill kernel on
// arm64 — the NEON tier by direct call and the scalar reference — at one
// pair (the plain chain-absorb) and at the 5 / 9 / 17-pair cascades of
// the 512 / 1024 / 2048-bit lockSeeds. Components stay stable across
// calls (the production pattern); the group base advances by 16 per
// call. Input: 16 lanes × 13 bytes = 208 bytes per iteration.
func BenchmarkTierX16(b *testing.B) {
	tiers := []struct {
		name string
		ok   bool
		k    fusedX16Fn
	}{
		{"neon", HasARMAESX16, func(key *[16]byte, comps []uint64, groupIdxBase uint64, out *[16][2]uint64) {
			aesITB128FusedChain13x16NeonAsm(key, &comps[0], len(comps)/2, groupIdxBase, out)
		}},
		{"scalar", true, scalarFusedX16},
	}
	for _, tier := range tiers {
		if !tier.ok {
			continue
		}
		for _, pairs := range fusedX16PairCounts {
			b.Run(fmt.Sprintf("%s/pairs%d", tier.name, pairs), func(b *testing.B) {
				key := ascendingKey()
				comps := fusedX16Components(0x0102030405060708, 0x090a0b0c0d0e0f00, pairs)
				var out [16][2]uint64
				b.SetBytes(16 * 13)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					tier.k(&key, comps, uint64(i*16), &out)
				}
			})
		}
	}
}
