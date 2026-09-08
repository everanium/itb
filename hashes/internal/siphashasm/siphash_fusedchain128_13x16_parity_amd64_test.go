//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

// fusedX16Tier describes one batch-16 dispatch state: the silicon it
// needs, its direct kernel entry (the ZMM sixteen-lane kernel, the YMM
// eight-lane kernel called twice, nil for the scalar reference) and the
// flag pair that selects it.
type fusedX16Tier struct {
	name         string
	ok           func() bool
	k            fusedX16Fn
	avx512, avx2 bool
}

func amd64FusedX16Tiers() []fusedX16Tier {
	return []fusedX16Tier{
		{"avx512", func() bool { return cpu.X86.HasAVX512F }, func(comps []uint64, base uint64, out *[16][2]uint64) {
			sipHash24FusedChain13x16Avx512Asm(&comps[0], len(comps)/2, base, out)
		}, true, false},
		{"avx2", func() bool { return cpu.X86.HasAVX2 }, func(comps []uint64, base uint64, out *[16][2]uint64) {
			sipHash24FusedChain13x8Avx2Asm(&comps[0], len(comps)/2, base, x16Half(out, 0))
			sipHash24FusedChain13x8Avx2Asm(&comps[0], len(comps)/2, base+8, x16Half(out, 1))
		}, false, true},
		{"scalar", func() bool { return true }, nil, false, false},
	}
}

// saveFusedX16Flags snapshots the batch-16 dispatch flags and registers
// a Cleanup that restores them.
func saveFusedX16Flags(t *testing.T) {
	t.Helper()
	a512, a2 := HasAVX512X16, HasAVX2X16
	t.Cleanup(func() { HasAVX512X16, HasAVX2X16 = a512, a2 })
}

// TestFusedChain13x16KernelParityAmd64 pins the ZMM batch-16 kernel and
// the YMM eight-lane fill kernel to the reference by direct call,
// independent of the dispatch flags.
func TestFusedChain13x16KernelParityAmd64(t *testing.T) {
	for _, tier := range amd64FusedX16Tiers() {
		if tier.k == nil {
			continue
		}
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok() {
				t.Skipf("%s tier not executable on this host", tier.name)
			}
			checkFusedX16Parity(t, tier.name, tier.k)
		})
	}
}

// TestFusedChain13x16DispatcherTiers installs each dispatch state the
// host can execute — both flags set atomically per tier — and pins the
// dispatcher's output to the reference.
func TestFusedChain13x16DispatcherTiers(t *testing.T) {
	saveFusedX16Flags(t)
	for _, tier := range amd64FusedX16Tiers() {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok() {
				t.Skipf("%s tier not executable on this host", tier.name)
			}
			HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
			checkFusedX16Parity(t, "dispatch-"+tier.name, FusedChain13x16)
		})
	}
}

// TestFusedChain13x16CrossTier installs every dispatch state the host
// can execute in turn and requires all of them to produce byte-identical
// output on the same inputs at every cascade length.
func TestFusedChain13x16CrossTier(t *testing.T) {
	saveFusedX16Flags(t)
	type result struct {
		tier string
		out  [16][2]uint64
	}
	for _, pairs := range fusedX16PairCounts {
		for _, tc := range fusedX16FixedCases {
			comps := fusedX16Components(tc.seed0, tc.seed1, pairs)
			for _, base := range tc.bases {
				var results []result
				for _, tier := range amd64FusedX16Tiers() {
					if !tier.ok() {
						continue
					}
					HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
					var out [16][2]uint64
					FusedChain13x16(comps, base, &out)
					results = append(results, result{tier.name, out})
				}
				for _, r := range results[1:] {
					if r.out != results[0].out {
						t.Errorf("%s pairs=%d base=%#x: %s differs from %s", tc.name, pairs, base, r.tier, results[0].tier)
					}
				}
			}
		}
	}
}

// BenchmarkTierX16 times every batch-16 Interlocked Barrier fill arm the
// host silicon can execute through the dispatcher, at one pair (the
// plain chain-absorb) and at the 5 / 9 / 17-pair cascades of the 512 /
// 1024 / 2048-bit lockSeeds.
func BenchmarkTierX16(b *testing.B) {
	saved := [2]bool{HasAVX512X16, HasAVX2X16}
	b.Cleanup(func() { HasAVX512X16, HasAVX2X16 = saved[0], saved[1] })
	for _, tier := range amd64FusedX16Tiers() {
		if !tier.ok() {
			continue
		}
		for _, pairs := range fusedX16PairCounts {
			b.Run(fmt.Sprintf("%s/pairs%d", tier.name, pairs), func(b *testing.B) {
				HasAVX512X16, HasAVX2X16 = tier.avx512, tier.avx2
				comps := fusedX16Components(0x0102030405060708, 0x090a0b0c0d0e0f00, pairs)
				var out [16][2]uint64
				b.SetBytes(16 * 13)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					FusedChain13x16(comps, uint64(i*16), &out)
				}
			})
		}
	}
}
