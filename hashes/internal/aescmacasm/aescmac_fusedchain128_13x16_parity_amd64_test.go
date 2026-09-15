//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"
)

type fusedAsmX16 func(*[176]byte, *uint64, int, uint64, *[16][2]uint64)

func wrapX16(f fusedAsmX16) fusedX16Fn {
	return func(s *Schedule, comps []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		f(&s.roundKeys, &comps[0], len(comps)/2, groupIdxBase, out)
	}
}

// fusedX16Tier describes one batch-16 dispatch state: the silicon it
// needs, its kernel entry (nil for the scalar state) and the complete
// four-flag tuple that selects it, so installing one cannot leave a
// higher-priority flag set from the previous state or from the
// forced-tier init.
type fusedX16Tier struct {
	name                 string
	ok                   func() bool
	k                    fusedX16Fn
	zmm, ymm, vex, aesni bool
}

func amd64FusedX16Tiers() []fusedX16Tier {
	return []fusedX16Tier{
		{"avx512", func() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX512 }, wrapX16(aesCMAC128FusedChain13x16Avx512Asm), true, false, false, false},
		{"vaesavx2", func() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX2 }, wrapX16(aesCMAC128FusedChain13x16VaesAvx2Asm), false, true, false, false},
		{"vex", func() bool { return aes.CPU.HasAESNI && aes.CPU.HasAVX2 }, wrapX16(aesCMAC128FusedChain13x16VexAsm), false, false, true, false},
		{"aesni", func() bool { return aes.CPU.HasAESNI }, wrapX16(aesCMAC128FusedChain13x16AesNiAsm), false, false, false, true},
		{"scalar", func() bool { return true }, nil, false, false, false, false},
	}
}

// saveFusedX16Flags snapshots the four batch-16 dispatch flags and
// registers a Cleanup that restores them.
func saveFusedX16Flags(t *testing.T) {
	t.Helper()
	zmm, ymm, vex, aesni := HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16
	t.Cleanup(func() {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = zmm, ymm, vex, aesni
	})
}

// TestFusedChain13x16KernelParityAmd64 pins every batch-16 kernel the
// host can execute to the reference by direct call, independent of the
// dispatch flags.
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
// host can execute — all four flags set atomically per tier — and pins
// the dispatcher's output to the reference. The scalar state verifies
// the default arm.
func TestFusedChain13x16DispatcherTiers(t *testing.T) {
	saveFusedX16Flags(t)
	for _, tier := range amd64FusedX16Tiers() {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok() {
				t.Skipf("%s tier not executable on this host", tier.name)
			}
			HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = tier.zmm, tier.ymm, tier.vex, tier.aesni
			checkFusedX16Parity(t, "dispatch-"+tier.name, FusedChain13x16)
		})
	}
}

// TestFusedChain13x16CrossTier installs every dispatch state the host
// can execute in turn and requires all of them to produce byte-identical
// output on the same inputs at every cascade length — the assembly tiers
// agree with each other, not only with the reference.
func TestFusedChain13x16CrossTier(t *testing.T) {
	if !aes.CPU.HasAESNI {
		t.Skip("AES-NI not available")
	}
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
					HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = tier.zmm, tier.ymm, tier.vex, tier.aesni
					s := NewSchedule(tc.key)
					var out [16][2]uint64
					FusedChain13x16(s, comps, base, &out)
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
