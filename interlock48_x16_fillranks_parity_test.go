package itb

import (
	"bytes"
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/forcetier"
	"github.com/everanium/itb/internal/interlock"
)

// interlock48_x16_fillranks_parity_test.go — the batch-16 ≡ sequential
// PRF fill invariant of the Interlocked Barrier.
//
// splitTriple48LockedBatchInto / interleaveTriple48LockedBatch split the
// group range across runtime.NumCPU() workers, and each worker routes a
// group through the batch-16 hook (fillRanksSuper) whenever its range
// still holds 16 groups and through the per-group fillRanks path
// otherwise. Which path a given group takes therefore depends on the
// core count of the machine running the call: an encoder with many
// cores and a decoder with few cores can fill the same group through
// different paths. The wire is only portable if the two paths produce
// bit-identical rank pairs on every group index.
//
// Two layers pin that invariant on a real aesitb128 lockSeed with the
// batch-16 hook attached the way triple/seeds.go attaches it:
//
//  1. Direct: bp.fillRanksSuper on a base versus 16 sequential
//     bp.fillRanks calls on base .. base+15, at bases the worker split
//     can never reach (byte-7 → byte-8 carry, top-of-range wrap).
//  2. Wiring: splitTriple48LockedBatchInto with the hook armed versus the
//     same closure with fillRanksSuper = nil, at sizes that straddle
//     the 16-group batch boundary and the worker split, plus the
//     cross round trip (armed encode → disarmed decode and back).
//
// Both layers run under every batch-16 kernel tier the host silicon
// can execute, by setting the aesitbasm dispatch flags atomically per
// tier, so the invariant is pinned for every shipped kernel and for the
// scalar reference. The wiring layer additionally runs under both
// unrank geometries of the batch-16 branch — the 16-lane AVX-512 pass
// and the two-8-lane-pass fallback (ITB_FORCE_INTERLOCK_TIER=avx512x8)
// — on hosts where the 16-lane kernel is selectable.

// x16UnrankGeometries lists the unrank geometries the batch-16 branch
// can run on this host: the auto-selected one, and — when the 16-lane
// AVX-512 kernel is selectable — the explicit 16-lane and two-8-lane
// settings of interlock.UseUnrank16.
func x16UnrankGeometries() []struct {
	name     string
	unrank16 bool
} {
	geometries := []struct {
		name     string
		unrank16 bool
	}{{"auto", interlock.UseUnrank16}}
	if interlock.HasAVX512RankMask {
		geometries = append(geometries,
			struct {
				name     string
				unrank16 bool
			}{"unrank16", true},
			struct {
				name     string
				unrank16 bool
			}{"unrank8x2", false})
	}
	return geometries
}

// x16TierFlags is a snapshot of the aesitbasm batch-16 dispatch flags.
type x16TierFlags struct {
	zmm, ymm, vex, aesni, arm bool
}

func readX16TierFlags() x16TierFlags {
	return x16TierFlags{
		aesitbasm.HasVAESAVX512X16, aesitbasm.HasVAESAVX2X16,
		aesitbasm.HasAVXAESNIX16, aesitbasm.HasAESNIX16, aesitbasm.HasARMAESX16,
	}
}

func (f x16TierFlags) apply() {
	aesitbasm.HasVAESAVX512X16, aesitbasm.HasVAESAVX2X16 = f.zmm, f.ymm
	aesitbasm.HasAVXAESNIX16, aesitbasm.HasAESNIX16, aesitbasm.HasARMAESX16 = f.vex, f.aesni, f.arm
}

// x16HostTiers lists every batch-16 dispatch state the host can
// execute: the auto-selected state, each assembly tier the silicon
// supports, and the scalar reference.
func x16HostTiers() []struct {
	name  string
	flags x16TierFlags
} {
	tiers := []struct {
		name  string
		flags x16TierFlags
	}{
		{"auto", readX16TierFlags()},
	}
	if aes.CPU.HasVAES && aes.CPU.HasAVX512 {
		tiers = append(tiers, struct {
			name  string
			flags x16TierFlags
		}{"avx512", x16TierFlags{zmm: true}})
	}
	if aes.CPU.HasVAES && aes.CPU.HasAVX2 {
		tiers = append(tiers, struct {
			name  string
			flags x16TierFlags
		}{"vaesavx2", x16TierFlags{ymm: true}})
	}
	if aes.CPU.HasAESNI && aes.CPU.HasAVX2 {
		tiers = append(tiers, struct {
			name  string
			flags x16TierFlags
		}{"vex", x16TierFlags{vex: true}})
	}
	if aes.CPU.HasAESNI {
		tiers = append(tiers, struct {
			name  string
			flags x16TierFlags
		}{"aesni", x16TierFlags{aesni: true}})
	}
	if aes.CPU.HasARMCrypto {
		tiers = append(tiers, struct {
			name  string
			flags x16TierFlags
		}{"neon", x16TierFlags{arm: true}})
	}
	tiers = append(tiers, struct {
		name  string
		flags x16TierFlags
	}{"scalar", x16TierFlags{}})
	return tiers
}

// x16LockSeedCases builds aesitb128 lockSeeds with the batch-16 hook
// attached exactly as the hashes package's constructors attach it (the
// hook dispatches through aesitbasm.FusedChain13x16 under the seed's
// own fixed key), on fixed keys and components for reproducibility. The
// seeds carry no fused ChainHash hooks, so fillRanks / fillRanksX4 run
// the sequential Hash / BatchHash cascade over the prepended lock
// components and the layers below pin the batch-16 kernel to that
// sequential reference. Every case's fillRanksSuper must be armed; the
// test is skipped when ITB_FORCE_INTERLOCK_PRF_FILL_SEQ disarms it.
func x16LockSeedCases(t *testing.T) []struct {
	label string
	bp    lockBatchPRF48
} {
	t.Helper()
	if forcetier.InterlockPRFFillSeq() {
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ set; batch-16 hook disarmed")
	}
	nonce := interlock48Nonce()
	keys := [][16]byte{
		{},
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		{0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98},
	}
	componentSets := [][]uint64{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{0x0102030405060708, 0x090a0b0c0d0e0f00, 0xFFFFFFFFFFFFFFFF, 0, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555},
		{0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917},
	}
	var cases []struct {
		label string
		bp    lockBatchPRF48
	}
	for i := range keys {
		key := keys[i]
		h, bh, _ := MakeAESITB128Hash(key)
		seed, err := SeedFromComponents128(h, componentSets[i]...)
		if err != nil {
			t.Fatal(err)
		}
		seed.BatchHash = bh
		seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
			aesitbasm.FusedChain13x16(&key, components, groupIdxBase, out)
		})
		bp := buildLockBatchPRF48_128(seed, nonce)
		if bp.fillRanksSuper == nil {
			t.Fatalf("case %d: fillRanksSuper not armed", i)
		}
		cases = append(cases, struct {
			label string
			bp    lockBatchPRF48
		}{[]string{"zero-key", "ascending-key", "mixed-key"}[i], bp})
	}
	return cases
}

// x16FillRanksBases are the group-index bases the direct layer checks:
// small bases, bases straddling the byte-7 → byte-8 carry of the
// in-register groupIdx synthesis, and bases whose 16-lane batch wraps
// the uint64 range.
var x16FillRanksBases = []uint64{
	0, 1, 7, 15, 16, 17, 31, 0xFF, 0x100, 0xFFF0, 0xFFF8,
	0x00FFFFFFFFFFFFF0, 0x00FFFFFFFFFFFFF8, 0x00FFFFFFFFFFFFFF, 0x0100000000000000,
	0x7FFFFFFFFFFFFFF0, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
	0xFEFEFEFEFEFEFEFE, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFFFFF8, 0xFFFFFFFFFFFFFFFF,
}

// TestFillRanksSuperVsFillRanksParity is the direct layer: one
// fillRanksSuper call on a base must produce exactly the 16 rank pairs
// of 16 sequential fillRanks calls on base .. base+15, under every
// batch-16 dispatch tier the host can execute.
func TestFillRanksSuperVsFillRanksParity(t *testing.T) {
	saved := readX16TierFlags()
	t.Cleanup(saved.apply)
	cases := x16LockSeedCases(t)
	for _, tier := range x16HostTiers() {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			tier.flags.apply()
			for _, tc := range cases {
				for _, base := range x16FillRanksBases {
					var scratch lockFillScratch48
					var super [8 * lockBatchFactor48Max]uint64
					tc.bp.fillRanksSuper(&scratch, base, super[0:32])

					var buf [13]byte
					var seq [8 * lockBatchFactor48Max]uint64
					for i := 0; i < 16; i++ {
						tc.bp.fillRanks(buf[:], base+uint64(i), seq[2*i:])
					}
					for i := 0; i < 16; i++ {
						if super[2*i] != seq[2*i] || super[2*i+1] != seq[2*i+1] {
							t.Fatalf("%s base=%#x lane %d: fillRanksSuper (%#x, %#x) != fillRanks (%#x, %#x)",
								tc.label, base, i, super[2*i], super[2*i+1], seq[2*i], seq[2*i+1])
						}
					}
				}
			}
		})
	}
}

// x16SplitSizes are framed-input sizes in bytes chosen so the group
// count straddles the 16-group batch boundary (15 / 16 / 17, 31 / 32 /
// 33, 47 / 48, 63 / 64 / 65, 96 groups at 6 bytes per group), plus the
// standard residue-class and worker-spawning sizes.
var x16SplitSizes = func() []int {
	sizes := []int{
		6 * 15, 6*15 + 1, 6 * 16, 6*16 + 1, 6 * 17,
		6 * 31, 6 * 32, 6*32 + 5, 6 * 33,
		6 * 47, 6 * 48, 6 * 63, 6 * 64, 6 * 65, 6 * 96,
		6*100 + 3, 6*1000 + 1, 6*1024 + 2,
	}
	return append(sizes, interlock48Sizes...)
}()

// TestFillRanksSuperSplitParity is the wiring layer: the batched split
// with fillRanksSuper armed must produce lane bytes bit-identical to
// the same closure with fillRanksSuper disarmed (x4 / per-group paths
// only), under every batch-16 dispatch tier the host can execute.
func TestFillRanksSuperSplitParity(t *testing.T) {
	saved := readX16TierFlags()
	t.Cleanup(saved.apply)
	savedUnrank16 := interlock.UseUnrank16
	t.Cleanup(func() { interlock.UseUnrank16 = savedUnrank16 })
	// Snapshot the tier list (its "auto" entry reads the flags) before any
	// subtest mutates them.
	tiers := x16HostTiers()
	cases := x16LockSeedCases(t)
	inputs := make([][]byte, len(x16SplitSizes))
	for i, sz := range x16SplitSizes {
		inputs[i] = interlock48RandomBytes(sz)
	}
	for _, geo := range x16UnrankGeometries() {
		geo := geo
		t.Run(geo.name, func(t *testing.T) {
			interlock.UseUnrank16 = geo.unrank16
			for _, tier := range tiers {
				tier := tier
				t.Run(tier.name, func(t *testing.T) {
					tier.flags.apply()
					for _, tc := range cases {
						seq := tc.bp
						seq.fillRanksSuper = nil
						for i, framed := range inputs {
							src := framedSrc48{body: framed}
							M := src.chunkCount()
							x0, x1, x2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
							s0, s1, s2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
							splitTriple48LockedBatchInto(src, x0, x1, x2, tc.bp, nil)
							splitTriple48LockedBatchInto(src, s0, s1, s2, seq, nil)
							if !bytes.Equal(x0, s0) || !bytes.Equal(x1, s1) || !bytes.Equal(x2, s2) {
								t.Fatalf("%s size %d: batch-16 lanes diverge from sequential lanes", tc.label, x16SplitSizes[i])
							}
						}
					}
				})
			}
		})
	}
}

// TestFillRanksSuperCrossRoundTrip encodes with the batch-16 hook armed
// and decodes with it disarmed, and vice versa, requiring exact
// recovery of the framed input — the cross-machine shape (many-core
// encoder, few-core decoder) reduced to one process.
func TestFillRanksSuperCrossRoundTrip(t *testing.T) {
	saved := readX16TierFlags()
	t.Cleanup(saved.apply)
	savedUnrank16 := interlock.UseUnrank16
	t.Cleanup(func() { interlock.UseUnrank16 = savedUnrank16 })
	// Snapshot the tier list (its "auto" entry reads the flags) before any
	// subtest mutates them.
	tiers := x16HostTiers()
	cases := x16LockSeedCases(t)
	for _, geo := range x16UnrankGeometries() {
		geo := geo
		t.Run(geo.name, func(t *testing.T) {
			interlock.UseUnrank16 = geo.unrank16
			for _, tier := range tiers {
				tier := tier
				t.Run(tier.name, func(t *testing.T) {
					tier.flags.apply()
					for _, tc := range cases {
						seq := tc.bp
						seq.fillRanksSuper = nil
						for _, sz := range x16SplitSizes {
							framed := interlock48RandomBytes(sz)
							src := framedSrc48{body: framed}
							M := src.chunkCount()
							for _, dir := range []struct {
								label    string
								enc, dec lockBatchPRF48
							}{
								{"armed→disarmed", tc.bp, seq},
								{"disarmed→armed", seq, tc.bp},
								{"armed→armed", tc.bp, tc.bp},
							} {
								p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
								splitTriple48LockedBatchInto(src, p0, p1, p2, dir.enc, nil)
								got := interleaveTriple48LockedBatch(p0, p1, p2, dir.dec, nil)
								if len(got) < len(framed) || !bytes.Equal(got[:len(framed)], framed) {
									t.Fatalf("%s size %d %s: round-trip mismatch", tc.label, sz, dir.label)
								}
								for i := len(framed); i < len(got); i++ {
									if got[i] != 0 {
										t.Fatalf("%s size %d %s: non-zero padding byte at %d", tc.label, sz, dir.label, i)
									}
								}
							}
						}
					}
				})
			}
		})
	}
}
