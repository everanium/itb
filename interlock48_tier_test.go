//go:build amd64 && !purego && !noitbasm

package itb

import (
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/interlock"
)

// interlockTier names one dispatch arm of the 48-bit interlock kernels
// together with the capability-flag state that selects it.
type interlockTier struct {
	name   string
	avx512 bool
	avx2   bool
	bmi2   bool
}

// runnableInterlockTiers enumerates the interlock dispatch arms the
// current silicon can execute: the pure-Go scalar paths always, the
// BMI2 PEXT/PDEP chunk kernels and the AVX2 4-lane rank-unrank kernel
// when the silicon has them, the AVX-512 8-lane rank-unrank kernel on
// AVX-512F hosts.
func runnableInterlockTiers() []interlockTier {
	tiers := []interlockTier{{name: "scalar"}}
	if cpu.X86.HasAVX2 && cpu.X86.HasBMI2 {
		tiers = append(tiers, interlockTier{name: "avx2", avx2: true, bmi2: true})
	}
	if cpu.X86.HasAVX512F {
		tiers = append(tiers, interlockTier{name: "avx512", avx512: true, bmi2: cpu.X86.HasBMI2})
	}
	return tiers
}

// setInterlockTier overrides the interlock dispatch capability flags
// for one test and restores the saved values on cleanup. The flags are
// process-global, so tests using this helper must not run in parallel.
func setInterlockTier(t *testing.T, tier interlockTier) {
	t.Helper()
	saved512 := interlock.HasAVX512RankMask
	saved2 := interlock.HasAVX2RankMask
	savedBMI2 := interlock.HasBMI2
	interlock.HasAVX512RankMask = tier.avx512
	interlock.HasAVX2RankMask = tier.avx2
	interlock.HasBMI2 = tier.bmi2
	t.Cleanup(func() {
		interlock.HasAVX512RankMask = saved512
		interlock.HasAVX2RankMask = saved2
		interlock.HasBMI2 = savedBMI2
	})
}

// tierTestRank derives a deterministic 128-bit rank pair from an index,
// spreading values across the rank space (including near-zero and
// all-ones patterns at the extremes).
func tierTestRank(i int) (lo, hi uint64) {
	switch i {
	case 0:
		return 0, 0
	case 1:
		return ^uint64(0), ^uint64(0)
	}
	lo = uint64(i) * 0x9E3779B97F4A7C15
	hi = uint64(i) * 0xC2B2AE3D27D4EB4F
	return lo, hi
}

// TestChunk48LockTierParity verifies that the BMI2 PEXT/PDEP chunk
// kernels and the pure-Go softPEXT48/softPDEP48 fallback produce
// identical lane splits and roundtrip every 48-bit input under
// identical mask triples.
func TestChunk48LockTierParity(t *testing.T) {
	if !interlock.HasBMI2 {
		t.Skip("host lacks BMI2; scalar arm is the only runnable path")
	}
	for i := 0; i < 16; i++ {
		lo, hi := tierTestRank(i)
		m0, m1, m2 := rankToMaskTriple48(lo, hi)
		x := (uint64(i)*0xD1B54A32D192ED03 + 0x0123456789AB) & (1<<48 - 1)

		// Reference: pure-Go path.
		setInterlockTier(t, interlockTier{name: "scalar"})
		wantL0, wantL1, wantL2 := chunk48lock(x, m0, m1, m2)
		if got := unchunk48lock(wantL0, wantL1, wantL2, m0, m1, m2); got != x {
			t.Fatalf("rank %d: scalar roundtrip: got %#x, want %#x", i, got, x)
		}

		// BMI2 hardware path must agree lane-for-lane and roundtrip.
		setInterlockTier(t, interlockTier{name: "bmi2", bmi2: true})
		gotL0, gotL1, gotL2 := chunk48lock(x, m0, m1, m2)
		if gotL0 != wantL0 || gotL1 != wantL1 || gotL2 != wantL2 {
			t.Fatalf("rank %d: BMI2 lanes (%#x,%#x,%#x) diverge from scalar (%#x,%#x,%#x)",
				i, gotL0, gotL1, gotL2, wantL0, wantL1, wantL2)
		}
		if got := unchunk48lock(gotL0, gotL1, gotL2, m0, m1, m2); got != x {
			t.Fatalf("rank %d: BMI2 roundtrip: got %#x, want %#x", i, got, x)
		}
	}
}

// TestFillLockMasksTriple48TierParity verifies that the batched mask
// derivation agrees bit-exactly across every runnable dispatch arm —
// AVX-512 8-lane kernel, AVX2 4-lane kernel, per-rank scalar
// rankToMaskTriple48 — at every chunk count the batch contract admits.
func TestFillLockMasksTriple48TierParity(t *testing.T) {
	var prf [8]uint64
	for i := range prf {
		lo, hi := tierTestRank(i / 2)
		if i%2 == 0 {
			prf[i] = lo
		} else {
			prf[i] = hi
		}
	}
	for count := 1; count <= lockBatchFactor48Max; count++ {
		// Reference: scalar per-rank derivation.
		setInterlockTier(t, interlockTier{name: "scalar"})
		var want [lockBatchFactor48Max][3]uint64
		fillLockMasksTriple48(&prf, count, &want)
		for j := 0; j < count; j++ {
			lo, hi := prf[2*j], prf[2*j+1]
			m0, m1, m2 := rankToMaskTriple48(lo, hi)
			if want[j] != [3]uint64{m0, m1, m2} {
				t.Fatalf("count %d chunk %d: scalar batch diverges from rankToMaskTriple48", count, j)
			}
		}
		for _, tier := range runnableInterlockTiers() {
			if tier.name == "scalar" {
				continue
			}
			t.Run(tier.name, func(t *testing.T) {
				setInterlockTier(t, tier)
				var got [lockBatchFactor48Max][3]uint64
				fillLockMasksTriple48(&prf, count, &got)
				if got != want {
					t.Fatalf("count %d: %s arm diverges from scalar reference:\n got %#x\nwant %#x",
						count, tier.name, got, want)
				}
			})
		}
	}
}

// TestFillLockMasksTriple48SuperTierParity verifies the superblock-wide
// mask derivation across every runnable dispatch arm at every chunk
// count 1..superChunks48, including the short-superblock tail where the
// upper kernel lanes run on zero ranks.
func TestFillLockMasksTriple48SuperTierParity(t *testing.T) {
	var prf [2 * superChunks48]uint64
	for i := range prf {
		lo, hi := tierTestRank(i / 2)
		if i%2 == 0 {
			prf[i] = lo
		} else {
			prf[i] = hi
		}
	}
	for count := 1; count <= superChunks48; count++ {
		// Reference: scalar per-rank derivation.
		setInterlockTier(t, interlockTier{name: "scalar"})
		var want [superChunks48][3]uint64
		fillLockMasksTriple48Super(&prf, count, &want)
		for j := 0; j < count; j++ {
			m0, m1, m2 := rankToMaskTriple48(prf[2*j], prf[2*j+1])
			if want[j] != [3]uint64{m0, m1, m2} {
				t.Fatalf("count %d chunk %d: scalar super batch diverges from rankToMaskTriple48", count, j)
			}
		}
		for _, tier := range runnableInterlockTiers() {
			if tier.name == "scalar" {
				continue
			}
			t.Run(tier.name, func(t *testing.T) {
				setInterlockTier(t, tier)
				var got [superChunks48][3]uint64
				fillLockMasksTriple48Super(&prf, count, &got)
				if got != want {
					t.Fatalf("count %d: %s arm diverges from scalar reference:\n got %#x\nwant %#x",
						count, tier.name, got, want)
				}
			})
		}
	}
}
