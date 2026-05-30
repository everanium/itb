package parallax

import (
	"math"
	"testing"
)

func TestFisherYatesIsPermutation(t *testing.T) {
	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	for _, n := range []int{1, 2, 3, 9, 24, 100, 255} {
		perm := fisherYates(seed, n)
		if len(perm) != n {
			t.Fatalf("n=%d len=%d", n, len(perm))
		}
		seen := make([]bool, n)
		for _, v := range perm {
			if v < 0 || v >= n {
				t.Fatalf("n=%d out-of-range value %d", n, v)
			}
			if seen[v] {
				t.Fatalf("n=%d duplicate value %d", n, v)
			}
			seen[v] = true
		}
	}
}

func TestFisherYatesDeterministic(t *testing.T) {
	seed := []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90}
	a := fisherYates(seed, 50)
	b := fisherYates(seed, 50)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("fisherYates non-deterministic at i=%d", i)
		}
	}
}

func TestFisherYatesDistinctSeedsDiffer(t *testing.T) {
	seedA := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	seedB := append([]byte(nil), seedA...)
	seedB[0] ^= 0x80
	a := fisherYates(seedA, 32)
	b := fisherYates(seedB, 32)
	equal := true
	for i := range a {
		if a[i] != b[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatal("fisherYates produced identical permutations for differing seeds")
	}
}

// TestFisherYatesUniformity does a chi-square goodness-of-fit check on
// the first-position output across many seeds. The expected count per
// outcome is samples / n; the chi-square statistic must sit below the
// upper-tail critical value at a comfortable margin.
func TestFisherYatesUniformity(t *testing.T) {
	const n = 9
	const samples = 1 << 17
	counts := make([]int, n)
	for s := uint64(0); s < samples; s++ {
		var seed [16]byte
		// Spread the trial index across both seed halves so both
		// SplitMix64 seedings differ between trials.
		writeUint64LE(seed[:8], s*0x9e3779b97f4a7c15+0x12345)
		writeUint64LE(seed[8:], s*0xbf58476d1ce4e5b9+0x6789a)
		perm := fisherYates(seed[:], n)
		counts[perm[0]]++
	}
	expected := float64(samples) / float64(n)
	chi := 0.0
	for _, c := range counts {
		d := float64(c) - expected
		chi += d * d / expected
	}
	// 8 degrees of freedom, p=0.001 critical value ≈ 26.12.
	if chi > 26.12 {
		t.Fatalf("chi-square = %.2f exceeds critical 26.12 for df=%d", chi, n-1)
	}
	if math.IsNaN(chi) {
		t.Fatal("chi-square NaN")
	}
}

func writeUint64LE(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
}

func TestScheduleReproducibleAcrossCiphersets(t *testing.T) {
	palette := []string{"aescmac", "chacha20", "blake3", "siphash24"}
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	master := mustMaster(t)
	csA := mustCipherset(t, master, schedule)
	csB := mustCipherset(t, master, schedule)
	nonce := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	piA, err := buildPermutation(schedule, csA, nonce)
	if err != nil {
		t.Fatalf("buildPermutation A: %v", err)
	}
	piB, err := buildPermutation(schedule, csB, nonce)
	if err != nil {
		t.Fatalf("buildPermutation B: %v", err)
	}
	if len(piA) != len(piB) {
		t.Fatalf("permutation length mismatch")
	}
	for i := range piA {
		if piA[i] != piB[i] {
			t.Fatalf("schedule diverges at i=%d (%d vs %d)", i, piA[i], piB[i])
		}
	}
}

func TestScheduleChangesWithNonce(t *testing.T) {
	palette := []string{"aescmac", "chacha20", "blake3", "siphash24", "blake2s"}
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), schedule)
	nonceA := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	nonceB := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	piA, err := buildPermutation(schedule, cs, nonceA)
	if err != nil {
		t.Fatalf("buildPermutation A: %v", err)
	}
	piB, err := buildPermutation(schedule, cs, nonceB)
	if err != nil {
		t.Fatalf("buildPermutation B: %v", err)
	}
	equal := true
	for i := range piA {
		if piA[i] != piB[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatalf("permutation unchanged when nonce changed")
	}
}

func TestUnbiasedRangeBoundZero(t *testing.T) {
	state := uint64(42)
	if got := unbiasedRange(&state, 0); got != 0 {
		t.Fatalf("unbiasedRange(0) = %d, want 0", got)
	}
}
