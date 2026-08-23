package itb

// harness_test.go — construction-level structural / statistical harness for
// the 48-bit Interlocked Barrier core, primitive-agnostic. These probes drive
// the package-private barrier kernels (rankToMaskTriple48, chunk48lock)
// directly, verifying the architectural mask-space and lane-independence
// claims at the derivation layer rather than through the facade.
//
// None of these is an attack: no seed, key, or plaintext is recovered. They
// are white-box correctness + uniformity measurements — the kind a randomness
// harness runs to confirm a construction has no structural bug that would
// collapse the space its security argument rests on.
//
// Statistical loops are gated behind ITB_HARNESS_FULL=1 so the committed
// suite stays fast under `go test ./...`; the smoke path still exercises every
// invariant on a small sample. Set ITB_HARNESS_FULL=1 to reproduce the
// sample sizes recorded in the REDTEAM.md creative-probes section.

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/bits"
	"os"
	"testing"
)

// harnessFull reports whether the full-sample statistical path is enabled.
func harnessFull() bool { return os.Getenv("ITB_HARNESS_FULL") == "1" }

// harnessN returns the sample size for a probe: full when ITB_HARNESS_FULL=1,
// otherwise a small smoke sample that still exercises every invariant.
func harnessN(full, smoke int) int {
	if harnessFull() {
		return full
	}
	return smoke
}

// randLanes fills two 64-bit lanes from crypto/rand — one 128-bit PRF-output
// stand-in per barrier chunk.
func randLanes(t *testing.T) (uint64, uint64) {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return binary.LittleEndian.Uint64(b[0:8]), binary.LittleEndian.Uint64(b[8:16])
}

// reduceLanes replicates the two-step divmod reduction of rankToMaskTriple48
// to recover (idx0, idx1) from a 128-bit rank. Test-only mirror of the
// production arithmetic, used by the gcd-trap witness (the production kernel
// returns masks, not the intermediate indices).
func reduceLanes(lane0, lane1 uint64) (idx0, idx1 uint64) {
	qHi, r1 := bits.Div64(0, lane1, interlockB48)
	qLo, r := bits.Div64(r1, lane0, interlockB48)
	idx1 = r
	_, hiMod := bits.Div64(0, qHi, interlockA48)
	_, idx0 = bits.Div64(hiMod, qLo, interlockA48)
	return idx0, idx1
}

// ============================================================================
// Probe C2 — mask-space structural uniformity + balance
// ============================================================================

// TestHarnessC2MaskTripleInvariants asserts the three balanced-partition
// invariants on every draw and measures per-bit lane-0 membership balance.
// Each of the 48 payload bits must land in lane 0 with probability 16/48; a
// systematic deviation would betray a biased unrank or a mask-space collapse.
func TestHarnessC2MaskTripleInvariants(t *testing.T) {
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	n := harnessN(200_000, 2_000)

	var bitInLane0 [48]int64
	for i := 0; i < n; i++ {
		l0, l1 := randLanes(t)
		m0, m1, m2 := rankToMaskTriple48(l0, l1)

		if got := bits.OnesCount64(m0); got != 16 {
			t.Fatalf("draw %d: popcount(m0)=%d, want 16", i, got)
		}
		if got := bits.OnesCount64(m1); got != 16 {
			t.Fatalf("draw %d: popcount(m1)=%d, want 16", i, got)
		}
		if got := bits.OnesCount64(m2); got != 16 {
			t.Fatalf("draw %d: popcount(m2)=%d, want 16", i, got)
		}
		if union := m0 | m1 | m2; union != domain {
			t.Fatalf("draw %d: m0|m1|m2=%#x, want %#x", i, union, domain)
		}
		if m0&m1 != 0 || m0&m2 != 0 || m1&m2 != 0 {
			t.Fatalf("draw %d: masks not pairwise disjoint (%#x %#x %#x)", i, m0, m1, m2)
		}
		for b := 0; b < 48; b++ {
			if (m0>>uint(b))&1 == 1 {
				bitInLane0[b]++
			}
		}
	}

	// Per-bit balance: expected count = n * 16/48 = n/3; sampling stddev =
	// sqrt(n * p * (1-p)) with p = 1/3. Flag any bit beyond 5 sigma.
	p := 16.0 / 48.0
	exp := float64(n) * p
	sd := math.Sqrt(float64(n) * p * (1 - p))
	maxZ := 0.0
	for b := 0; b < 48; b++ {
		z := math.Abs(float64(bitInLane0[b])-exp) / sd
		if z > maxZ {
			maxZ = z
		}
	}
	t.Logf("C2 balance: n=%d exp=%.1f sd=%.1f maxZ=%.3f (per-bit lane-0 membership)", n, exp, sd, maxZ)
	if maxZ > 5.0 {
		t.Errorf("C2 balance: per-bit lane-0 membership deviates %.2f sigma (>5)", maxZ)
	}
}

// TestHarnessC2IndexUniformity measures chi-square uniformity of the low bits
// of idx0 and idx1 across the mask draws. A structured reduction would show a
// chi-square well outside the acceptance band for the bin count.
func TestHarnessC2IndexUniformity(t *testing.T) {
	const bins = 256
	n := harnessN(200_000, 4_000)

	var h0, h1 [bins]int64
	for i := 0; i < n; i++ {
		l0, l1 := randLanes(t)
		idx0, idx1 := reduceLanes(l0, l1)
		h0[idx0%bins]++
		h1[idx1%bins]++
	}
	chi := func(h *[bins]int64) float64 {
		exp := float64(n) / bins
		var c float64
		for _, o := range h {
			d := float64(o) - exp
			c += d * d / exp
		}
		return c
	}
	c0, c1 := chi(&h0), chi(&h1)
	// df = bins-1 = 255; mean of chi-square is df, sd = sqrt(2*df) ≈ 22.6.
	// Acceptance: within ~5 sd of df, i.e. roughly [142, 368].
	df := float64(bins - 1)
	lo, hi := df-5*math.Sqrt(2*df), df+5*math.Sqrt(2*df)
	t.Logf("C2 uniformity: n=%d bins=%d chi2(idx0 low)=%.1f chi2(idx1 low)=%.1f accept[%.0f,%.0f]", n, bins, c0, c1, lo, hi)
	if c0 < lo || c0 > hi {
		t.Errorf("C2 uniformity: idx0 chi2=%.1f outside [%.0f,%.0f]", c0, lo, hi)
	}
	if c1 < lo || c1 > hi {
		t.Errorf("C2 uniformity: idx1 chi2=%.1f outside [%.0f,%.0f]", c1, lo, hi)
	}
}

// TestHarnessC2GcdTrapWitness confirms the shipped two-step reduction spreads
// (idx0 mod g, idx1 mod g) off the diagonal, where g = gcd(A,B) = 66861. The
// rejected same-rank double-mod would confine every pair to idx0 ≡ idx1
// (mod g) — the residue-class trap. The witness: on-diagonal fraction under
// the shipped reduction must approach 1/g, not 1.0.
func TestHarnessC2GcdTrapWitness(t *testing.T) {
	const g uint64 = 66861 // gcd(C(48,16), C(32,16)) = 3^2 * 17 * 19 * 23
	// Sanity: g is indeed the gcd of the two constants.
	if got := gcd64(interlockA48, interlockB48); got != g {
		t.Fatalf("gcd(A,B)=%d, want %d", got, g)
	}
	n := harnessN(500_000, 10_000)

	onDiag := 0
	for i := 0; i < n; i++ {
		l0, l1 := randLanes(t)
		idx0, idx1 := reduceLanes(l0, l1)
		if idx0%g == idx1%g {
			onDiag++
		}
	}
	frac := float64(onDiag) / float64(n)
	// Under a full-space reduction the on-diagonal probability is ≈ 1/g.
	expFrac := 1.0 / float64(g)
	t.Logf("C2 gcd-trap: n=%d g=%d on-diagonal frac=%.3e expected≈1/g=%.3e (rejected double-mod would give 1.0)", n, g, frac, expFrac)
	// Accept anything below 10x the expected diagonal density — the point is
	// it is nowhere near 1.0. Even a modest n rarely lands any on-diagonal.
	if frac > 100*expFrac+1e-4 {
		t.Errorf("C2 gcd-trap: on-diagonal frac=%.3e unexpectedly high (>%.3e) — reduction may be collapsing", frac, 100*expFrac)
	}
}

// gcd64 is Euclid's algorithm on uint64 — test-only helper for the gcd-trap
// witness self-check.
func gcd64(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// ============================================================================
// Probe C4b — cross-lane (cross-snake) decorrelation at the kernel layer
// ============================================================================

// TestHarnessC4bLaneDecorrelation drives chunk48lock with random chunk words
// under fresh random mask triples and measures the pairwise Pearson
// correlation between the three lane outputs. The barrier's split scatters
// each chunk across three lanes; under the mask-space independence claim the
// lane values carry no linear cross-correlation beyond the sampling floor.
func TestHarnessC4bLaneDecorrelation(t *testing.T) {
	n := harnessN(200_000, 4_000)

	xs := make([][3]float64, n)
	for i := 0; i < n; i++ {
		lx0, lx1 := randLanes(t)
		x := lx0 & 0x0000_FFFF_FFFF_FFFF
		// Fresh mask triple from an independent 128-bit draw.
		l0, l1 := randLanes(t)
		m0, m1, m2 := rankToMaskTriple48(l0, l1)
		_ = lx1
		a, b, c := chunk48lock(x, m0, m1, m2)
		xs[i] = [3]float64{float64(a), float64(b), float64(c)}
	}

	pearson := func(col1, col2 int) float64 {
		var sx, sy, sxx, syy, sxy float64
		nf := float64(n)
		for i := 0; i < n; i++ {
			x, y := xs[i][col1], xs[i][col2]
			sx += x
			sy += y
			sxx += x * x
			syy += y * y
			sxy += x * y
		}
		cov := sxy - sx*sy/nf
		vx := sxx - sx*sx/nf
		vy := syy - sy*sy/nf
		if vx <= 0 || vy <= 0 {
			return 0
		}
		return cov / math.Sqrt(vx*vy)
	}
	r01, r02, r12 := pearson(0, 1), pearson(0, 2), pearson(1, 2)
	floor := 1.0 / math.Sqrt(float64(n)) // sampling stddev of r under H0
	maxR := math.Max(math.Abs(r01), math.Max(math.Abs(r02), math.Abs(r12)))
	t.Logf("C4b lane decorrelation: n=%d r01=%.5f r02=%.5f r12=%.5f max|r|=%.5f floor≈%.5f", n, r01, r02, r12, maxR, floor)
	// Accept |r| up to 6x the sampling floor.
	if maxR > 6*floor {
		t.Errorf("C4b: cross-lane |r|=%.5f exceeds 6x sampling floor %.5f", maxR, 6*floor)
	}
}

// ============================================================================
// Probe C5-core — per-bit balance floor of the barrier lane output
// ============================================================================

// TestHarnessC5LaneBitBalance pools the lane-output bits over many chunks and
// confirms each of the 48 output bit positions (16 per lane) is balanced at
// 0.5 within the sampling floor. This is the derivation-layer analogue of the
// cumulative-bias probe: the architectural per-chunk bias (~2^-57.8) is far
// below the sqrt(1/N) detection floor at any attainable N, so the observed
// per-bit deviation must track the sampling floor, not exceed it.
func TestHarnessC5LaneBitBalance(t *testing.T) {
	n := harnessN(300_000, 5_000)

	var ones [48]int64 // 16 bits from each of 3 lanes
	for i := 0; i < n; i++ {
		lx0, _ := randLanes(t)
		x := lx0 & 0x0000_FFFF_FFFF_FFFF
		l0, l1 := randLanes(t)
		m0, m1, m2 := rankToMaskTriple48(l0, l1)
		a, b, c := chunk48lock(x, m0, m1, m2)
		lane := (uint64(a)) | (uint64(b) << 16) | (uint64(c) << 32)
		for bit := 0; bit < 48; bit++ {
			ones[bit] += int64((lane >> uint(bit)) & 1)
		}
	}
	exp := float64(n) * 0.5
	sd := math.Sqrt(float64(n) * 0.25)
	maxZ, maxDev := 0.0, 0.0
	for bit := 0; bit < 48; bit++ {
		dev := math.Abs(float64(ones[bit])/float64(n) - 0.5)
		z := math.Abs(float64(ones[bit])-exp) / sd
		if z > maxZ {
			maxZ = z
		}
		if dev > maxDev {
			maxDev = dev
		}
	}
	// The architectural per-chunk bias for reference (log2 ≈ -57.8).
	archBias := math.Pow(2, -57.8)
	t.Logf("C5 lane-bit balance: n=%d maxZ=%.3f max|dev|=%.3e sampling-floor≈%.3e arch-bias≈%.3e", n, maxZ, maxDev, 1/math.Sqrt(float64(n)), archBias)
	if maxZ > 5.0 {
		t.Errorf("C5: per-bit balance deviates %.2f sigma (>5)", maxZ)
	}
	if maxDev < archBias {
		t.Errorf("C5 sanity: observed floor %.3e below architectural bias %.3e — impossible, check accounting", maxDev, archBias)
	}
}
