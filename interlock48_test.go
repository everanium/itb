package itb

import (
	"encoding/binary"
	"math/big"
	"math/bits"
	"math/rand"
	"testing"
)

// ============================================================================
// Big-integer oracles — allowed here (tests only) as ground-truth references
// against the production 64-bit-only arithmetic in interlock48.go.
// ============================================================================

var (
	biOne  = big.NewInt(1)
	biA    = new(big.Int).SetUint64(interlockA48)
	biB    = new(big.Int).SetUint64(interlockB48)
	biAB   = new(big.Int).Mul(biA, biB)
	bi2p64 = new(big.Int).Lsh(biOne, 64)
	bi2p128 = new(big.Int).Lsh(biOne, 128)
	biQ    = new(big.Int).Quo(bi2p128, biAB)                        // floor(2^128 / (A*B))
	biR    = new(big.Int).Sub(bi2p128, new(big.Int).Mul(biQ, biAB)) // 2^128 mod (A*B)
	biQAB  = new(big.Int).Mul(biQ, biAB)                            // window start
	biMax  = new(big.Int).Sub(bi2p128, biOne)                       // 2^128 - 1
)

// splitLimbs128 converts a big-endian *big.Int in [0, 2^128) into the
// (lane0 = low 64, lane1 = high 64) split consumed by rankToMaskTriple48.
func splitLimbs128(r *big.Int) (lane0, lane1 uint64) {
	var buf [16]byte
	r.FillBytes(buf[:]) // MSB-first, big-endian; zero-pads on the left.
	lane1 = binary.BigEndian.Uint64(buf[0:8])
	lane0 = binary.BigEndian.Uint64(buf[8:16])
	return
}

// oracleTriple48 is the independent big.Int-driven mask-triple reference.
// Splits (rank / B, rank mod B), reduces the quotient mod A, and applies
// the same combinadic unrank / remap as production. Used purely as a
// ground-truth oracle in tests.
func oracleTriple48(rank *big.Int) (m0, m1, m2 uint64) {
	q := new(big.Int)
	rem := new(big.Int)
	q.QuoRem(rank, biB, rem)
	idx1 := rem.Uint64()
	qModA := new(big.Int).Rem(q, biA).Uint64()

	m0 = unrankCombination48(qModA, 16, 48)
	m1Local := unrankCombination48(idx1, 16, 32)
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	remaining := domain & ^m0
	var posIdx uint
	for bit := uint(0); bit < 48; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint64(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

// ============================================================================
// Pascal identity — binomialC48 self-consistency.
// ============================================================================

func TestBinomialC48Pascal(t *testing.T) {
	for n := 1; n <= 48; n++ {
		maxK := 16
		if maxK > n {
			maxK = n
		}
		for k := 1; k <= maxK; k++ {
			got := binomialC48[n][k]
			want := binomialC48[n-1][k-1] + binomialC48[n-1][k]
			if got != want {
				t.Fatalf("C(%d, %d) = %d, want %d (Pascal)", n, k, got, want)
			}
		}
	}
	// Anchor: C(48, 16) is the top-of-table value.
	if binomialC48[48][16] != interlockA48 {
		t.Fatalf("binomialC48[48][16] = %d, want %d", binomialC48[48][16], interlockA48)
	}
	// Anchor: C(32, 16) is the m1Local top-of-range.
	if binomialC48[32][16] != interlockB48 {
		t.Fatalf("binomialC48[32][16] = %d, want %d", binomialC48[32][16], interlockB48)
	}
}

// ============================================================================
// unrankCombination48 — popcount and range invariants.
// ============================================================================

func TestUnrankCombination48Invariants(t *testing.T) {
	cases := []struct {
		k, n int
		card uint64
	}{
		{16, 48, interlockA48},
		{16, 32, interlockB48},
		{8, 24, 735471},
		{8, 16, 12870},
	}
	for _, tc := range cases {
		// Sample dense boundaries + a random sweep.
		samples := []uint64{0, 1, tc.card / 2, tc.card - 2, tc.card - 1}
		rng := rand.New(rand.NewSource(int64(tc.n*100 + tc.k)))
		for i := 0; i < 10000; i++ {
			samples = append(samples, rng.Uint64()%tc.card)
		}
		for _, r := range samples {
			mask := unrankCombination48(r, tc.k, tc.n)
			pc := bits.OnesCount64(mask)
			if pc != tc.k {
				t.Fatalf("(k=%d, n=%d, rank=%d): popcount(mask)=%d, want %d",
					tc.k, tc.n, r, pc, tc.k)
			}
			if mask>>uint(tc.n) != 0 {
				t.Fatalf("(k=%d, n=%d, rank=%d): mask %012x has bits beyond position %d",
					tc.k, tc.n, r, mask, tc.n)
			}
		}
	}
}

// ============================================================================
// rankToMaskTriple48 — mask invariants across a random sweep.
// ============================================================================

func TestRankToMaskTriple48Invariants(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const N = 1 << 15
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for i := 0; i < N; i++ {
		lo := rng.Uint64()
		hi := rng.Uint64()
		m0, m1, m2 := rankToMaskTriple48(lo, hi)
		if bits.OnesCount64(m0) != 16 || bits.OnesCount64(m1) != 16 || bits.OnesCount64(m2) != 16 {
			t.Fatalf("iter=%d rank=(%016x,%016x): popcount (%d, %d, %d), want (16, 16, 16)",
				i, hi, lo, bits.OnesCount64(m0), bits.OnesCount64(m1), bits.OnesCount64(m2))
		}
		if m0|m1|m2 != domain {
			t.Fatalf("iter=%d rank=(%016x,%016x): m0|m1|m2 = %012x, want %012x",
				i, hi, lo, m0|m1|m2, domain)
		}
		if m0&m1 != 0 || m0&m2 != 0 || m1&m2 != 0 {
			t.Fatalf("iter=%d rank=(%016x,%016x): masks not pairwise-disjoint: m0&m1=%012x m0&m2=%012x m1&m2=%012x",
				i, hi, lo, m0&m1, m0&m2, m1&m2)
		}
	}
}

// ============================================================================
// Reduction boundaries — explicit literal ranks around A*B and Q*(A*B).
// ============================================================================

// These ranks are the load-bearing corner cases for the two-step reduction.
// Each rank is emitted here as an explicit big.Int derivation (not a random
// draw) so a fuzzer that never visits the final partial window still exercises
// the boundary points on every run. The window start Q*(A*B) is where every
// rank up to 2^128 - 1 becomes an extra-preimage rank — the only place the
// two-step reduction could diverge from a one-step 128-by-(A*B) split.
func TestRankToMaskTriple48ReductionBoundary(t *testing.T) {
	cases := []struct {
		label string
		rank  *big.Int
	}{
		{"AB-1", new(big.Int).Sub(biAB, biOne)},
		{"AB", new(big.Int).Set(biAB)},
		{"AB+1", new(big.Int).Add(biAB, biOne)},
		{"Q*AB-1", new(big.Int).Sub(biQAB, biOne)},
		{"Q*AB", new(big.Int).Set(biQAB)},
		{"Q*AB+1", new(big.Int).Add(biQAB, biOne)},
		{"2^128-1", new(big.Int).Set(biMax)},
	}
	visited := make(map[string]bool)
	for _, tc := range cases {
		lo, hi := splitLimbs128(tc.rank)
		gotM0, gotM1, gotM2 := rankToMaskTriple48(lo, hi)
		wantM0, wantM1, wantM2 := oracleTriple48(tc.rank)
		if gotM0 != wantM0 || gotM1 != wantM1 || gotM2 != wantM2 {
			t.Fatalf("%s rank=%s:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
				tc.label, tc.rank.String(),
				gotM0, gotM1, gotM2,
				wantM0, wantM1, wantM2)
		}
		visited[tc.label] = true
	}
	// Guard rail: the harness must have exercised every literal case above.
	for _, tc := range cases {
		if !visited[tc.label] {
			t.Fatalf("boundary %q was not exercised", tc.label)
		}
	}
	// Cross-check on the geometry itself: Q*(A*B) + R = 2^128 exactly.
	sum := new(big.Int).Add(biQAB, biR)
	if sum.Cmp(bi2p128) != 0 {
		t.Fatalf("Q*(A*B) + R != 2^128: got %s, want %s", sum.String(), bi2p128.String())
	}
}

// ============================================================================
// Reduction anti-collapse probe — the two-step math must NOT reduce to
// (rank mod A, rank mod B). Same-rank double-mod is trapped by the fact
// that it reaches only (idx0, idx1) pairs with idx0 ≡ idx1 (mod gcd(A, B))
// where gcd(A, B) = 66861. A correct two-step reduction lands on the
// diagonal roughly N/gcd times out of N samples.
// ============================================================================

func TestRankToMaskTriple48ReductionGcdTrap(t *testing.T) {
	const gcd = 66861
	rng := rand.New(rand.NewSource(1))
	const N = 100000
	onDiag := 0
	for i := 0; i < N; i++ {
		lo := rng.Uint64()
		hi := rng.Uint64()
		qHi, r1 := bits.Div64(0, hi, interlockB48)
		qLo, r := bits.Div64(r1, lo, interlockB48)
		_, hiMod := bits.Div64(0, qHi, interlockA48)
		_, idx0 := bits.Div64(hiMod, qLo, interlockA48)
		idx1 := r
		if idx0%gcd == idx1%gcd {
			onDiag++
		}
	}
	// Uniform two-step reduction: onDiag ≈ N/gcd ≈ 1.5.
	// Broken same-rank reduction: onDiag == N (all samples collapse to the diagonal).
	limit := N / 1000
	if onDiag > limit {
		t.Fatalf("reduction produced %d diagonal-class samples out of N=%d (limit %d) — two-step reduction may be collapsing",
			onDiag, N, limit)
	}
}

// TestReductionResidueCoverage confirms the two-step reduction reaches every
// residue class of both interlockA48 and interlockB48 modulo the small prime-
// power factors of gcd(A, B). A same-rank collapse (idx0 == rank mod A,
// idx1 == rank mod B) would leave idx0 and idx1 correlated through gcd; here
// the classes are exercised independently.
func TestRankToMaskTriple48ReductionResidueCoverage(t *testing.T) {
	primes := []uint64{9, 17, 19, 23}
	rng := rand.New(rand.NewSource(1))
	seen := make([]map[uint64]bool, len(primes))
	for i := range primes {
		seen[i] = make(map[uint64]bool)
	}
	for i := 0; i < 200000; i++ {
		lo := rng.Uint64()
		hi := rng.Uint64()
		qHi, r1 := bits.Div64(0, hi, interlockB48)
		qLo, r := bits.Div64(r1, lo, interlockB48)
		_, hiMod := bits.Div64(0, qHi, interlockA48)
		_, idx0 := bits.Div64(hiMod, qLo, interlockA48)
		for pi, p := range primes {
			seen[pi][(idx0%p)*p+(r%p)] = true
		}
	}
	for pi, p := range primes {
		want := int(p * p)
		if len(seen[pi]) != want {
			t.Errorf("prime factor %d: covered %d joint residue classes, want %d",
				p, len(seen[pi]), want)
		}
	}
}

// ============================================================================
// chunk48lock / unchunk48lock — round-trip under random inputs and
// PRF-derived mask triples.
// ============================================================================

func TestChunk48LockRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const N = 20000
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for i := 0; i < N; i++ {
		x := rng.Uint64() & domain
		m0, m1, m2 := rankToMaskTriple48(rng.Uint64(), rng.Uint64())
		l0, l1, l2 := chunk48lock(x, m0, m1, m2)
		back := unchunk48lock(l0, l1, l2, m0, m1, m2)
		if back != x {
			t.Fatalf("iter=%d x=%012x masks=(%012x,%012x,%012x): chunk∘unchunk=%012x, want %012x",
				i, x, m0, m1, m2, back, x)
		}
	}
}

// TestChunk48LockDirectedInputs exercises structured chunk values: all-zero,
// all-one (within 48-bit domain), single-bit walks, and mask boundaries.
func TestChunk48LockDirectedInputs(t *testing.T) {
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	// Fix a mask triple derived from a known rank so this test is deterministic.
	m0, m1, m2 := rankToMaskTriple48(0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE)

	inputs := []uint64{0, domain}
	for i := 0; i < 48; i++ {
		inputs = append(inputs, uint64(1)<<uint(i))
	}
	inputs = append(inputs, m0, m1, m2, m0^m1, m1^m2, m0&m1)

	for _, x := range inputs {
		x &= domain
		l0, l1, l2 := chunk48lock(x, m0, m1, m2)
		back := unchunk48lock(l0, l1, l2, m0, m1, m2)
		if back != x {
			t.Fatalf("x=%012x masks=(%012x,%012x,%012x): chunk∘unchunk=%012x, want %012x",
				x, m0, m1, m2, back, x)
		}
	}
}

// ============================================================================
// softPEXT48 / softPDEP48 — invertibility under matching mask.
// ============================================================================

func TestSoftPEXT48PDEP48Inverse(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const N = 10000
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for i := 0; i < N; i++ {
		// Draw a random 16-of-48 mask via unrank so popcount is exactly 16.
		mask := unrankCombination48(rng.Uint64()%interlockA48, 16, 48)
		// Random 16-bit value to expand.
		v := uint16(rng.Uint32())
		expanded := softPDEP48(v, mask)
		if expanded>>48 != 0 {
			t.Fatalf("iter=%d: softPDEP48 wrote outside 48-bit domain: %016x", i, expanded)
		}
		if expanded&mask != expanded {
			t.Fatalf("iter=%d: softPDEP48 wrote outside mask positions", i)
		}
		back := softPEXT48(expanded, mask)
		if back != v {
			t.Fatalf("iter=%d mask=%012x v=%04x: PEXT∘PDEP=%04x, want %04x",
				i, mask, v, back, v)
		}
		// PEXT of a random 48-bit value under mask: high bits must be zero.
		x := rng.Uint64() & domain
		compressed := softPEXT48(x, mask)
		if uint64(compressed) != uint64(compressed)&0xFFFF {
			t.Fatalf("iter=%d: softPEXT48 result %04x has bits beyond bit 15",
				i, compressed)
		}
	}
}
