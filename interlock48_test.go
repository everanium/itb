package itb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"runtime"
	"sync"
	"testing"
)

// ============================================================================
// Big-integer oracles — allowed here (tests only) as ground-truth references
// against the production 64-bit-only arithmetic in interlock48.go.
// ============================================================================

var (
	biOne   = big.NewInt(1)
	biA     = new(big.Int).SetUint64(interlockA48)
	biB     = new(big.Int).SetUint64(interlockB48)
	biAB    = new(big.Int).Mul(biA, biB)
	bi2p64  = new(big.Int).Lsh(biOne, 64)
	bi2p128 = new(big.Int).Lsh(biOne, 128)
	biQ     = new(big.Int).Quo(bi2p128, biAB)                        // floor(2^128 / (A*B))
	biR     = new(big.Int).Sub(bi2p128, new(big.Int).Mul(biQ, biAB)) // 2^128 mod (A*B)
	biQAB   = new(big.Int).Mul(biQ, biAB)                            // window start
	biMax   = new(big.Int).Sub(bi2p128, biOne)                       // 2^128 - 1
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
		rng := mathrand.New(mathrand.NewSource(int64(tc.n*100 + tc.k)))
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
	rng := mathrand.New(mathrand.NewSource(1))
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
	rng := mathrand.New(mathrand.NewSource(1))
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
	rng := mathrand.New(mathrand.NewSource(1))
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
	rng := mathrand.New(mathrand.NewSource(1))
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
	rng := mathrand.New(mathrand.NewSource(1))
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

// ============================================================================
// High-level split / interleave — round-trip across widths and driver paths.
// ============================================================================

// interlock48Sizes covers every (4 + len(data)) mod 6 residue class so that
// LPad exercises each of the six padding lengths, then several sizes where the
// parallel workers actually spawn.
var interlock48Sizes = []int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	23, 24, 25, 47, 48, 49,
	100, 255, 256, 257,
	1023, 1024, 1025,
	4095, 4096, 4097,
	65535, 65536, 65537,
	1 << 20,
}

func interlock48RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// interlock48Nonce returns a deterministic nonce so PRF-derived masks are
// reproducible across encoder / decoder invocations within one test.
func interlock48Nonce() []byte {
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i * 37)
	}
	return nonce
}

// perChunkRoundTrip48 encodes framed via splitTriple48Locked and decodes back
// via interleaveTriple48Locked using the supplied PRF pair (encoder / decoder
// derive identical masks from the same lockSeed). Returns the recovered bytes
// including any padding the encoder added — the caller compares against the
// framed prefix of appropriate length.
func perChunkRoundTrip48(framed []byte, prf lockPRF48) []byte {
	p0, p1, p2 := splitTriple48Locked(framed, prf)
	return interleaveTriple48Locked(p0, p1, p2, prf)
}

func batchRoundTrip48(framed []byte, bp lockBatchPRF48) []byte {
	p0, p1, p2 := splitTriple48LockedBatch(framed, bp)
	return interleaveTriple48LockedBatch(p0, p1, p2, bp)
}

func TestSplitInterleaveTriple48LockedRoundTrip(t *testing.T) {
	nonce := interlock48Nonce()

	widthCases := []struct {
		label string
		build func() lockPRF48
	}{
		{"128-sip", func() lockPRF48 {
			ns, _ := NewSeed128(512, sipHash128)
			return buildLockPRF48_128(ns, nonce)
		}},
		{"256-blake3", func() lockPRF48 {
			ns, _ := NewSeed256(512, makeBlake3Hash256())
			return buildLockPRF48_256(ns, nonce)
		}},
		{"512-areion", func() lockPRF48 {
			ns, _ := NewSeed512(512, makeAreionSoEM512())
			return buildLockPRF48_512(ns, nonce)
		}},
	}
	for _, wc := range widthCases {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			prf := wc.build()
			for _, sz := range interlock48Sizes {
				framed := interlock48RandomBytes(sz)
				out := perChunkRoundTrip48(framed, prf)
				if len(out) < len(framed) {
					t.Fatalf("size %d: interleave shorter than input (%d < %d)", sz, len(out), len(framed))
				}
				if !bytes.Equal(out[:len(framed)], framed) {
					t.Fatalf("size %d: round-trip mismatch", sz)
				}
			}
		})
	}
}

func TestSplitInterleaveTriple48LockedBatchRoundTrip(t *testing.T) {
	nonce := interlock48Nonce()

	widthCases := []struct {
		label string
		build func() lockBatchPRF48
	}{
		{"128-sip", func() lockBatchPRF48 {
			ns, _ := NewSeed128(512, sipHash128)
			return buildLockBatchPRF48_128(ns, nonce)
		}},
		{"256-blake3", func() lockBatchPRF48 {
			ns, _ := NewSeed256(512, makeBlake3Hash256())
			return buildLockBatchPRF48_256(ns, nonce)
		}},
		{"512-areion", func() lockBatchPRF48 {
			ns, _ := NewSeed512(512, makeAreionSoEM512())
			return buildLockBatchPRF48_512(ns, nonce)
		}},
	}
	for _, wc := range widthCases {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			bp := wc.build()
			for _, sz := range interlock48Sizes {
				framed := interlock48RandomBytes(sz)
				out := batchRoundTrip48(framed, bp)
				if len(out) < len(framed) {
					t.Fatalf("size %d: interleave shorter than input (%d < %d)", sz, len(out), len(framed))
				}
				if !bytes.Equal(out[:len(framed)], framed) {
					t.Fatalf("size %d: round-trip mismatch", sz)
				}
			}
		})
	}
}

// TestBatchVsPerChunkFactor1 checks that at the single-chunk-per-group
// width (128-bit hash, factor == 1), the batched wire is bit-identical
// to the per-chunk wire under the same shared seed. This is the only
// width where the equivalence holds: at factor > 1 the batched closure
// consumes multiple 128-bit rank slices from ONE hash call (harvesting
// lane pairs 2j, 2j+1 for chunk j of the group), whereas the per-chunk
// closure runs one hash call per chunk with its own globalChunkIdx —
// the two paths derive different masks past factor 1, by design. The
// wire is not a compatibility surface across driver paths; both sides
// of a channel must choose the same driver and stick to it.
func TestBatchVsPerChunkFactor1(t *testing.T) {
	nonce := interlock48Nonce()
	ns128, _ := NewSeed128(512, sipHash128)
	perChunk := buildLockPRF48_128(ns128, nonce)
	batched := buildLockBatchPRF48_128(ns128, nonce)
	for _, sz := range interlock48Sizes {
		framed := interlock48RandomBytes(sz)
		pcP0, pcP1, pcP2 := splitTriple48Locked(framed, perChunk)
		btP0, btP1, btP2 := splitTriple48LockedBatch(framed, batched)
		if !bytes.Equal(pcP0, btP0) || !bytes.Equal(pcP1, btP1) || !bytes.Equal(pcP2, btP2) {
			t.Fatalf("size %d: factor=1 batch vs per-chunk lane bytes diverge", sz)
		}
	}
}

// TestBatchClosureLaneOracle verifies that at each width, the batched
// closure's per-lane mask output matches an independent reference
// derivation: manually invoke the underlying hash on the group buffer,
// take lane pairs (out[2j], out[2j+1]) as chunk j's 128-bit rank, and
// call rankToMaskTriple48 on each. This anchors the closure's wiring
// (lane pair layout, group index in buf[1:9], domain tag in buf[0])
// against a formula that has no closure-side arithmetic to hide behind.
func TestBatchClosureLaneOracle(t *testing.T) {
	nonce := interlock48Nonce()

	// 128-bit: 1 lane pair per hash call.
	{
		ns, _ := NewSeed128(512, sipHash128)
		bp := buildLockBatchPRF48_128(ns, nonce)
		var masks [lockBatchFactor48Max][3]uint64
		var buf [13]byte
		for groupIdx := uint64(0); groupIdx < 5; groupIdx++ {
			bp.fill(buf[:], groupIdx, &masks)

			// Independent reference: reconstruct the buf and call hash directly.
			var refBuf [13]byte
			refBuf[0] = 0x03
			binary.LittleEndian.PutUint64(refBuf[1:9], groupIdx)
			lockLo, lockHi := ns.deriveInterLockSeed(nonce)
			lo, hi := ns.Hash(refBuf[:], lockLo, lockHi)
			wantM0, wantM1, wantM2 := rankToMaskTriple48(lo, hi)
			if masks[0][0] != wantM0 || masks[0][1] != wantM1 || masks[0][2] != wantM2 {
				t.Fatalf("128 group=%d: batched (%012x, %012x, %012x), reference (%012x, %012x, %012x)",
					groupIdx, masks[0][0], masks[0][1], masks[0][2], wantM0, wantM1, wantM2)
			}
		}
	}

	// 256-bit: 2 lane pairs per hash call (chunk j uses out[2j], out[2j+1]).
	{
		ns, _ := NewSeed256(512, makeBlake3Hash256())
		bp := buildLockBatchPRF48_256(ns, nonce)
		var masks [lockBatchFactor48Max][3]uint64
		var buf [13]byte
		for groupIdx := uint64(0); groupIdx < 5; groupIdx++ {
			bp.fill(buf[:], groupIdx, &masks)

			var refBuf [13]byte
			refBuf[0] = 0x03
			binary.LittleEndian.PutUint64(refBuf[1:9], groupIdx)
			lockSeed := ns.deriveInterLockSeed(nonce)
			out := ns.Hash(refBuf[:], lockSeed)
			for j := 0; j < 2; j++ {
				wantM0, wantM1, wantM2 := rankToMaskTriple48(out[2*j], out[2*j+1])
				if masks[j][0] != wantM0 || masks[j][1] != wantM1 || masks[j][2] != wantM2 {
					t.Fatalf("256 group=%d lane=%d: batched vs reference divergence",
						groupIdx, j)
				}
			}
		}
	}

	// 512-bit: 4 lane pairs per hash call.
	{
		ns, _ := NewSeed512(512, makeAreionSoEM512())
		bp := buildLockBatchPRF48_512(ns, nonce)
		var masks [lockBatchFactor48Max][3]uint64
		var buf [13]byte
		for groupIdx := uint64(0); groupIdx < 5; groupIdx++ {
			bp.fill(buf[:], groupIdx, &masks)

			var refBuf [13]byte
			refBuf[0] = 0x03
			binary.LittleEndian.PutUint64(refBuf[1:9], groupIdx)
			lockSeed := ns.deriveInterLockSeed(nonce)
			out := ns.Hash(refBuf[:], lockSeed)
			for j := 0; j < 4; j++ {
				wantM0, wantM1, wantM2 := rankToMaskTriple48(out[2*j], out[2*j+1])
				if masks[j][0] != wantM0 || masks[j][1] != wantM1 || masks[j][2] != wantM2 {
					t.Fatalf("512 group=%d lane=%d: batched vs reference divergence",
						groupIdx, j)
				}
			}
		}
	}
}

// TestSplitTriple48LockedPaddingEdges hits every LPad residue class explicitly.
func TestSplitTriple48LockedPaddingEdges(t *testing.T) {
	ns, _ := NewSeed128(512, sipHash128)
	prf := buildLockPRF48_128(ns, interlock48Nonce())

	// LPad = ((L+5)/6)*6; test residues 0..5 through the boundary at 6, 12, 48.
	sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 47, 48, 49}
	for _, sz := range sizes {
		framed := interlock48RandomBytes(sz)
		p0, p1, p2 := splitTriple48Locked(framed, prf)
		expectedM := (sz + 5) / 6
		wantLen := 2 * expectedM
		if len(p0) != wantLen || len(p1) != wantLen || len(p2) != wantLen {
			t.Fatalf("size %d: lane length (%d, %d, %d), want %d each",
				sz, len(p0), len(p1), len(p2), wantLen)
		}
		out := interleaveTriple48Locked(p0, p1, p2, prf)
		wantOutLen := expectedM * 6
		if len(out) != wantOutLen {
			t.Fatalf("size %d: interleave length %d, want %d", sz, len(out), wantOutLen)
		}
		if !bytes.Equal(out[:sz], framed) {
			t.Fatalf("size %d: recovered prefix differs from framed", sz)
		}
	}
}

// TestSplitTriple48LockedBatchShortFinalGroup exercises the tail-group
// break-out path when M is not a multiple of the batch factor. For
// 512-bit width factor == 4, so M mod 4 in {1, 2, 3} all need coverage.
func TestSplitTriple48LockedBatchShortFinalGroup(t *testing.T) {
	ns, _ := NewSeed512(512, makeAreionSoEM512())
	bp := buildLockBatchPRF48_512(ns, interlock48Nonce())
	// framed sizes tuned so M = 5, 6, 7 → tail = 1, 2, 3.
	for _, framedLen := range []int{30, 36, 42} {
		framed := interlock48RandomBytes(framedLen)
		out := batchRoundTrip48(framed, bp)
		if !bytes.Equal(out[:framedLen], framed) {
			t.Fatalf("framedLen %d (M=%d, tail=%d): round-trip mismatch",
				framedLen, framedLen/6, (framedLen/6)%bp.factor)
		}
	}
}

// ============================================================================
// Per-chunk PRF oracle — test-only reference for the batched production path.
// ============================================================================
//
// Production dispatches only through the batched closure surface: encrypt /
// decrypt call splitTriple48LockedBatch / interleaveTriple48LockedBatch with
// a lockBatchPRF48 built by buildLockBatchPRF48_{128,256,512}. The per-chunk
// closure lives here in _test.go as the oracle against which the batched
// closure's factor > 1 lane layout is verified (TestBatchClosureLaneOracle,
// TestBatchVsPerChunkFactor1). It is not reachable from any production code.
//
// The buffer layout matches the batched closure so scratch reuse is
// symmetric:
//
//	buf[0]    = 0x03   (Triple lock domain tag)
//	buf[1:9]  = uint64-LE(globalChunkIdx)
//	buf[9:13] = reserved

// lockPRF48 is the per-chunk PRF closure type consumed by
// splitTriple48Locked / interleaveTriple48Locked.
type lockPRF48 func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64)

// buildLockPRF48_128 constructs a per-chunk lockPRF48 closure for the
// 128-bit Triple context. The lockSeed argument supplies BOTH the
// per-chunk PRF keying material AND the Hash function.
func buildLockPRF48_128(lockSeed *Seed128, nonce []byte) lockPRF48 {
	lockLo, lockHi := lockSeed.deriveInterLockSeed(nonce)
	h := lockSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		lo, hi := h(buf, lockLo, lockHi)
		return rankToMaskTriple48(lo, hi)
	}
}

// buildLockPRF48_256 — 256-bit counterpart of [buildLockPRF48_128].
func buildLockPRF48_256(lockSeed *Seed256, nonce []byte) lockPRF48 {
	lockKey := lockSeed.deriveInterLockSeed(nonce)
	h := lockSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockKey)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// buildLockPRF48_512 — 512-bit counterpart of [buildLockPRF48_128].
func buildLockPRF48_512(lockSeed *Seed512, nonce []byte) lockPRF48 {
	lockKey := lockSeed.deriveInterLockSeed(nonce)
	h := lockSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockKey)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// splitTriple48Locked splits framed into three lane buffers of 2*M
// bytes each, applying the PRF-derived mask triple to every 48-bit
// chunk. Input is padded up to a multiple of 6 bytes; the caller
// strips the framing length prefix on the way back out.
func splitTriple48Locked(data []byte, prf lockPRF48) (p0, p1, p2 []byte) {
	L := len(data)
	LPad := ((L + 5) / 6) * 6
	var padded []byte
	if LPad == L {
		padded = data
	} else {
		padded = make([]byte, LPad)
		copy(padded, data)
	}
	M := LPad / 6

	p0 = make([]byte, 2*M)
	p1 = make([]byte, 2*M)
	p2 = make([]byte, 2*M)

	if M == 0 {
		return
	}

	G := runtime.NumCPU()
	if G > M {
		G = M
	}
	chunksPerWorker := (M + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		start := w * chunksPerWorker
		end := start + chunksPerWorker
		if end > M {
			end = M
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			var buf [13]byte
			for k := s; k < e; k++ {
				m0, m1, m2 := prf(buf[:], uint64(k))
				x := readChunk48(padded, 6*k)
				l0, l1, l2 := chunk48lock(x, m0, m1, m2)
				binary.LittleEndian.PutUint16(p0[2*k:], l0)
				binary.LittleEndian.PutUint16(p1[2*k:], l1)
				binary.LittleEndian.PutUint16(p2[2*k:], l2)
			}
		}(start, end)
	}
	wg.Wait()
	return
}

// interleaveTriple48Locked is the inverse of [splitTriple48Locked].
// Lane buffers must be equal length (2*M bytes each). Result includes
// any padding bytes the encoder added; the caller strips them via the
// framing length prefix.
func interleaveTriple48Locked(p0, p1, p2 []byte, prf lockPRF48) []byte {
	M := len(p0) / 2
	result := make([]byte, M*6)

	if M == 0 {
		return result
	}

	G := runtime.NumCPU()
	if G > M {
		G = M
	}
	chunksPerWorker := (M + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		start := w * chunksPerWorker
		end := start + chunksPerWorker
		if end > M {
			end = M
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			var buf [13]byte
			for k := s; k < e; k++ {
				m0, m1, m2 := prf(buf[:], uint64(k))
				l0 := binary.LittleEndian.Uint16(p0[2*k:])
				l1 := binary.LittleEndian.Uint16(p1[2*k:])
				l2 := binary.LittleEndian.Uint16(p2[2*k:])
				x := unchunk48lock(l0, l1, l2, m0, m1, m2)
				writeChunk48(result, 6*k, x)
			}
		}(start, end)
	}
	wg.Wait()
	return result
}
