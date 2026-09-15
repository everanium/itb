package itb

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"runtime"
	"sync"
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/forcetier"
	"github.com/everanium/itb/internal/interlock"
)

// The Interlocked Barrier's 48-bit lock path: the combinadic rank
// arithmetic, the per-chunk and batched split / interleave drivers, and
// the PRF fill ladder that keys them.
//
// The sections below move from the arithmetic outward — the big-integer
// oracles and the rank / mask invariants, the chunk48lock round trip,
// the high-level split / interleave across widths and driver paths, the
// per-chunk PRF oracle the batched production path is checked against,
// the fill-ladder knobs, and the four-lane, batch-16 and superblock
// rungs of the fill with their parity and golden pins.

// ============================================================================
// Big-integer oracles — allowed here (tests only) as ground-truth references
// against the production 64-bit-only arithmetic in interlock48.go.
// ============================================================================

var (
	biOne   = big.NewInt(1)
	biA     = new(big.Int).SetUint64(interlockA48)
	biB     = new(big.Int).SetUint64(interlockB48)
	biAB    = new(big.Int).Mul(biA, biB)
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
	src := framedSrc48{body: framed}
	M := src.chunkCount()
	p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
	splitTriple48LockedBatchInto(src, p0, p1, p2, bp, nil)
	return interleaveTriple48LockedBatch(p0, p1, p2, bp, nil)
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
		src := framedSrc48{body: framed}
		M := src.chunkCount()
		btP0, btP1, btP2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
		splitTriple48LockedBatchInto(src, btP0, btP1, btP2, batched, nil)
		if !bytes.Equal(pcP0, btP0) || !bytes.Equal(pcP1, btP1) || !bytes.Equal(pcP2, btP2) {
			t.Fatalf("size %d: factor=1 batch vs per-chunk lane bytes diverge", sz)
		}
	}
}

// TestBatchClosureLaneOracle verifies that at each width, the batched
// closure's per-lane mask output matches an independent reference
// derivation: run the cascade over the prepended lock components on the
// group buffer directly through the underlying hash, take lane pairs
// (out[2j], out[2j+1]) as chunk j's 128-bit rank, and call
// rankToMaskTriple48 on each. This anchors the closure's wiring (lane
// pair layout, group index in buf[1:9], domain tag in buf[0], the
// prepend order of the cascade) against a formula that has no
// closure-side arithmetic to hide behind.
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
			lo, hi := oracleCascade128(ns.Hash, oracleLockComps128(ns, nonce), refBuf[:])
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
			out := oracleCascade256(ns.Hash, oracleLockComps256(ns, nonce), refBuf[:])
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
			out := oracleCascade512(ns.Hash, oracleLockComps512(ns, nonce), refBuf[:])
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
// decrypt call splitTriple48LockedBatchInto / interleaveTriple48LockedBatch with
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

// oracleCascade128 is the per-chunk oracle's own cascade over the
// prepended lock components, written directly over the raw Hash arm
// (no seed-side cascade helper is used, so the oracle is independent of
// the code it checks).
func oracleCascade128(h HashFunc128, comps []uint64, buf []byte) (uint64, uint64) {
	lo, hi := h(buf, comps[0], comps[1])
	for i := 2; i < len(comps); i += 2 {
		lo, hi = h(buf, comps[i]^lo, comps[i+1]^hi)
	}
	return lo, hi
}

func oracleCascade256(h HashFunc256, comps []uint64, buf []byte) [4]uint64 {
	var seed [4]uint64
	copy(seed[:], comps[:4])
	out := h(buf, seed)
	for i := 4; i < len(comps); i += 4 {
		for j := range seed {
			seed[j] = comps[i+j] ^ out[j]
		}
		out = h(buf, seed)
	}
	return out
}

func oracleCascade512(h HashFunc512, comps []uint64, buf []byte) [8]uint64 {
	var seed [8]uint64
	copy(seed[:], comps[:8])
	out := h(buf, seed)
	for i := 8; i < len(comps); i += 8 {
		for j := range seed {
			seed[j] = comps[i+j] ^ out[j]
		}
		out = h(buf, seed)
	}
	return out
}

// oracleLockComps128 prepends the setup key K = cascade(0x04 ‖ nonce)
// over the seed's components to those components — the hot-loop
// component slice of the cascade fill.
func oracleLockComps128(lockSeed *Seed128, nonce []byte) []uint64 {
	lo, hi := oracleCascade128(lockSeed.Hash, lockSeed.Components, append([]byte{0x04}, nonce...))
	return append([]uint64{lo, hi}, lockSeed.Components...)
}

func oracleLockComps256(lockSeed *Seed256, nonce []byte) []uint64 {
	k := oracleCascade256(lockSeed.Hash, lockSeed.Components, append([]byte{0x04}, nonce...))
	return append(k[:], lockSeed.Components...)
}

func oracleLockComps512(lockSeed *Seed512, nonce []byte) []uint64 {
	k := oracleCascade512(lockSeed.Hash, lockSeed.Components, append([]byte{0x04}, nonce...))
	return append(k[:], lockSeed.Components...)
}

// buildLockPRF48_128 constructs a per-chunk lockPRF48 closure for the
// 128-bit Triple context: the cascade fill of the batched builder, one
// chunk per call. The lockSeed argument supplies BOTH the per-chunk PRF
// keying material AND the Hash function.
func buildLockPRF48_128(lockSeed *Seed128, nonce []byte) lockPRF48 {
	lockComps := oracleLockComps128(lockSeed, nonce)
	h := lockSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		lo, hi := oracleCascade128(h, lockComps, buf)
		return rankToMaskTriple48(lo, hi)
	}
}

// buildLockPRF48_256 — 256-bit counterpart of [buildLockPRF48_128].
func buildLockPRF48_256(lockSeed *Seed256, nonce []byte) lockPRF48 {
	lockComps := oracleLockComps256(lockSeed, nonce)
	h := lockSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := oracleCascade256(h, lockComps, buf)
		return rankToMaskTriple48(out[0], out[1])
	}
}

// buildLockPRF48_512 — 512-bit counterpart of [buildLockPRF48_128].
func buildLockPRF48_512(lockSeed *Seed512, nonce []byte) lockPRF48 {
	lockComps := oracleLockComps512(lockSeed, nonce)
	h := lockSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint64) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := oracleCascade512(h, lockComps, buf)
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

// ============================================================================
// Fill-ladder knobs — the rungs as the tests see them: a test that
// exercises a rung skips when a knob disarms it.
// ============================================================================

// fillBatch16Disarmed reports whether a knob leaves the batch-16 fill
// rung off: ITB_FORCE_INTERLOCK_PRF_FILL_SEQ, _X1 or _X4.
func fillBatch16Disarmed() bool {
	return forcetier.InterlockPRFFillSeq() || forcetier.InterlockPRFFillX1() || forcetier.InterlockPRFFillX4()
}

// fillBatch32Disarmed reports whether a knob leaves the batch-32 fill
// rung off: any knob of fillBatch16Disarmed or _X16.
func fillBatch32Disarmed() bool {
	return fillBatch16Disarmed() || forcetier.InterlockPRFFillX16()
}

// clearFillKnobs unsets every fill-ladder knob for the test's duration.
func clearFillKnobs(t interface{ Setenv(string, string) }) {
	for _, k := range []string{"ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "ITB_FORCE_INTERLOCK_PRF_FILL_X1", "ITB_FORCE_INTERLOCK_PRF_FILL_X4", "ITB_FORCE_INTERLOCK_PRF_FILL_X16"} {
		t.Setenv(k, "")
	}
}

// TestInterlockPRFFillSeqEnvVarToggle verifies that ITB_FORCE_INTERLOCK_PRF_FILL_SEQ
// environment variable properly toggles the batch-16 path nil/non-nil state in
// buildLockBatchPRF48_128. When SEQ=1, fillRanksSuper is nil (sequential fallback);
// when SEQ is unset, fillRanksSuper is populated (batch-16 active).
func TestInterlockPRFFillSeqEnvVarToggle(t *testing.T) {
	// Create a seed with AES-ITB-128 hash for testing
	seedKey := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	hash128, _, _ := MakeAESITB128Hash(seedKey)

	seed, err := NewSeed128(512, hash128)
	if err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}

	// Attach a batch-16 hook (the Triple pipeline attaches the real one
	// in allocOneSeed). The hook body is irrelevant here: the test
	// checks only that buildLockBatchPRF48_128 consults InterlockFillX16()
	// and gates fillRanksSuper on the env-var, so a no-op stands in for
	// the kernel dispatch.
	seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {})

	nonce := bytes.Repeat([]byte{0xAA}, 16)
	clearFillKnobs(t)

	// Test 1: SEQ=1 → fillRanksSuper must be nil (sequential path forced)
	t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "1")
	bp1 := buildLockBatchPRF48_128(seed, nonce)
	if bp1.fillRanksSuper != nil {
		t.Error("SEQ=1: fillRanksSuper should be nil, got non-nil")
	}

	// Test 2: SEQ unset → fillRanksSuper must be populated (batch-16 active)
	t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "")
	bp2 := buildLockBatchPRF48_128(seed, nonce)
	if bp2.fillRanksSuper == nil {
		t.Error("SEQ unset: fillRanksSuper should be populated, got nil")
	}

	// Test 3: Verify env-var is consulted per call (toggle again)
	t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "1")
	bp3 := buildLockBatchPRF48_128(seed, nonce)
	if bp3.fillRanksSuper != nil {
		t.Error("SEQ=1 after toggle: fillRanksSuper should be nil")
	}
}

// ============================================================================
// Four-lane fill parity — the fillRanksX4 batched PRF fill path of
// splitTriple48LockedBatchInto / interleaveTriple48LockedBatch.
// ============================================================================
//
// The x4 arm must produce lane bytes bit-identical to the scalar
// fillRanks arm on every input: the tests below run the same split with
// fillRanksX4 armed and disarmed and require byte-equal lane outputs,
// then round-trip the x4-armed encode through the x4-armed decode.
// The 256/512-bit widths use the real Areion-SoEM batched arm; the
// 128-bit width uses a synthetic 4-lane BatchHash wrapper over the
// scalar test hash, which satisfies the BatchHash parity invariant by
// construction and exercises the loop restructure on any host.

// synthBatch128 wraps a HashFunc128 into a 4-lane BatchHashFunc128 that
// trivially satisfies the parity invariant.
func synthBatch128(h HashFunc128) BatchHashFunc128 {
	return func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		var out [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane][0], out[lane][1] = h(data[lane], seeds[lane][0], seeds[lane][1])
		}
		return out
	}
}

func interlock48X4Cases(t *testing.T) []struct {
	label string
	bp    lockBatchPRF48
} {
	t.Helper()
	nonce := interlock48Nonce()

	ns128, err := NewSeed128(512, sipHash128)
	if err != nil {
		t.Fatal(err)
	}
	ns128.BatchHash = synthBatch128(sipHash128)

	h256, b256, _ := MakeAreionSoEM256Hash()
	ns256, err := NewSeed256(512, h256)
	if err != nil {
		t.Fatal(err)
	}
	ns256.BatchHash = b256

	h512, b512 := makeAreionSoEM512Pair()
	ns512, err := NewSeed512(512, h512)
	if err != nil {
		t.Fatal(err)
	}
	ns512.BatchHash = b512

	return []struct {
		label string
		bp    lockBatchPRF48
	}{
		{"128-sip-synthbatch", buildLockBatchPRF48_128(ns128, nonce)},
		{"256-areion", buildLockBatchPRF48_256(ns256, nonce)},
		{"512-areion", buildLockBatchPRF48_512(ns512, nonce)},
	}
}

// TestFillRanksX4VsScalarParity splits identical framed inputs through
// the x4-armed and scalar-only variants of the same lockBatchPRF48 and
// requires bit-identical lane bytes at every size class.
func TestFillRanksX4VsScalarParity(t *testing.T) {
	for _, tc := range interlock48X4Cases(t) {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if tc.bp.fillRanksX4 == nil {
				t.Skip("BatchHash arm unavailable on this host/build — fillRanksX4 not armed")
			}
			scalar := tc.bp
			scalar.fillRanksX4 = nil
			for _, sz := range interlock48Sizes {
				framed := interlock48RandomBytes(sz)
				src := framedSrc48{body: framed}
				M := src.chunkCount()
				x0, x1, x2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
				s0, s1, s2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
				splitTriple48LockedBatchInto(src, x0, x1, x2, tc.bp, nil)
				splitTriple48LockedBatchInto(src, s0, s1, s2, scalar, nil)
				if !bytes.Equal(x0, s0) || !bytes.Equal(x1, s1) || !bytes.Equal(x2, s2) {
					t.Fatalf("size %d: x4 lanes diverge from scalar lanes", sz)
				}
			}
		})
	}
}

// TestFillRanksX4RoundTrip encodes with the x4-armed closure and
// decodes with the same closure, requiring exact recovery of the
// framed input (modulo the 6-byte zero padding the encoder added).
func TestFillRanksX4RoundTrip(t *testing.T) {
	for _, tc := range interlock48X4Cases(t) {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if tc.bp.fillRanksX4 == nil {
				t.Skip("BatchHash arm unavailable on this host/build — fillRanksX4 not armed")
			}
			for _, sz := range interlock48Sizes {
				framed := interlock48RandomBytes(sz)
				src := framedSrc48{body: framed}
				M := src.chunkCount()
				p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
				splitTriple48LockedBatchInto(src, p0, p1, p2, tc.bp, nil)
				got := interleaveTriple48LockedBatch(p0, p1, p2, tc.bp, nil)
				if len(got) < len(framed) {
					t.Fatalf("size %d: recovered %d bytes < input %d", sz, len(got), len(framed))
				}
				if !bytes.Equal(got[:len(framed)], framed) {
					t.Fatalf("size %d: round-trip mismatch", sz)
				}
				for i := len(framed); i < len(got); i++ {
					if got[i] != 0 {
						t.Fatalf("size %d: non-zero padding byte at %d", sz, i)
					}
				}
			}
		})
	}
}

// ============================================================================
// Batch-16 fill parity — the batch-16 ≡ sequential PRF fill invariant of
// the Interlocked Barrier.
// ============================================================================
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
// test is skipped when a fill-ladder knob disarms it.
func x16LockSeedCases(t *testing.T) []struct {
	label string
	bp    lockBatchPRF48
} {
	t.Helper()
	if fillBatch16Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-16 hook")
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

// ============================================================================
// Superblock parity + golden lane digests for the batched 48-bit lock path.
// ============================================================================
//
// The production worker loops in splitTriple48LockedBatchInto /
// interleaveTriple48LockedBatch accumulate the 128-bit rank pairs of up
// to superChunks48 chunks and derive their mask triples in one
// fillLockMasksTriple48Super pass. The mask derivation is a pure
// function of each chunk's rank pair, so the lane bytes must be
// bit-identical to a sequential per-group derivation through bp.fill.
// Two independent anchors enforce that:
//
//  1. refSplitPerGroup48 / refInterleavePerGroup48 — sequential
//     single-threaded references driven by bp.fill (one mask-derivation
//     pass per PRF group), compared byte-for-byte against the parallel
//     superblock production kernels across M values that cross every
//     superblock boundary at every width factor.
//  2. Golden SHA-256 digests of the lane bytes under fixed seed
//     components, fixed nonce, and fixed data — locking the overlay's
//     wire contribution against any derivation-order or kernel change.

// refSplitPerGroup48 is the sequential per-group reference for
// [splitTriple48LockedBatchInto]: identical padding, group indexing, and
// lane serialisation, with one bp.fill mask-derivation per group and no
// superblock accumulation and no parallelism.
func refSplitPerGroup48(data []byte, bp lockBatchPRF48) (p0, p1, p2 []byte) {
	L := len(data)
	LPad := ((L + 5) / 6) * 6
	padded := make([]byte, LPad)
	copy(padded, data)
	M := LPad / 6

	p0 = make([]byte, 2*M)
	p1 = make([]byte, 2*M)
	p2 = make([]byte, 2*M)

	factor := bp.factor
	numGroups := (M + factor - 1) / factor
	var buf [13]byte
	var masks [lockBatchFactor48Max][3]uint64
	for g := 0; g < numGroups; g++ {
		bp.fill(buf[:], uint64(g), &masks)
		for j := 0; j < factor; j++ {
			k := g*factor + j
			if k >= M {
				break
			}
			m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
			x := readChunk48(padded, 6*k)
			l0, l1, l2 := chunk48lock(x, m0, m1, m2)
			p0[2*k] = byte(l0)
			p0[2*k+1] = byte(l0 >> 8)
			p1[2*k] = byte(l1)
			p1[2*k+1] = byte(l1 >> 8)
			p2[2*k] = byte(l2)
			p2[2*k+1] = byte(l2 >> 8)
		}
	}
	return
}

// refInterleavePerGroup48 is the sequential per-group reference for
// [interleaveTriple48LockedBatch].
func refInterleavePerGroup48(p0, p1, p2 []byte, bp lockBatchPRF48) []byte {
	M := len(p0) / 2
	result := make([]byte, M*6)

	factor := bp.factor
	numGroups := (M + factor - 1) / factor
	var buf [13]byte
	var masks [lockBatchFactor48Max][3]uint64
	for g := 0; g < numGroups; g++ {
		bp.fill(buf[:], uint64(g), &masks)
		for j := 0; j < factor; j++ {
			k := g*factor + j
			if k >= M {
				break
			}
			m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
			l0 := uint16(p0[2*k]) | uint16(p0[2*k+1])<<8
			l1 := uint16(p1[2*k]) | uint16(p1[2*k+1])<<8
			l2 := uint16(p2[2*k]) | uint16(p2[2*k+1])<<8
			x := unchunk48lock(l0, l1, l2, m0, m1, m2)
			writeChunk48(result, 6*k, x)
		}
	}
	return result
}

// superTestFixedData returns n deterministic bytes for the parity and
// golden fixtures (no RNG — the fixtures must be reproducible across
// runs and trees).
func superTestFixedData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}

// superTestNonce is the fixed nonce shared by the parity and golden
// fixtures in this file.
var superTestNonce = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

// superTestComponents is the fixed 8-component seed material shared by
// the parity and golden fixtures in this file.
var superTestComponents = []uint64{
	0xc07724706ed0758b, 0x0489964ee29ad754,
	0x97819a4b77e0fd0a, 0xd9b9322f08f9eb5c,
	0x9d8dc0b866e92b87, 0xaf7f4a99914da68b,
	0x51101868dab807ae, 0xbc6e07a2a5067689,
}

// superTestBuilders returns one deterministic lockBatchPRF48 per hash
// width (factor 1 / 2 / 4), all keyed from the same fixed components
// and fixed nonce.
func superTestBuilders(t *testing.T) []struct {
	label string
	bp    lockBatchPRF48
} {
	t.Helper()
	ls128, err := SeedFromComponents128(sipHash128, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	ls256, err := SeedFromComponents256(testHash256, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	ls512, err := SeedFromComponents512(testHash512, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	return []struct {
		label string
		bp    lockBatchPRF48
	}{
		{"128-factor1", buildLockBatchPRF48_128(ls128, superTestNonce)},
		{"256-factor2", buildLockBatchPRF48_256(ls256, superTestNonce)},
		{"512-factor4", buildLockBatchPRF48_512(ls512, superTestNonce)},
	}
}

// TestSuperblockVsPerGroupParity asserts that the superblock production
// kernels produce lane bytes bit-identical to the sequential per-group
// bp.fill reference at every width factor, across M values that cross
// the superblock boundary (multiples of superChunks48 and their
// neighbours), short tails at every factor residue, and worker-range
// splits from the parallel dispatch.
func TestSuperblockVsPerGroupParity(t *testing.T) {
	// M values crossing every superblock / factor / worker boundary of
	// interest; sizes exercise both 6-aligned and padded framed lengths.
	mValues := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 23, 24, 25, 31, 32, 33, 40, 64, 65, 100, 257}
	for _, wc := range superTestBuilders(t) {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for _, m := range mValues {
				for _, sz := range []int{6 * m, 6*m - 3} {
					if sz <= 0 {
						continue
					}
					framed := superTestFixedData(sz)

					refP0, refP1, refP2 := refSplitPerGroup48(framed, wc.bp)
					src := framedSrc48{body: framed}
					M := src.chunkCount()
					gotP0, gotP1, gotP2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
					splitTriple48LockedBatchInto(src, gotP0, gotP1, gotP2, wc.bp, nil)
					if !bytes.Equal(refP0, gotP0) || !bytes.Equal(refP1, gotP1) || !bytes.Equal(refP2, gotP2) {
						t.Fatalf("M=%d size=%d: superblock split lane bytes diverge from per-group reference", m, sz)
					}

					refOut := refInterleavePerGroup48(refP0, refP1, refP2, wc.bp)
					gotOut := interleaveTriple48LockedBatch(gotP0, gotP1, gotP2, wc.bp, nil)
					if !bytes.Equal(refOut, gotOut) {
						t.Fatalf("M=%d size=%d: superblock interleave diverges from per-group reference", m, sz)
					}
					if !bytes.Equal(gotOut[:sz], framed) {
						t.Fatalf("M=%d size=%d: round-trip mismatch", m, sz)
					}
				}
			}
		})
	}
}

// TestInterlock48LockedLaneGolden locks the batched lock split's lane
// bytes to fixed SHA-256 digests under fixed seed components, fixed
// nonce, and fixed data. Any change to the mask derivation, PRF group
// indexing, chunk packing, or lane serialisation — including asm-kernel
// and derivation-order changes — breaks these digests. The interleave
// of the same lanes must also round-trip to the input.
func TestInterlock48LockedLaneGolden(t *testing.T) {
	golden := map[string]map[int]string{
		"128-factor1": {
			144:  "d73a343a6ed9b92f35677afe98ede3a00b98b08ec284a7ba0d91c756be07a07b",
			1000: "af8ff890ace80cb334a736c4a89da102139b0652aac6c4c5a96a174c862390d0",
		},
		"256-factor2": {
			144:  "233f41c8911a60f8a18dad4aace7e762b16905c37ccfa48ce3873324554959b9",
			1000: "81af7eec8de327ea762506ffb82ec271e4a01583d2d01574f1c662b76d0f8290",
		},
		"512-factor4": {
			144:  "9f8533db28e32bd292b57e4eb047325227c32a800f2b6078372e96db3bfa811c",
			1000: "d38d2f1ba459d4f6124f89075bbcc282c9319c8c7968186632ef63c238200285",
		},
	}
	for _, wc := range superTestBuilders(t) {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for sz, want := range golden[wc.label] {
				framed := superTestFixedData(sz)
				src := framedSrc48{body: framed}
				M := src.chunkCount()
				p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
				splitTriple48LockedBatchInto(src, p0, p1, p2, wc.bp, nil)
				h := sha256.New()
				h.Write(p0)
				h.Write(p1)
				h.Write(p2)
				got := hex.EncodeToString(h.Sum(nil))
				if got != want {
					t.Fatalf("size=%d: lane digest %s, want %s", sz, got, want)
				}
				out := interleaveTriple48LockedBatch(p0, p1, p2, wc.bp, nil)
				if !bytes.Equal(out[:sz], framed) {
					t.Fatalf("size=%d: golden lanes do not round-trip", sz)
				}
			}
		})
	}
}
