//go:build redteam

package itb

// Below-spec jokeHash adversarial re-verification for the shipped
// architecture (always-on 48-bit Interlocked Barrier + Triple Ouroboros +
// 8-seed constellation). This file is the Go landing surface for FAQ.md's
// jokeHash walkthrough (Question 1).
//
// Scope: a three-line multiply-add fold, deliberately as trivial as a
// primitive can be while still producing a per-pixel varying output. It
// stands in for the FAQ.md thought experiment "what if I plugged the
// dumbest hash imaginable into all eight seed roles". The primitive
// belongs to the T-function class (Klimov and Shamir 2002): output bit t
// depends only on input bits at position <= t, so recovery is polynomial
// per bit-plane. It is deliberately below spec, must NEVER be plugged
// into the shipped registry, and exists only to stress the construction
// with a primitive weaker than either CRC128 or FNV-1a.
//
// The probes below record what a passive observer sees on the wire when
// every one of the eight seed roles is fed by jokeHash under fresh
// nonces (shipped attacker-realism: 0/8 seeds granted, no nonce reuse):
//
//   Probe 1  Roundtrip on short and long plaintexts, plus chunk48lock
//            functionality check (18 KB plaintext).
//   Probe 2  N=500 repeat-plaintext CPA batch under fresh nonces.
//            Ciphertext-uniqueness check, per-position byte-value chi
//            square, per-bit p(bit=1) deviation histogram.
//   Probe 3  N=500 varying-plaintext batch under fresh nonces. Same
//            statistical surface; the delta between Probe 2 and Probe 3
//            is the plaintext-content-derived wire signal (0 under the
//            shipped construction).
//   Probe 4  Monobit-frequency test on the concatenated body region.
//
// Attacker-realism discipline: no probe reads any seed component, any
// nonce value, or the raw hash output. Every measurement runs on
// container bytes only, exactly what a passive observer would collect.

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"

	"github.com/dchest/siphash"
)

// jokeHash is a three-line multiply-add fold: initialise the accumulator
// from seed0, mix each data byte in via a small odd multiplier plus add.
// T-function class (Klimov and Shamir 2002): output bit t depends only
// on input bits at position <= t, so recovery is polynomial per bit
// plane. Trivially invertible for any single (data, seed) observation
// pair. Included here only to demonstrate that even a primitive this
// weak cannot produce a wire-level plaintext-recovery channel through
// the shipped barrier.
func jokeHash(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = seed0
	for _, b := range data {
		lo = lo*257 + uint64(b)
	}
	hi = ^lo
	return
}

// makeJokeSeeds constructs the eight seeds required by Encrypt3x128Cfg,
// each keyed by fresh CSPRNG components and each running the jokeHash
// primitive.
func makeJokeSeeds(t *testing.T, keyBits int) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	mk := func(role string) *Seed128 {
		s, err := NewSeed128(keyBits, jokeHash)
		if err != nil {
			t.Fatalf("NewSeed128(%s): %v", role, err)
		}
		return s
	}
	return mk("noiseSeed"), mk("lockSeed"),
		mk("dataSeed1"), mk("dataSeed2"), mk("dataSeed3"),
		mk("startSeed1"), mk("startSeed2"), mk("startSeed3")
}

// TestRedTeamJokeHashChainHashNonDegenerate confirms the multiply-add
// fold produces a per-buffer varying ChainHash output. A trivially-
// affine jokeHash (data[0] XOR seed[0]) would collapse to a per-seed
// constant under the eight-round cascade because XOR-wrap cancels data
// on every even round; the multiply-add breaks that cancellation.
// Included as a sanity check so the wire-level probes below run against
// a non-degenerate primitive.
func TestRedTeamJokeHashChainHashNonDegenerate(t *testing.T) {
	s, err := NewSeed128(1024, jokeHash)
	if err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	buffers := [][]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
		{0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99},
	}
	seen := make(map[[2]uint64]struct{}, len(buffers))
	for _, buf := range buffers {
		lo, hi := s.ChainHash128(buf)
		seen[[2]uint64{lo, hi}] = struct{}{}
		t.Logf("ChainHash128(%v) = (0x%016x, 0x%016x)", buf, lo, hi)
	}
	if len(seen) != len(buffers) {
		t.Fatalf("ChainHash cascade degenerate: %d distinct outputs across %d buffers", len(seen), len(buffers))
	}
	t.Logf("cascade non-degenerate: %d/%d distinct outputs", len(seen), len(buffers))
}

// TestRedTeamJokeHashRoundtrip confirms the shipped pipeline decrypts
// plaintext exactly under jokeHash on all eight seed roles, on both a
// short plaintext and an 18 KB plaintext that exercises chunk48lock.
func TestRedTeamJokeHashRoundtrip(t *testing.T) {
	const keyBits = 1024
	ns, ls, d1, d2, d3, s1, s2, s3 := makeJokeSeeds(t, keyBits)

	shortPT := []byte("Passive observer holding this container under jokeHash on every seed.")
	ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, shortPT)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg short: %v", err)
	}
	pt, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128Cfg short: %v", err)
	}
	if !bytes.Equal(pt, shortPT) {
		t.Fatalf("short roundtrip: mismatch\n want %q\n  got %q", shortPT, pt)
	}
	t.Logf("short roundtrip: plaintext %d bytes → ciphertext %d bytes → plaintext recovered", len(shortPT), len(ct))

	longPT := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 400)
	ctL, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, longPT)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg long: %v", err)
	}
	ptL, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, ctL)
	if err != nil {
		t.Fatalf("Decrypt3x128Cfg long: %v", err)
	}
	if !bytes.Equal(ptL, longPT) {
		t.Fatalf("long roundtrip: mismatch")
	}
	t.Logf("long roundtrip: plaintext %d bytes → ciphertext %d bytes → chunk48lock functional under jokeHash", len(longPT), len(ctL))
}

// bitStats holds per-position (per byte and per bit) counts across a
// batch of ciphertext samples.
type bitStats struct {
	N          int
	L          int
	bitCounts  []int // len = L * 8
	byteCounts [][256]int
}

func measureCiphertexts(cts [][]byte) *bitStats {
	L := len(cts[0])
	for _, c := range cts {
		if len(c) != L {
			panic("bitStats: ciphertext length varies within batch")
		}
	}
	s := &bitStats{N: len(cts), L: L, bitCounts: make([]int, L*8), byteCounts: make([][256]int, L)}
	for _, c := range cts {
		for bi := 0; bi < L; bi++ {
			b := c[bi]
			s.byteCounts[bi][b]++
			for j := 0; j < 8; j++ {
				if (b>>j)&1 == 1 {
					s.bitCounts[bi*8+j]++
				}
			}
		}
	}
	return s
}

// chiSquareAt returns the byte-value chi-square (df=255) at position pos.
func (s *bitStats) chiSquareAt(pos int) float64 {
	exp := float64(s.N) / 256.0
	chi2 := 0.0
	for _, h := range s.byteCounts[pos] {
		d := float64(h) - exp
		chi2 += d * d / exp
	}
	return chi2
}

// hotBits counts bit positions where |p(bit=1) - 0.5| exceeds threshold.
func (s *bitStats) hotBits(threshold float64) (signal, maxDevBit int, maxDev float64) {
	for i, cnt := range s.bitCounts {
		p := float64(cnt) / float64(s.N)
		dev := math.Abs(p - 0.5)
		if dev > threshold {
			signal++
		}
		if dev > maxDev {
			maxDev = dev
			maxDevBit = i
		}
	}
	return
}

// hotPerByteHistogram counts, for each byte position, how many of its
// eight bits exceed the signal threshold. Returns a 9-element histogram
// indexed by hot-bit count per byte (0..8).
func (s *bitStats) hotPerByteHistogram(threshold float64) [9]int {
	var h [9]int
	for bi := 0; bi < s.L; bi++ {
		hot := 0
		for j := 0; j < 8; j++ {
			p := float64(s.bitCounts[bi*8+j]) / float64(s.N)
			if math.Abs(p-0.5) > threshold {
				hot++
			}
		}
		h[hot]++
	}
	return h
}

// TestRedTeamJokeHashRepeatPlaintextCPA batches N encryptions of the
// same short plaintext under fresh nonces and measures the wire's
// statistical surface. Under attacker-realism (fresh nonce per call, no
// seed peek) the barrier's Part 2 absorption should keep every wire
// byte in the body region indistinguishable from a fresh CSPRNG draw
// even when every derived encoding parameter (channelXOR, noisePos,
// rotation, startPixel, mask triple) collapses to a per-session
// constant under jokeHash.
//
// Sample size N = 10000 exceeds the shipped FNV-1a-on-8-roles fresh-
// nonce CPA cell (N = 2000 per REDTEAM.md § Broken-primitive stress)
// by 5x, so the surface here is stricter than the FNV-1a arm at the
// same measurement angle and matches the fresh-nonce collision probe
// in REDTEAM.md § Wire-observable properties (N = 10000).
//
// Failure indicators recorded to t.Logf; the test fails hard only on
// pipeline failure (encrypt error, decrypt mismatch, catastrophic bit
// bias in the body region).
func TestRedTeamJokeHashRepeatPlaintextCPA(t *testing.T) {
	const (
		keyBits = 1024
		N       = 10000
	)
	ns, ls, d1, d2, d3, s1, s2, s3 := makeJokeSeeds(t, keyBits)

	plaintext := []byte("Passive observer holding this container under jokeHash on every seed.")
	cts := make([][]byte, 0, N)
	uniq := make(map[string]struct{}, N)
	for i := 0; i < N; i++ {
		c, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg[%d]: %v", i, err)
		}
		cts = append(cts, c)
		uniq[string(c)] = struct{}{}
		pt, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, c)
		if err != nil {
			t.Fatalf("Decrypt3x128Cfg[%d]: %v", i, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("repeat-plaintext roundtrip[%d]: plaintext mismatch", i)
		}
	}
	if len(uniq) != N {
		t.Fatalf("ciphertext uniqueness: %d unique across %d samples (fresh nonce not producing fresh container)", len(uniq), N)
	}
	t.Logf("repeat-plaintext N=%d: all ciphertexts unique, all roundtrips recovered", N)

	stats := measureCiphertexts(cts)

	// Byte-value chi-square at sampled positions. df=255 uniform expects
	// chi^2 ~ 255 with sigma sqrt(510) ~ 22.6, so a random draw stays
	// well under 350 with overwhelming probability.
	positions := []int{20, stats.L / 4, stats.L / 2, 3 * stats.L / 4, stats.L - 32}
	for _, pos := range positions {
		chi2 := stats.chiSquareAt(pos)
		t.Logf("chi^2 at pos=%d: %.1f (uniform expects 255 +/- 22.6, flag if >350)", pos, chi2)
		if chi2 > 500 {
			t.Errorf("chi^2 at pos=%d: %.1f exceeds heavy-bias threshold 500", pos, chi2)
		}
	}

	// Per-bit deviation: any wire bit whose fixation across N samples
	// exceeds |p - 0.5| > 0.30 is catastrophically biased. Under uniform
	// CSPRNG at N=500 this should not happen except for structural
	// metadata (W and H fields in the header, always fixed for a given
	// plaintext length regardless of primitive).
	signal, maxBit, maxDev := stats.hotBits(0.15)
	catastrophic, _, _ := stats.hotBits(0.30)
	t.Logf("per-bit deviation N=%d: |p-0.5|>0.15 → %d/%d (%.3f%%); |p-0.5|>0.30 → %d (%.3f%%); max dev %.4f at bit %d",
		N, signal, stats.L*8, 100*float64(signal)/float64(stats.L*8),
		catastrophic, 100*float64(catastrophic)/float64(stats.L*8),
		maxDev, maxBit)

	// Hot-bit-per-byte histogram: locate whether the biased bits cluster
	// per byte (hot=1..7 → per-byte body leak) or concentrate in a small
	// count of hot=8 bytes (fully-fixed metadata bytes).
	h := stats.hotPerByteHistogram(0.15)
	t.Logf("hot-bit-per-byte histogram (0..8): %d %d %d %d %d %d %d %d %d",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8])

	// Under the shipped construction the only permissible catastrophic
	// bytes are the structural metadata: 2 bytes W + 2 bytes H = 4 bytes
	// fully fixed for a given plaintext length. Body bytes must show
	// hot=0. Fail the test if any body byte exhibits any hot bits.
	bodyBytesWithHot := h[1] + h[2] + h[3] + h[4] + h[5] + h[6] + h[7]
	if bodyBytesWithHot != 0 {
		t.Errorf("body-region bit-fixation observed: %d bytes with 1..7 hot bits (expected 0 under barrier absorption)", bodyBytesWithHot)
	}
}

// TestRedTeamJokeHashVaryingPlaintextCPA batches N encryptions of
// varying plaintexts under fresh nonces. The delta between the repeat-
// plaintext catastrophic-bit count and the varying-plaintext count
// isolates the plaintext-content-derived wire signal. Under the shipped
// construction the delta is expected to be zero: the barrier absorbs
// every trace of primitive weakness before it reaches the wire.
func TestRedTeamJokeHashVaryingPlaintextCPA(t *testing.T) {
	const (
		keyBits    = 1024
		N          = 10000
		ptLen      = 64
		bodyMargin = 200 // skip header + trailing framing when measuring body monobit
	)
	ns, ls, d1, d2, d3, s1, s2, s3 := makeJokeSeeds(t, keyBits)

	cts := make([][]byte, 0, N)
	L := 0
	for i := 0; i < N; i++ {
		pt := make([]byte, ptLen)
		if _, err := rand.Read(pt); err != nil {
			t.Fatalf("crypto/rand[%d]: %v", i, err)
		}
		c, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg[%d]: %v", i, err)
		}
		pt2, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, c)
		if err != nil {
			t.Fatalf("Decrypt3x128Cfg[%d]: %v", i, err)
		}
		if !bytes.Equal(pt, pt2) {
			t.Fatalf("varying-plaintext roundtrip[%d]: mismatch", i)
		}
		cts = append(cts, c)
		if L == 0 {
			L = len(c)
		}
		if len(c) != L {
			t.Fatalf("varying-plaintext ciphertext length changed: %d vs %d at i=%d", L, len(c), i)
		}
	}
	t.Logf("varying-plaintext N=%d ptLen=%d: all roundtrips recovered, ciphertext len fixed at %d", N, ptLen, L)

	stats := measureCiphertexts(cts)
	signal, maxBit, maxDev := stats.hotBits(0.15)
	catastrophic, _, _ := stats.hotBits(0.30)
	t.Logf("per-bit deviation N=%d: |p-0.5|>0.15 → %d/%d (%.3f%%); |p-0.5|>0.30 → %d (%.3f%%); max dev %.4f at bit %d",
		N, signal, stats.L*8, 100*float64(signal)/float64(stats.L*8),
		catastrophic, 100*float64(catastrophic)/float64(stats.L*8),
		maxDev, maxBit)

	// Same body-region invariant as the repeat-plaintext test.
	h := stats.hotPerByteHistogram(0.15)
	t.Logf("hot-bit-per-byte histogram (0..8): %d %d %d %d %d %d %d %d %d",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8])
	bodyBytesWithHot := h[1] + h[2] + h[3] + h[4] + h[5] + h[6] + h[7]
	if bodyBytesWithHot != 0 {
		t.Errorf("body-region bit-fixation observed under varying plaintext: %d bytes with 1..7 hot bits", bodyBytesWithHot)
	}

	// Monobit frequency on the concatenated body region across all N
	// samples. Total bit count reaches ~ N * (L - 2*bodyMargin) * 8, so
	// at N=5000 and L~10 K the sample is ~ 380 M bits and per-bit sigma
	// is sqrt(0.25/T) ~ 2.6e-5. At that scale a 3-sigma gate is
	// stochastically reachable ~0.27% of the time under a perfect
	// CSPRNG, so 3 sigma alone would produce a spurious FAIL roughly
	// one run in 400. The gate here is 5 sigma (false-positive rate
	// ~5.7e-7), which distinguishes a real barrier leak from ordinary
	// large-sample fluctuation. The 3-sigma and 5-sigma readings are
	// both logged for transparency; the hot-bit-per-byte histogram gate
	// above is the load-bearing structural check.
	if L > 2*bodyMargin+1000 {
		total, ones := 0, 0
		for _, c := range cts {
			for _, b := range c[bodyMargin : L-bodyMargin] {
				for j := 0; j < 8; j++ {
					total++
					if (b>>j)&1 == 1 {
						ones++
					}
				}
			}
		}
		frac := float64(ones) / float64(total)
		dev := math.Abs(frac - 0.5)
		sigma := math.Sqrt(0.25 / float64(total))
		zscore := dev / sigma
		t.Logf("monobit on body region [%d..%d) across %d samples: total %d bits, p(bit=1)=%.6f, |z|=%.2f (3sigma band=%.6f, 5sigma band=%.6f)",
			bodyMargin, L-bodyMargin, N, total, frac, zscore, 3*sigma, 5*sigma)
		if zscore > 5 {
			t.Errorf("body monobit exceeds 5 sigma: p(bit=1)=%.6f, |z|=%.2f (structural signal, not stochastic noise)", frac, zscore)
		}
	}
}

// sipHash24Adapter is a HashFunc128 wrapper over dchest/siphash's
// SipHash-2-4 128-bit variant. The per-call (seed0, seed1) pair is
// the entire SipHash key, matching hashes/siphash24.go's shipped
// SipHash24 closure without a package import (this file lives in
// package itb which hashes/ imports, so hashes/ cannot be pulled in
// here). SipHash-2-4 is a designed PRF whose output is
// computationally indistinguishable from random under the standard
// PRF assumption, so it serves as the load-bearing PRF-grade control
// for the HW-distinguisher probe below.
func sipHash24Adapter(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

// fnv1a128NativeAdapter is a HashFunc128 wrapper over two independent
// FNV-1a-64 lanes: T-function class with the standard 64-bit FNV
// prime 0x100000001b3 (popcount 6). The redteam suite already carries
// a full-128-bit FNV-1a variant (fnv1a128BrokenLab in
// redteam_broken_test.go) that uses math/big for the mod-2^128
// arithmetic; that version is faithful to the archived probe but
// significantly slower than native uint64. This adapter is the
// native-speed T-function control the HW distinguisher probe below
// needs for a 2000-sample two-arm CPA without extending the test's
// runtime beyond a few seconds.
func fnv1a128NativeAdapter(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	const fnvPrime64 = 0x100000001b3
	lo, hi := seed0, seed1
	for _, b := range data {
		lo ^= uint64(b)
		lo *= fnvPrime64
		hi ^= uint64(b)
		hi *= fnvPrime64
	}
	return lo, hi
}

func makeSipHash24Seeds(t *testing.T, keyBits int) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	mk := func(role string) *Seed128 {
		s, err := NewSeed128(keyBits, sipHash24Adapter)
		if err != nil {
			t.Fatalf("NewSeed128(sipHash24, %s): %v", role, err)
		}
		return s
	}
	return mk("noiseSeed"), mk("lockSeed"),
		mk("dataSeed1"), mk("dataSeed2"), mk("dataSeed3"),
		mk("startSeed1"), mk("startSeed2"), mk("startSeed3")
}

// hwDistinguisherResult holds the per-arm metrics for one primitive.
type hwDistinguisherResult struct {
	Label       string
	ZerosPBit1  float64
	ZerosZ      float64
	RandomPBit1 float64
	RandomZ     float64
	ChiZeros    float64
	ChiRandom   float64
	ChiHomog    float64
}

// measureHWDistinguisher encrypts N ciphertexts of ptZeros and N of
// ptRand under the supplied 8 seeds, measures pooled body monobit +
// per-arm chi² against uniform + two-sample chi² homogeneity between
// the arms, and returns the metrics. Ciphertext length must be
// identical across all 2N encryptions (guaranteed by fixed ptLen).
func measureHWDistinguisher(t *testing.T, label string, ns, ls, d1, d2, d3, s1, s2, s3 *Seed128, ptZeros, ptRand []byte, N, bodyMargin int) hwDistinguisherResult {
	t.Helper()
	encryptArm := func(pt []byte, armLabel string) [][]byte {
		cts := make([][]byte, 0, N)
		for i := 0; i < N; i++ {
			c, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, pt)
			if err != nil {
				t.Fatalf("Encrypt3x128Cfg[%s/%s][%d]: %v", label, armLabel, i, err)
			}
			cts = append(cts, c)
		}
		return cts
	}
	ctsZ := encryptArm(ptZeros, "zeros")
	ctsR := encryptArm(ptRand, "random")
	L := len(ctsZ[0])
	for _, c := range append(ctsZ, ctsR...) {
		if len(c) != L {
			t.Fatalf("[%s] ciphertext length varies: got %d, expected %d", label, len(c), L)
		}
	}

	poolBits := func(cts [][]byte) (total, ones int) {
		for _, c := range cts {
			for _, b := range c[bodyMargin : L-bodyMargin] {
				total += 8
				for j := 0; j < 8; j++ {
					if (b>>j)&1 == 1 {
						ones++
					}
				}
			}
		}
		return
	}
	tZ, oZ := poolBits(ctsZ)
	tR, oR := poolBits(ctsR)
	pZ := float64(oZ) / float64(tZ)
	pR := float64(oR) / float64(tR)
	zZ := math.Abs(pZ-0.5) / math.Sqrt(0.25/float64(tZ))
	zR := math.Abs(pR-0.5) / math.Sqrt(0.25/float64(tR))

	histZ := [256]int{}
	histR := [256]int{}
	tzZ, tzR := 0, 0
	for _, c := range ctsZ {
		for _, b := range c[bodyMargin : L-bodyMargin] {
			histZ[b]++
			tzZ++
		}
	}
	for _, c := range ctsR {
		for _, b := range c[bodyMargin : L-bodyMargin] {
			histR[b]++
			tzR++
		}
	}
	chi2Uniform := func(h [256]int, total int) float64 {
		exp := float64(total) / 256.0
		c := 0.0
		for _, cnt := range h {
			d := float64(cnt) - exp
			c += d * d / exp
		}
		return c
	}
	chiZ := chi2Uniform(histZ, tzZ)
	chiR := chi2Uniform(histR, tzR)

	chiHomog := 0.0
	for i := 0; i < 256; i++ {
		colTot := histZ[i] + histR[i]
		if colTot == 0 {
			continue
		}
		eZ := float64(colTot) * float64(tzZ) / float64(tzZ+tzR)
		eR := float64(colTot) * float64(tzR) / float64(tzZ+tzR)
		if eZ > 0 {
			d := float64(histZ[i]) - eZ
			chiHomog += d * d / eZ
		}
		if eR > 0 {
			d := float64(histR[i]) - eR
			chiHomog += d * d / eR
		}
	}

	return hwDistinguisherResult{
		Label: label, ZerosPBit1: pZ, ZerosZ: zZ, RandomPBit1: pR, RandomZ: zR,
		ChiZeros: chiZ, ChiRandom: chiR, ChiHomog: chiHomog,
	}
}

// makeSeedsFor is a generic 8-seed constructor over any HashFunc128.
// Used by the HW distinguisher test to build seed constellations for
// jokeHash, CRC128, FNV-1a, and SipHash-2-4 uniformly.
func makeSeedsFor(t *testing.T, fn HashFunc128, keyBits int) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	mk := func(role string) *Seed128 {
		s, err := NewSeed128(keyBits, fn)
		if err != nil {
			t.Fatalf("NewSeed128(%s): %v", role, err)
		}
		return s
	}
	return mk("noiseSeed"), mk("lockSeed"),
		mk("dataSeed1"), mk("dataSeed2"), mk("dataSeed3"),
		mk("startSeed1"), mk("startSeed2"), mk("startSeed3")
}

// TestRedTeamJokeHashHWDistinguisherVsPRF runs a two-arm repeat-
// plaintext CPA (all-zeros vs uniform-random 4 KB plaintext, both
// encrypted N times under fresh nonces) under four W128 primitives on
// all eight seed roles:
//
//	jokeHash      — multiply-add fold, multiplier 257 (popcount 2)
//	CRC128        — GF(2)-linear (two keyed CRC64 lanes, ECMA + ISO)
//	FNV-1a        — T-function, multiplier 0x100000001b3 (popcount 6)
//	SipHash-2-4   — designed PRF (hard-gated control)
//
// Purpose. Preserve the empirical finding recorded in FAQ.md
// § Residual bias under repeat-plaintext CPA. The shipped barrier
// absorbs plaintext-content-recovery entirely (earlier tests in this
// file), and the HW distinguisher surfaces only when the primitive's
// output distribution itself carries a measurable bias — for the
// tested set only jokeHash's popcount-2 multiplier produces the
// signal; CRC128, FNV-1a, and SipHash-2-4 all show null under the
// same measurement despite CRC128 and FNV-1a being algebraically
// weak. The finding is not "any broken primitive leaks"; it is
// "a poorly-diffused primitive leaks", which is a strictly narrower
// claim.
//
// Gate strategy.
//   - jokeHash, CRC128, FNV-1a arms — log only. jokeHash is expected
//     to show the signal; CRC128 and FNV-1a are expected to be
//     within the noise floor. Hard-gating on the specific magnitude
//     would create spurious FAILs if the below-spec primitives'
//     internals drift.
//   - SipHash-2-4 arm — hard gate at |z| <= 5 per arm and homogeneity
//     chi² <= 500. A regression in the PRF-grade control would signal
//     a wire-format artefact or a barrier defect the earlier tests do
//     not catch. The gate leaves ample room for stochastic scatter.
//
// Runtime: 8 × 2000 encryptions ≈ 8-10 s.
func TestRedTeamJokeHashHWDistinguisherVsPRF(t *testing.T) {
	const (
		keyBits    = 1024
		N          = 2000
		ptLen      = 4096
		bodyMargin = 200
	)

	ptZeros := make([]byte, ptLen)
	ptRand := make([]byte, ptLen)
	if _, err := rand.Read(ptRand); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}

	logResult := func(label string, r hwDistinguisherResult) {
		t.Logf("[%s] zeros arm  p(bit=1)=%.6f |z|=%.2f  chi^2=%.2f", label, r.ZerosPBit1, r.ZerosZ, r.ChiZeros)
		t.Logf("[%s] random arm p(bit=1)=%.6f |z|=%.2f  chi^2=%.2f", label, r.RandomPBit1, r.RandomZ, r.ChiRandom)
		t.Logf("[%s] two-sample homogeneity chi^2=%.2f (df=255)", label, r.ChiHomog)
	}

	// jokeHash arm — log only, signal is expected (popcount-2 multiplier).
	{
		ns, ls, d1, d2, d3, s1, s2, s3 := makeJokeSeeds(t, keyBits)
		r := measureHWDistinguisher(t, "jokeHash", ns, ls, d1, d2, d3, s1, s2, s3, ptZeros, ptRand, N, bodyMargin)
		logResult("jokeHash", r)
		if r.ZerosZ < 3 {
			t.Logf("[jokeHash] note: zeros-arm |z|=%.2f below 3σ this run — primitive-attributable signal did not surface at this sample size (expected occasional stochastic-miss at N=%d)", r.ZerosZ, N)
		}
	}

	// CRC128 arm — log only, null expected (GF(2)-linear with dense
	// polynomial table produces uniform-distributed output under
	// random seeds).
	{
		ns, ls, d1, d2, d3, s1, s2, s3 := makeSeedsFor(t, crc128BrokenLab, keyBits)
		r := measureHWDistinguisher(t, "CRC128", ns, ls, d1, d2, d3, s1, s2, s3, ptZeros, ptRand, N, bodyMargin)
		logResult("CRC128", r)
	}

	// FNV-1a arm (native two-lane, T-function class) — log only, null
	// expected (multiplier 0x100000001b3 has popcount 6 and is prime,
	// spreading bits well enough to keep output distribution uniform
	// under random seeds).
	{
		ns, ls, d1, d2, d3, s1, s2, s3 := makeSeedsFor(t, fnv1a128NativeAdapter, keyBits)
		r := measureHWDistinguisher(t, "FNV-1a", ns, ls, d1, d2, d3, s1, s2, s3, ptZeros, ptRand, N, bodyMargin)
		logResult("FNV-1a", r)
	}

	// SipHash-2-4 arm — hard gate. PRF-grade control anchors the null
	// baseline; regression here signals barrier or wire-format defect.
	{
		ns, ls, d1, d2, d3, s1, s2, s3 := makeSipHash24Seeds(t, keyBits)
		r := measureHWDistinguisher(t, "SipHash-2-4", ns, ls, d1, d2, d3, s1, s2, s3, ptZeros, ptRand, N, bodyMargin)
		logResult("SipHash-2-4", r)

		if r.ZerosZ > 5 {
			t.Errorf("[SipHash-2-4] zeros-arm |z|=%.2f exceeds 5σ (PRF-grade arm must not distinguish plaintext HW)", r.ZerosZ)
		}
		if r.RandomZ > 5 {
			t.Errorf("[SipHash-2-4] random-arm |z|=%.2f exceeds 5σ", r.RandomZ)
		}
		if r.ChiHomog > 500 {
			t.Errorf("[SipHash-2-4] two-sample homogeneity chi^2=%.2f exceeds 500 (PRF-grade arm must not distinguish arms; uniform expects 255±22.6, 3σ band top ≈ 323)", r.ChiHomog)
		}
	}
}
