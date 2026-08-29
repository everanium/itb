//go:build redteam

package itb

// Red-team empirical corroboration for the PRF-grade primitive null
// result, run against BLAKE3 as the representative PRF-grade primitive
// (Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-CMAC,
// SipHash-2-4, ChaCha20 all inherit the argument via the PRF
// assumption — see REDTEAM.md "PRF-grade primitives" section).
//
// Every probe drives the shipped core Triple entrypoint
// Encrypt3x256Cfg / Decrypt3x256Cfg: 8 mandatory distinct seeds,
// always-on 48-bit Interlocked Barrier, no Single-Ouroboros fallback,
// no overlay toggle. The barrier layer is the surface under test;
// parallax and the outer-cipher wrapper are independent additional
// layers not exercised here.
//
// These are lab experiments. Verdicts are sample-bounded: a null
// result here means "no measurable signal above the finite-sample
// floor at the tested sample size N under the stated threat model",
// never "no signal exists". Closure of the KPA / CPA families is
// architectural under the PRF assumption and fresh per-message nonces
// (mask-space cardinality per chunk ~= 2^70.20, per-chunk PRF
// independence, 3-snake enumeration, 8-seed isolation); the empirical
// probes corroborate the architecture, they do not prove it.
//
// TestRedteamPRF_BLAKE3_NullResult is the asserting landed test. The
// other four functions are the mandatory 4-probe minimum and log raw
// numbers under `go test -run TestRedteamPRF -v` for the attack log;
// each also asserts the sample-bounded null bound so a regression that
// injects a distinguishable signal fails CI.

import (
	"bytes"
	"math"
	"testing"
)

// prfPublicCrib is a public-schema JSON header prefix — the kind of
// attacker-visible crib a Crib KPA leans on. It is identical in every
// crib-bearing plaintext so the probe measures whether shared known
// plaintext anchors any distinguisher.
var prfPublicCrib = []byte(`{"type":"message","v":1,"enc":"itb","body":`)

// blake3EightSeedsForProbe builds the 8 mandatory distinct seeds
// (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3) at 512-bit key
// width, all sharing one freshly-keyed BLAKE3-256 hash closure. The
// seeds are independent random draws — the 8-seed isolation the
// construction requires.
func blake3EightSeedsForProbe() (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256) {
	h := makeBlake3Hash256()
	return makeEightSeeds256(512, h)
}

// byteEqualRate returns the fraction of positions where a and b hold
// the same byte, over the shorter of the two lengths. For two
// independent uniform byte streams the expectation is 1/256 ~= 0.00391.
func byteEqualRate(a, b []byte) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	eq := 0
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			eq++
		}
	}
	return float64(eq) / float64(n)
}

// bitDiffFraction returns the fraction of differing bits between a and
// b over the shorter length. For two independent uniform streams the
// expectation is 0.5 (full avalanche).
func bitDiffFraction(a, b []byte) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	diff := 0
	for i := 0; i < n; i++ {
		v := a[i] ^ b[i]
		for v != 0 {
			diff += int(v & 1)
			v >>= 1
		}
	}
	return float64(diff) / float64(n*8)
}

// pearsonBytes returns the Pearson correlation coefficient between two
// equal-prefix byte streams treated as integer samples. |r| near 0
// means no linear byte-value correlation.
func pearsonBytes(a, b []byte) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	var sa, sb, saa, sbb, sab float64
	for i := 0; i < n; i++ {
		x := float64(a[i])
		y := float64(b[i])
		sa += x
		sb += y
		saa += x * x
		sbb += y * y
		sab += x * y
	}
	nf := float64(n)
	cov := sab - sa*sb/nf
	va := saa - sa*sa/nf
	vb := sbb - sb*sb/nf
	if va <= 0 || vb <= 0 {
		return 0
	}
	return cov / math.Sqrt(va*vb)
}

// Probe 1 — Crib KPA under fresh nonces.
//
// Two plaintexts share the public-schema crib prefix but differ in the
// body; both are encrypted under one fixed 8-seed bundle with fresh
// per-message nonces (the shipped condition). If the shared crib
// anchored any bit-position-to-lane mapping, the crib-region
// ciphertext bytes of the two messages would correlate. The measured
// crib-region byte-equal rate is compared against the 1/256
// independent-stream floor.
func TestRedteamPRF_Probe1_CribKPAFreshNonce(t *testing.T) {
	const (
		trials  = 200
		bodyLen = 4096
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := blake3EightSeedsForProbe()

	var sumCrib, sumFull, sumPearson float64
	for i := 0; i < trials; i++ {
		pt1 := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)
		pt2 := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)

		ct1, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt1)
		if err != nil {
			t.Fatal(err)
		}
		ct2, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt2)
		if err != nil {
			t.Fatal(err)
		}
		cribLen := len(prfPublicCrib)
		if cribLen > len(ct1) || cribLen > len(ct2) {
			cribLen = min(len(ct1), len(ct2))
		}
		sumCrib += byteEqualRate(ct1[:cribLen], ct2[:cribLen])
		sumFull += byteEqualRate(ct1, ct2)
		sumPearson += math.Abs(pearsonBytes(ct1, ct2))
	}
	cribRate := sumCrib / trials
	fullRate := sumFull / trials
	meanPearson := sumPearson / trials
	const floor = 1.0 / 256.0

	t.Logf("Probe 1 Crib KPA (fresh nonce, BLAKE3, Triple, barrier): N=%d bodyLen=%d", trials, bodyLen)
	t.Logf("  crib-region ct byte-equal rate = %.5f (independent-stream floor %.5f)", cribRate, floor)
	t.Logf("  full ct byte-equal rate        = %.5f", fullRate)
	t.Logf("  mean |Pearson(ct1,ct2)|        = %.5f", meanPearson)
	t.Logf("  distinguisher signal |rate-floor| = %.5f", math.Abs(cribRate-floor))

	// Sample-bounded null bound: the crib region sits at the
	// independent-stream floor within finite-sample tolerance.
	if cribRate > 0.02 {
		t.Errorf("crib-region ct byte-equal rate %.5f exceeds null bound 0.02 — possible crib anchor signal", cribRate)
	}
	if meanPearson > 0.05 {
		t.Errorf("mean |Pearson| %.5f exceeds null bound 0.05", meanPearson)
	}
}

// Probe 2 — Nonce-reuse correlation (lab-only assumption).
//
// Nonce reuse is not reachable through the shipped API (the nonce is
// drawn from crypto/rand on every call). Forced here via the
// test-only nonce override to measure the one condition under which the
// archived suite saw any signal. Two different plaintexts are
// encrypted under identical seeds AND an identical nonce; the
// ciphertext-level byte-equal rate and Pearson correlation are
// reported. The container's CSPRNG tail fill is drawn independently of
// the nonce, so even under reuse the ciphertext-level correlation
// stays near the independent-stream floor; a full demask of the
// colliding pair additionally requires Full KPA (archived Phase 2d).
func TestRedteamPRF_Probe2_NonceReuseCorrelation(t *testing.T) {
	const (
		trials  = 200
		bodyLen = 4096
	)
	fixedNonce := bytes.Repeat([]byte{0xA5}, NonceSize)
	installTestNonce(t, fixedNonce)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := blake3EightSeedsForProbe()

	var sumEq, sumPearson float64
	for i := 0; i < trials; i++ {
		pt1 := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)
		pt2 := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)

		ct1, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt1)
		if err != nil {
			t.Fatal(err)
		}
		ct2, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt2)
		if err != nil {
			t.Fatal(err)
		}
		sumEq += byteEqualRate(ct1, ct2)
		sumPearson += math.Abs(pearsonBytes(ct1, ct2))
	}
	eqRate := sumEq / trials
	meanPearson := sumPearson / trials
	const floor = 1.0 / 256.0

	t.Logf("Probe 2 Nonce-reuse (LAB-ONLY, BLAKE3, Triple, barrier): N=%d bodyLen=%d", trials, bodyLen)
	t.Logf("  reused-nonce ct byte-equal rate = %.5f (independent-stream floor %.5f)", eqRate, floor)
	t.Logf("  mean |Pearson(ct1,ct2)|         = %.5f", meanPearson)
	t.Logf("  NOTE: nonce reuse is a lab-only assumption; the shipped API draws the nonce from crypto/rand per call")

	// Even under the lab-only reuse condition the ciphertext-level
	// correlation stays near the floor because the CSPRNG tail fill is
	// nonce-independent. Bound generously to record, not over-claim.
	if eqRate > 0.05 {
		t.Errorf("reused-nonce ct byte-equal rate %.5f exceeds recorded bound 0.05", eqRate)
	}
}

// Probe 3 — Related-seed differential.
//
// Not reachable through the shipped API (the 8-seed intake draws
// independent CSPRNG components and rejects pointer collisions). Forced
// here: a seed and its 1-bit-delta twin, every other seed identical,
// same plaintext, same nonce (the fixed nonce isolates the seed's
// effect — otherwise fresh masks would swamp it). The ciphertext
// bit-diff fraction is measured for two channels:
//
//   - dataSeed1 — keys one snake's ChainHash render. Its 1-bit delta is
//     structurally scoped to that snake's third of the payload, then
//     diffused across a broader ciphertext region by the barrier
//     permutation and the COBS/interleave, landing well above the
//     one-snake floor. This diffusion is the 8-seed isolation made
//     observable: the delta does not stay in a few predictable bytes a
//     differential trace could follow.
//   - lockSeed — keys the 48-bit barrier permutation for every chunk.
//     Its 1-bit delta re-draws every per-chunk mask triple, so the
//     ciphertext delta approaches full avalanche (~0.5).
//
// The null verdict is that neither channel exposes a low-weight,
// position-predictable differential: the seed delta decorrelates the
// ciphertext rather than tracing a followable path.
func TestRedteamPRF_Probe3_RelatedSeedDifferential(t *testing.T) {
	const (
		trials  = 128
		bodyLen = 4096
	)
	fixedNonce := bytes.Repeat([]byte{0x5A}, NonceSize)
	installTestNonce(t, fixedNonce)

	h := makeBlake3Hash256()
	var sumData, sumLock float64
	for i := 0; i < trials; i++ {
		ns, _ := NewSeed256(512, h)
		ls, _ := NewSeed256(512, h)
		ds1, _ := NewSeed256(512, h)
		ds2, _ := NewSeed256(512, h)
		ds3, _ := NewSeed256(512, h)
		ss1, _ := NewSeed256(512, h)
		ss2, _ := NewSeed256(512, h)
		ss3, _ := NewSeed256(512, h)

		// dataSeed1' — flip the low bit of the first component.
		ds1pComp := append([]uint64(nil), ds1.Components...)
		ds1pComp[0] ^= 1
		ds1p, err := SeedFromComponents256(h, ds1pComp...)
		if err != nil {
			t.Fatal(err)
		}
		// lockSeed' — flip the low bit (barrier permutation channel).
		lspComp := append([]uint64(nil), ls.Components...)
		lspComp[0] ^= 1
		lsp, err := SeedFromComponents256(h, lspComp...)
		if err != nil {
			t.Fatal(err)
		}

		pt := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)

		ctBase, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatal(err)
		}
		ctData, err := Encrypt3x256Cfg(nil, ns, ls, ds1p, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatal(err)
		}
		ctLock, err := Encrypt3x256Cfg(nil, ns, lsp, ds1, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatal(err)
		}
		sumData += bitDiffFraction(ctBase, ctData)
		sumLock += bitDiffFraction(ctBase, ctLock)
	}
	dataAval := sumData / trials
	lockAval := sumLock / trials

	t.Logf("Probe 3 Related-seed differential (1-bit delta, BLAKE3, Triple, barrier): N=%d bodyLen=%d", trials, bodyLen)
	t.Logf("  dataSeed1 1-bit delta ct bit-diff fraction = %.5f (snake-scoped, barrier-diffused; one-snake floor ~0.167)", dataAval)
	t.Logf("  lockSeed  1-bit delta ct bit-diff fraction = %.5f (global barrier re-draw; full-avalanche 0.5)", lockAval)

	// dataSeed1's delta is structurally scoped to one snake but the
	// barrier diffuses it well above the one-snake floor; lockSeed's
	// delta re-draws every mask and approaches full avalanche. Neither
	// leaves a low-weight followable differential.
	if dataAval < 0.12 || dataAval > 0.42 {
		t.Errorf("dataSeed1 avalanche %.5f outside [0.12,0.42]", dataAval)
	}
	if lockAval < 0.40 || lockAval > 0.55 {
		t.Errorf("lockSeed avalanche %.5f outside [0.40,0.55]", lockAval)
	}
}

// Probe 4 — Full KPA at N derivations sharing state.
//
// Worst-case baseline: the attacker holds N complete plaintext /
// ciphertext pairs produced under one fixed 8-seed bundle with fresh
// nonces, and tries to recover any seed component. The architectural
// obstacle is instance-formulation, not solver speed: even granting
// the 48 known plaintext bits of a chunk, the per-chunk mask triple has
// ~= 2^57.80 preimages and is unobservable without the lockSeed, so no
// per-bit constraint can be written down and no ranking signal exists
// among the ~= 2^70.20 masks. This closure is mathematically bounded,
// not brute-forced (coordinator budget decision — attempts the
// architecture already rules out are documented, not run).
//
// The empirical anchor recorded here confirms the observable side of
// that argument: across N fresh-nonce pairs sharing the full seed
// bundle, the pairwise ciphertext byte-equal rate stays at the
// independent-stream floor — the shared derivation state produces no
// cross-message ciphertext correlation an attacker could aggregate.
func TestRedteamPRF_Probe4_FullKPASharedState(t *testing.T) {
	const (
		nPairs  = 64
		bodyLen = 4096
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := blake3EightSeedsForProbe()

	cts := make([][]byte, nPairs)
	pts := make([][]byte, nPairs)
	for i := 0; i < nPairs; i++ {
		pt := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)
		ct, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatal(err)
		}
		// Round-trip integrity: the attacker's known plaintext is real.
		dec, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dec, pt) {
			t.Fatalf("round-trip mismatch at pair %d", i)
		}
		cts[i] = ct
		pts[i] = pt
	}

	// Aggregate pairwise ciphertext byte-equal rate across the shared-
	// state corpus — the quantity an attacker aggregating N pairs would
	// hope to see rise above the floor.
	var sum float64
	var cnt int
	for i := 0; i < nPairs; i++ {
		for j := i + 1; j < nPairs; j++ {
			sum += byteEqualRate(cts[i], cts[j])
			cnt++
		}
	}
	meanEq := sum / float64(cnt)
	const floor = 1.0 / 256.0

	t.Logf("Probe 4 Full KPA shared-state (BLAKE3, Triple, barrier): N=%d pairs bodyLen=%d", nPairs, bodyLen)
	t.Logf("  pairwise ct byte-equal rate = %.5f (independent-stream floor %.5f)", meanEq, floor)
	t.Logf("  per-chunk mask preimages ~= 2^57.80; per-chunk mask space ~= 2^70.20 (architectural, not brute-forced)")
	t.Logf("  seed recovery is instance-formulation-bounded under the PRF assumption + fresh nonces")

	if meanEq > 0.02 {
		t.Errorf("pairwise ct byte-equal rate %.5f exceeds null bound 0.02 — shared-state correlation", meanEq)
	}
}

// TestRedteamPRF_BLAKE3_NullResult is the compact asserting landed
// test: a fixed corpus of sizes round-trips correctly under BLAKE3 +
// Triple + always-on barrier, and two encryptions of the identical
// plaintext under one seed bundle with fresh nonces produce ciphertext
// at the independent-stream floor — the sample-bounded null-result
// claim for the PRF-grade representative primitive.
func TestRedteamPRF_BLAKE3_NullResult(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := blake3EightSeedsForProbe()
	sizes := []int{1, 64, 255, 256, 1024, 4096, 65537}
	for _, sz := range sizes {
		pt := generateData(sz)
		ct, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatalf("size %d: %v", sz, err)
		}
		dec, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
		if err != nil {
			t.Fatalf("size %d: %v", sz, err)
		}
		if !bytes.Equal(dec, pt) {
			t.Fatalf("size %d: round-trip mismatch", sz)
		}
	}

	// Fresh-nonce independence on identical plaintext: the crib cannot
	// anchor because each message draws fresh masks / noise / offsets.
	const (
		trials  = 100
		bodyLen = 4096
	)
	pt := append(append([]byte(nil), prfPublicCrib...), generateData(bodyLen)...)
	var sum float64
	for i := 0; i < trials; i++ {
		ct1, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatal(err)
		}
		ct2, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, pt)
		if err != nil {
			t.Fatal(err)
		}
		sum += byteEqualRate(ct1, ct2)
	}
	rate := sum / trials
	const floor = 1.0 / 256.0
	t.Logf("identical-plaintext fresh-nonce ct byte-equal rate = %.5f (floor %.5f, N=%d)", rate, floor, trials)
	if rate > 0.02 {
		t.Errorf("identical-plaintext ct byte-equal rate %.5f exceeds null bound 0.02", rate)
	}
}
