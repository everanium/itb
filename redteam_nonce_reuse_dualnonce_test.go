//go:build redteam

package itb

// Nonce-Reuse dual-nonce re-verification for the v0.3.0 wire format
// (`[main_nonce (N)][interlock_nonce (N)][W][H][container]`, header
// size `2*N+4`). Companion to the historical `redteam_nonce_reuse_test.go`
// probes, which were authored against the pre-v0.3.0 single-nonce wire
// and cannot re-run against the shipped construction (their wire
// parsers panic on out-of-range slices when W/H are read from bytes
// that are actually the interlock nonce).
//
// The three scenarios below map to the maintainer's methodology for
// isolating the two independent nonces' contributions:
//
//   Scenario A — Full nonce-reuse degeneracy. Both messages share the
//     main nonce AND both messages share the interlock nonce; within
//     each message the two nonces stay byte-distinct (matching the
//     shipped `generateNoncePairCfg` invariant). This reproduces the
//     pre-v0.3.0 single-nonce reuse event under the dual-nonce header.
//
//   Scenario B — Partial nonce-reuse (main-only). The main nonce is
//     fixed across the compared pair; the interlock nonce is drawn
//     from crypto/rand per encrypt. Reproduces a buggy caller who
//     reuses the seven main-nonce-keyed derivation slots (per-pixel
//     noisePos, per-snake rotation / channelXOR, per-snake startPixel)
//     but leaves the eighth (lockSeed-keyed per-chunk mask draw)
//     PRF-parameterised.
//
//   Scenario C — Partial nonce-reuse (interlock-only). Mirror of B —
//     the interlock nonce is fixed across the pair; the main nonce is
//     drawn per encrypt. Reproduces the buggy caller who reuses the
//     interlock permutation slot but leaves the seven main-nonce-keyed
//     slots PRF-parameterised.
//
// Each probe measures four container-body statistics: byte-equal rate
// against the 1/256 independent-stream floor, chi-square vs uniform
// df=255, |Pearson(c1_body, c2_body)|, and Hamming bit-diff fraction
// (target 0.5 under independence). All statistics operate on the
// container body only — the deterministic dual-nonce header bytes are
// stripped so they do not swamp the barrier signal by contributing
// perfectly correlated bytes under Scenario A. Two primitives cover
// the PRF (BLAKE3-128) and below-spec (FNV-1a) ends of the spectrum.
//
// Attacker-realism (CLAUDE.md discipline): every statistic reads
// ciphertext bytes and the public wire header only. Seed components
// and interlock lockSeed material are never touched in the decision
// path. The forced-nonce lab hooks are the probe input, not an
// attacker capability — a production caller cannot reach either
// override, because `generateNonceCfg` and `generateInterlockNonceCfg`
// both draw independently from crypto/rand.
//
// Emission: each probe writes a compact JSON record under
// `$HOME/scratch/redteam/nonce_reuse_dualnonce/<name>.json`
// (per CLAUDE.md working-tree layout) so downstream aggregation can
// consume the raw numbers without rerunning the tests. Override the
// parent directory via `REDTEAM_NONCE_REUSE_DUALNONCE_OUTPUT_DIR`.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// tmpDualNRDir is the shared scratch subdir all dual-nonce probes below
// emit into. Resolved via redteamOutputDir; see that helper for the
// default + env-override contract.
var tmpDualNRDir = redteamOutputDir("nonce_reuse_dualnonce")

// emitJSONDualNR writes a compact JSON record. Non-fatal on error.
func emitJSONDualNR(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpDualNRDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpDualNRDir, err)
		return
	}
	path := filepath.Join(tmpDualNRDir, name+".json")
	f, err := os.Create(path)
	if err != nil {
		t.Logf("[emit] create %s: %v", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Logf("[emit] encode %s: %v", path, err)
		return
	}
	t.Logf("[emit] %s", path)
}

// ---------------------------------------------------------------------------
// Test-only nonce override helpers — dual-nonce aware.
//
// The existing `setBrokenTestNonce` (`redteam_broken_test.go:84`) and
// `installTestNonce` (`stream_envelope_test.go:17`) both install the
// same byte value into both overrides — the Scenario-A-with-equal-nonces
// case. The three helpers below provide the missing independent-slot
// control needed to isolate Scenarios A / B / C:
//
//   - `setBrokenTestNoncePair(t, main, il)` installs both overrides
//     with independent values, so the pair reaches the encrypt path
//     with `main != il` even under lab control.
//   - `setBrokenTestMainNonceOnly(t, main)` installs the main override
//     and clears the interlock override, so `generateInterlockNonceCfg`
//     falls through to crypto/rand.
//   - `setBrokenTestInterlockNonceOnly(t, il)` mirrors the above for
//     the interlock slot.
//
// All three restore previously-installed overrides on test cleanup.
// ---------------------------------------------------------------------------

func setBrokenTestNoncePair(t *testing.T, mainNonce, interlockNonce []byte) {
	t.Helper()
	oldMain := testNonceOverride.Load()
	oldIl := testInterlockNonceOverride.Load()
	mc := append([]byte(nil), mainNonce...)
	ic := append([]byte(nil), interlockNonce...)
	testNonceOverride.Store(&mc)
	testInterlockNonceOverride.Store(&ic)
	t.Cleanup(func() {
		testNonceOverride.Store(oldMain)
		testInterlockNonceOverride.Store(oldIl)
	})
}

func setBrokenTestMainNonceOnly(t *testing.T, mainNonce []byte) {
	t.Helper()
	oldMain := testNonceOverride.Load()
	oldIl := testInterlockNonceOverride.Load()
	mc := append([]byte(nil), mainNonce...)
	testNonceOverride.Store(&mc)
	testInterlockNonceOverride.Store((*[]byte)(nil))
	t.Cleanup(func() {
		testNonceOverride.Store(oldMain)
		testInterlockNonceOverride.Store(oldIl)
	})
}

func setBrokenTestInterlockNonceOnly(t *testing.T, interlockNonce []byte) {
	t.Helper()
	oldMain := testNonceOverride.Load()
	oldIl := testInterlockNonceOverride.Load()
	ic := append([]byte(nil), interlockNonce...)
	testNonceOverride.Store((*[]byte)(nil))
	testInterlockNonceOverride.Store(&ic)
	t.Cleanup(func() {
		testNonceOverride.Store(oldMain)
		testInterlockNonceOverride.Store(oldIl)
	})
}

// ---------------------------------------------------------------------------
// Dual-nonce wire parser + statistics.
// ---------------------------------------------------------------------------

// wireLayoutDualNR describes the v0.3.0 dual-nonce wire slices. Both
// nonces are surfaced independently so probes can consult either one.
type wireLayoutDualNR struct {
	mainNonce      []byte
	interlockNonce []byte
	width          int
	height         int
	totalPixels    int
	headerSize     int
	body           []byte
}

// decodeWireDualNR parses the v0.3.0 dual-nonce wire header. Panics on
// malformed input — probes hand it fresh Encrypt output only.
func decodeWireDualNR(ct []byte) wireLayoutDualNR {
	n := NonceSize
	main := ct[:n]
	il := ct[n : 2*n]
	w := int(binary.BigEndian.Uint16(ct[2*n : 2*n+2]))
	h := int(binary.BigEndian.Uint16(ct[2*n+2 : 2*n+4]))
	total := w * h
	hdr := 2*n + 4
	body := ct[hdr : hdr+total*Channels]
	return wireLayoutDualNR{
		mainNonce:      main,
		interlockNonce: il,
		width:          w,
		height:         h,
		totalPixels:    total,
		headerSize:     hdr,
		body:           body,
	}
}

// byteEqualRateDualNR is the position-wise equal-byte fraction of two
// equal-prefix byte streams; expectation 1/256 under independence.
func byteEqualRateDualNR(a, b []byte) float64 {
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

// pearsonBytesDualNR is the Pearson correlation coefficient between two
// equal-prefix byte streams treated as integer samples.
func pearsonBytesDualNR(a, b []byte) float64 {
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

// bitDiffFractionDualNR is the fraction of differing bits between two
// equal-prefix byte streams; expectation 0.5 under independence. Used
// as the Hamming distinguisher the maintainer specifically flagged for
// re-measurement.
func bitDiffFractionDualNR(a, b []byte) float64 {
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

// chiSquareUniformBytesDualNR returns the byte-value chi-square vs the
// uniform-256 expectation (df = 255; uniform band at N large is
// approximately [220, 292] for p in [0.01, 0.99]).
func chiSquareUniformBytesDualNR(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var hist [256]int
	for _, b := range data {
		hist[b]++
	}
	expected := float64(len(data)) / 256.0
	if expected == 0 {
		return 0
	}
	var chi2 float64
	for _, c := range hist {
		d := float64(c) - expected
		chi2 += d * d / expected
	}
	return chi2
}

// buildEightSeedsDualNR builds the 8 mandatory seed roles as
// Seed128 handles, all keyed by `hf`, using independent PRNG streams
// derived from the given base seed.
func buildEightSeedsDualNR(t *testing.T, hf HashFunc128, keyBits int, base uint64) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	nComp := keyBits / 64
	streams := [8]uint64{
		base ^ 0xE100000000000001, base ^ 0xE100000000000002,
		base ^ 0xE100000000000003, base ^ 0xE100000000000004,
		base ^ 0xE100000000000005, base ^ 0xE100000000000006,
		base ^ 0xE100000000000007, base ^ 0xE100000000000008,
	}
	mk := func(streamTag uint64, role string) *Seed128 {
		rng := rand.New(rand.NewSource(int64(streamTag)))
		comps := make([]uint64, nComp)
		for i := range comps {
			comps[i] = rng.Uint64()
		}
		s, err := SeedFromComponents128(hf, comps...)
		if err != nil {
			t.Fatalf("SeedFromComponents128(%s): %v", role, err)
		}
		return s
	}
	return mk(streams[0], "noise"), mk(streams[1], "lock"),
		mk(streams[2], "d1"), mk(streams[3], "d2"), mk(streams[4], "d3"),
		mk(streams[5], "s1"), mk(streams[6], "s2"), mk(streams[7], "s3")
}

// derivePairNonces produces a byte-distinct (main, interlock) pair of
// NonceSize bytes each, deterministic from `seed`. Distinctness is
// enforced by post-derivation compare-and-flip on the first differing
// byte if the two streams happen to coincide (astronomically rare at
// 512 bits but the flip keeps the invariant unconditional).
func derivePairNonces(seed uint64) (main, il []byte) {
	main = make([]byte, NonceSize)
	il = make([]byte, NonceSize)
	rng := rand.New(rand.NewSource(int64(seed)))
	for i := range main {
		main[i] = byte(rng.Intn(256))
	}
	for i := range il {
		il[i] = byte(rng.Intn(256))
	}
	for i := range main {
		if main[i] != il[i] {
			return main, il
		}
	}
	il[0] ^= 0x01
	return main, il
}

// ---------------------------------------------------------------------------
// Probe framework — three scenarios × two plaintext shapes × two primitives.
// ---------------------------------------------------------------------------

// dualNRScenario selects which nonce slots are held fixed across the
// compared pair.
type dualNRScenario int

const (
	scenarioA dualNRScenario = iota // both collide
	scenarioB                       // main only collides
	scenarioC                       // interlock only collides
)

func (s dualNRScenario) String() string {
	switch s {
	case scenarioA:
		return "A (both collide)"
	case scenarioB:
		return "B (main only)"
	case scenarioC:
		return "C (interlock only)"
	}
	return "unknown"
}

// dualNRCell aggregates one (scenario, primitive, shape, size) result.
type dualNRCell struct {
	Scenario     string  `json:"scenario"`
	Primitive    string  `json:"primitive"`
	Shape        string  `json:"plaintext_shape"`
	PlaintextLen int     `json:"plaintext_bytes"`
	Pairs        int     `json:"pairs"`
	BodyBytes    int     `json:"body_bytes_total"`
	ByteEqualRt  float64 `json:"body_byte_equal_rate"`
	FloorRatio   float64 `json:"vs_1_over_256_floor"`
	Chi2Uniform  float64 `json:"body_chi2_uniform_df255"`
	PearsonMean  float64 `json:"body_mean_abs_pearson_c1_c2"`
	HammingBit   float64 `json:"body_bit_diff_fraction"`
}

// runDualNRScenario runs one (scenario × primitive × shape × size)
// cell, encrypting `pairs` message pairs and returning the aggregate
// container-body statistics. The forced-nonce lab hook is installed
// per pair — Scenarios B and C re-install with a fresh non-collided
// side on every iteration so the CSPRNG-drawn slot varies pair-to-pair.
func runDualNRScenario(t *testing.T, scenario dualNRScenario, primName string, hf HashFunc128, shape string, plaintextLen, pairs int, seedBase uint64) dualNRCell {
	t.Helper()

	// One session key bundle for the whole cell — the reuse threat model
	// holds seeds fixed and varies only the nonce slot(s).
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightSeedsDualNR(t, hf, 512, seedBase)

	// Fixed main / interlock values for the slots the scenario collides.
	fixedMain, fixedIl := derivePairNonces(seedBase ^ 0xDA1DA100C0DEDA1D)
	// Session-fresh scratch buffers for the CSPRNG-drawn side under
	// Scenarios B / C (crypto/rand fills these per pair via a re-derived
	// lab RNG so the cell is reproducible).
	freshRng := rand.New(rand.NewSource(int64(seedBase ^ 0x0F0F5A5AA5A5F0F0)))

	plainRng := rand.New(rand.NewSource(int64(seedBase ^ 0x5EED0FA5A5A50FEE)))
	makePair := func(i int) (p1, p2 []byte) {
		p1 = make([]byte, plaintextLen)
		p2 = make([]byte, plaintextLen)
		switch shape {
		case "random":
			plainRng.Read(p1)
			plainRng.Read(p2)
		case "near_identical":
			plainRng.Read(p1)
			copy(p2, p1)
			// Flip one bit at the middle byte per pair — the maximally
			// adversarial pair shape for the pre-v0.3.0 near-identical
			// Layer A residue.
			p2[plaintextLen/2] ^= byte(1 << (uint(i) % 8))
		default:
			t.Fatalf("unknown shape %q", shape)
		}
		return
	}

	// Body-only aggregate — the deterministic dual-nonce header bytes
	// are stripped so scenarios with a fixed nonce slot do not swamp
	// the barrier signal with perfectly correlated header bytes.
	var (
		bodyBytesTotal int
		byteEqualHits  int
		sumPearson     float64
		sumHamming     float64
		concatBodyXor  []byte
	)

	for i := 0; i < pairs; i++ {
		// Install overrides for this pair.
		switch scenario {
		case scenarioA:
			setBrokenTestNoncePair(t, fixedMain, fixedIl)
		case scenarioB:
			freshIl1 := make([]byte, NonceSize)
			freshRng.Read(freshIl1)
			setBrokenTestNoncePair(t, fixedMain, freshIl1)
		case scenarioC:
			freshMain1 := make([]byte, NonceSize)
			freshRng.Read(freshMain1)
			setBrokenTestNoncePair(t, freshMain1, fixedIl)
		}
		p1, p2 := makePair(i)
		c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg p1: %v", err)
		}
		// Re-install for the second encrypt — Scenarios B / C draw a
		// fresh non-collided side so `c1` and `c2` differ on that slot.
		switch scenario {
		case scenarioA:
			setBrokenTestNoncePair(t, fixedMain, fixedIl)
		case scenarioB:
			freshIl2 := make([]byte, NonceSize)
			freshRng.Read(freshIl2)
			setBrokenTestNoncePair(t, fixedMain, freshIl2)
		case scenarioC:
			freshMain2 := make([]byte, NonceSize)
			freshRng.Read(freshMain2)
			setBrokenTestNoncePair(t, freshMain2, fixedIl)
		}
		c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg p2: %v", err)
		}
		layout := decodeWireDualNR(c1)
		body1 := c1[layout.headerSize : layout.headerSize+layout.totalPixels*Channels]
		body2 := c2[layout.headerSize : layout.headerSize+layout.totalPixels*Channels]

		// Sanity: the collided-slot invariant actually holds on the wire.
		mainCollide := string(c1[:NonceSize]) == string(c2[:NonceSize])
		ilCollide := string(c1[NonceSize:2*NonceSize]) == string(c2[NonceSize:2*NonceSize])
		switch scenario {
		case scenarioA:
			if !mainCollide || !ilCollide {
				t.Fatalf("scenarioA pair %d: expected both nonces to collide, main=%v il=%v", i, mainCollide, ilCollide)
			}
		case scenarioB:
			if !mainCollide || ilCollide {
				t.Fatalf("scenarioB pair %d: expected main-only collision, main=%v il=%v", i, mainCollide, ilCollide)
			}
		case scenarioC:
			if mainCollide || !ilCollide {
				t.Fatalf("scenarioC pair %d: expected interlock-only collision, main=%v il=%v", i, mainCollide, ilCollide)
			}
		}

		nBody := len(body1)
		if len(body2) < nBody {
			nBody = len(body2)
		}
		bodyXor := make([]byte, nBody)
		for k := 0; k < nBody; k++ {
			bodyXor[k] = body1[k] ^ body2[k]
			if bodyXor[k] == 0 {
				byteEqualHits++
			}
		}
		bodyBytesTotal += nBody
		sumPearson += math.Abs(pearsonBytesDualNR(body1[:nBody], body2[:nBody]))
		sumHamming += bitDiffFractionDualNR(body1[:nBody], body2[:nBody])
		concatBodyXor = append(concatBodyXor, bodyXor...)
	}

	byteEqualRate := 0.0
	if bodyBytesTotal > 0 {
		byteEqualRate = float64(byteEqualHits) / float64(bodyBytesTotal)
	}
	pairsF := float64(pairs)
	if pairsF <= 0 {
		pairsF = 1
	}
	chi2 := chiSquareUniformBytesDualNR(concatBodyXor)

	return dualNRCell{
		Scenario:     scenario.String(),
		Primitive:    primName,
		Shape:        shape,
		PlaintextLen: plaintextLen,
		Pairs:        pairs,
		BodyBytes:    bodyBytesTotal,
		ByteEqualRt:  byteEqualRate,
		FloorRatio:   byteEqualRate / (1.0 / 256.0),
		Chi2Uniform:  chi2,
		PearsonMean:  sumPearson / pairsF,
		HammingBit:   sumHamming / pairsF,
	}
}

// TestRedTeamNonceReuseDualNonceMatrix runs the full 3 × 2 × 2 × 3 grid
// (scenarios × primitives × shapes × sizes) at N = 200 pairs per cell,
// emitting a compact JSON record. Wall-clock at the shipped default
// nonce width (512 bits) and 512-B / 4 KiB / 16 KiB plaintexts: ~2
// minutes on a modern desktop.
func TestRedTeamNonceReuseDualNonceMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("dual-nonce nonce-reuse matrix: skipped under -short")
	}

	const pairs = 200
	seedBase := uint64(0xD00D_C0DE_A11C_EBAB)

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"FNV-1a", fnv1a128BrokenLab},
		{"BLAKE3-128", makeBlake3Hash128CPA(0xB13A_5AFE_15AF_E5EE)},
	}
	sizes := []int{512, 4096, 16384}
	shapes := []string{"random", "near_identical"}
	scenarios := []dualNRScenario{scenarioA, scenarioB, scenarioC}

	var cells []dualNRCell
	for _, sc := range scenarios {
		for _, prim := range primitives {
			for _, size := range sizes {
				for _, shape := range shapes {
					cell := runDualNRScenario(t, sc, prim.name, prim.hf, shape, size, pairs, seedBase)
					cells = append(cells, cell)
					t.Logf("scenario=%s prim=%-11s size=%5d shape=%-14s N=%d body=%d byte_eq=%.5f (%.3fx floor) chi2=%9.1f |Pearson|=%.5f hamming=%.5f",
						sc, prim.name, size, shape, pairs, cell.BodyBytes,
						cell.ByteEqualRt, cell.FloorRatio, cell.Chi2Uniform,
						cell.PearsonMean, cell.HammingBit)
				}
			}
		}
	}

	emitJSONDualNR(t, "dualnonce_matrix", map[string]any{
		"description":   "Container-body statistics under three dual-nonce reuse scenarios; two primitives; two shapes; three plaintext sizes.",
		"scenarios":     "A: both nonces collide across pair (main != il within message). B: main only. C: interlock only.",
		"pairs_per_cell": pairs,
		"nonce_bits":    NonceSize * 8,
		"key_bits":      512,
		"floor_1_over_256": 1.0 / 256.0,
		"uniform_band_df255_p01_p99": []float64{220, 292},
		"cells": cells,
	})
	// Attach a compact summary row to the log so `go test -v` output is
	// self-contained without opening the JSON.
	t.Logf("Wrote %d cells to %s/dualnonce_matrix.json", len(cells), tmpDualNRDir)
	_ = fmt.Sprintf // retain import if a future edit drops the Sprintf use
}

// TestRedTeamNonceReuseDualNonceHeadlineBLAKE3 is a minimal fast smoke
// (N = 200, single 4 KiB size, random shape only) that produces the
// headline byte-equal / |Pearson| pair the REDTEAM.md verdict table
// cites for each scenario under a PRF-grade reference primitive. Wall
// clock ~10 seconds; the broader matrix above is the audit surface.
func TestRedTeamNonceReuseDualNonceHeadlineBLAKE3(t *testing.T) {
	const (
		pairs   = 200
		bodyLen = 4096
	)
	seedBase := uint64(0xB1A2_CE3E_5A17_E1AA)
	hf := makeBlake3Hash128CPA(0xB13A_5AFE_15AF_E5EE)

	scenarios := []dualNRScenario{scenarioA, scenarioB, scenarioC}
	var cells []dualNRCell
	for _, sc := range scenarios {
		cell := runDualNRScenario(t, sc, "BLAKE3-128", hf, "random", bodyLen, pairs, seedBase)
		cells = append(cells, cell)
		t.Logf("Headline BLAKE3-128 %s: byte_eq=%.5f (%.3fx floor) |Pearson|=%.5f hamming=%.5f chi2=%.1f",
			sc, cell.ByteEqualRt, cell.FloorRatio, cell.PearsonMean, cell.HammingBit, cell.Chi2Uniform)
	}

	emitJSONDualNR(t, "headline_blake3", map[string]any{
		"description": "Headline byte-equal / Pearson / Hamming numbers per scenario under PRF-grade BLAKE3-128 reference primitive.",
		"pairs":       pairs,
		"plaintext_bytes": bodyLen,
		"cells":       cells,
	})
}
