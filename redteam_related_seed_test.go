//go:build redteam

package itb

// Related-seed differential re-verification for the v0.3.0 architecture
// (always-on 48-bit Interlocked Barrier + Triple Ouroboros + 8 mandatory
// seeds). Companion to `redteam_broken_test.go` and
// `redteam_nonce_reuse_test.go`; extends the below-spec broken-primitive
// scaffolding with a focused related-seed χ² histogram probe.
//
// The pre-v0.3.0 Phase 2e sweep (archived in
// archive/REDTEAM-v0.2.md § Phase 2e) recorded, on a Single-Ouroboros
// overlay-disengaged encode of the same plaintext under the same nonce,
// a per-primitive axis-hit ciphertext-XOR χ² of **CRC128 ≈ 42.5M**
// and **FNV-1a ≈ 56.7M** against a neutralised cluster near **6.1M**
// (that cluster is the architectural `noisePos` permutation signal on
// the `noise` axis, not a primitive leak). This file measures the same
// statistic against v0.3.0's always-on barrier via the shipped
// `Encrypt3x128Cfg` API to test whether the barrier absorbs the two
// below-spec algebraic surfaces at their pre-v0.3.0 measurement angle.
//
// Threat model per probe (see docstrings): lab-forced 1-bit seed Δ,
// same nonce forced across the compared pair via `setBrokenTestNonce`,
// same plaintext, same hash-function instance. This is a **structural
// diffusion probe** — a real attacker cannot force seed deltas in
// production; the χ² measurement stresses the barrier's diffusion
// property, not any shipped-API attack path.
//
// Attacker-realism (CLAUDE.md discipline):
//
//   - The χ² statistic is inherently attacker-visible — it consumes
//     ciphertext bytes only. No `dataSeed*` / `noiseSeed` / `lockSeed`
//     components are read in any decision path.
//   - Ground-truth Δ hex is emitted only in terminal-stage JSON records
//     for later analysis; the χ² decision does not depend on knowing Δ.
//   - The lab-forced seed Δ is a probe input, not an attacker capability
//     — the ARCHITECTURAL question is whether a 1-bit seed perturbation
//     produces a measurable ciphertext-XOR bias against the df=255
//     uniform band.
//
// Emission: each test writes a compact JSON line to
// `$HOME/scratch/redteam/related_seed/<name>.json` (per CLAUDE.md
// working-tree layout) so downstream aggregation can consume the
// measurements without rerunning the tests. Override the parent
// directory via `REDTEAM_RELATED_SEED_OUTPUT_DIR`. The path is created
// lazily; failure to create it does not fail the test — the log line
// is the primary record.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tmpRSDir is the shared scratch subdir all related-seed probes below
// emit into. Resolved via redteamOutputDir; see that helper for the
// default + env-override contract.
var tmpRSDir = redteamOutputDir("related_seed")

// rsKeyComponents is the fixed component count per Seed128 used by the
// matrix — 1024-bit key = 16 uint64. Matches the pre-v0.3.0 Phase 2e
// baseline so the χ² numbers are directly comparable.
const rsKeyComponents = 16

// rsPlaintextBytes is the plaintext size per matrix cell. 512 KiB
// matches the pre-v0.3.0 Phase 2e sample size that produced the 42M /
// 57M axis-hit records.
const rsPlaintextBytes = 512 * 1024

// emitJSONRS writes a compact JSON line under tmpRSDir/<name>.json for
// downstream aggregation. Errors are logged, not fatal — the t.Logf
// line is the primary record; the JSON is a convenience.
func emitJSONRS(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpRSDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpRSDir, err)
		return
	}
	path := filepath.Join(tmpRSDir, name+".json")
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

// deriveFixedNonceRS builds a deterministic nonce of `size` bytes from
// a seed value via a simple xorshift expansion. Not cryptographically
// meaningful — just needs to be non-zero and reproducible so nonce
// reuse across a compared pair is realised via `setBrokenTestNonce`.
func deriveFixedNonceRS(seed uint64, size int) []byte {
	nonce := make([]byte, size)
	x := seed
	if x == 0 {
		x = 0xA17B1CE
	}
	for i := 0; i < size; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		nonce[i] = byte(x & 0xFF)
	}
	return nonce
}

// drawBaseComponentsRS pulls `n` uint64s from a deterministic PRNG
// keyed by (nonceSeed, streamTag). Disjoint streams per axis so
// baseline seeds are independent across the eight axes but reproducible
// across runs with the same nonceSeed.
func drawBaseComponentsRS(nonceSeed, streamTag uint64, n int) []uint64 {
	rng := rand.New(rand.NewSource(int64(nonceSeed ^ streamTag)))
	out := make([]uint64, n)
	for i := range out {
		out[i] = rng.Uint64()
	}
	return out
}

// rsDeltaComponents returns the 16-uint64 Δ for the given kind, matching
// the pre-v0.3.0 Phase 2e delta patterns (bit0, bit_mid512,
// bit_high1023). Deterministic and axis-agnostic.
func rsDeltaComponents(kind string) []uint64 {
	d := make([]uint64, rsKeyComponents)
	switch kind {
	case "bit0":
		d[0] = 1
	case "bit_mid":
		d[rsKeyComponents/2] = 1
	case "bit_high":
		d[rsKeyComponents-1] = uint64(1) << 63
	}
	return d
}

// generatePlaintextRS returns a deterministic plaintext of the requested
// size and kind — random bytes or printable ASCII drawn from the same
// deterministic PRNG for reproducibility across matrix cells.
func generatePlaintextRS(rng *rand.Rand, size int, kind string) []byte {
	pt := make([]byte, size)
	switch kind {
	case "random":
		if _, err := rng.Read(pt); err != nil {
			panic(err) // math/rand Read never fails
		}
	case "ascii":
		for i := range pt {
			r := rng.Intn(97)
			switch {
			case r == 95:
				pt[i] = 0x09
			case r == 96:
				pt[i] = 0x0A
			default:
				pt[i] = byte(0x20 + r)
			}
		}
	default:
		panic(fmt.Sprintf("rsGeneratePlaintext: bad kind %q", kind))
	}
	return pt
}

// byteChi2RS computes the Pearson χ² statistic on the 256-bin byte
// distribution of D against a uniform expectation (df=255). The
// pre-v0.3.0 analyzer's identical computation is
// scripts/redteam/itb/theory/_common/related_seed_diff_analyze.py::byte_chi_squared.
func byteChi2RS(diff []byte) float64 {
	if len(diff) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range diff {
		counts[b]++
	}
	expected := float64(len(diff)) / 256.0
	chi2 := 0.0
	for i := 0; i < 256; i++ {
		d := float64(counts[i]) - expected
		chi2 += (d * d) / expected
	}
	return chi2
}

// bitBalanceRS returns the mean |p_bit - 0.5| across the 8 bit
// positions of `diff`. A random D has this near 0; an algebraic bias
// pulls it toward 0.5.
func bitBalanceRS(diff []byte) (meanAbs, maxAbs float64) {
	var counts [8]int
	for _, b := range diff {
		for bit := 0; bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				counts[bit]++
			}
		}
	}
	n := float64(len(diff))
	if n == 0 {
		return 0, 0
	}
	sumAbs := 0.0
	for _, c := range counts {
		dev := math.Abs(float64(c)/n - 0.5)
		sumAbs += dev
		if dev > maxAbs {
			maxAbs = dev
		}
	}
	meanAbs = sumAbs / 8.0
	return meanAbs, maxAbs
}

// bodyOfCTRS slices the ciphertext body out of a v0.3.0 wire. Layout:
// main_nonce (NonceSize) || interlock_nonce (NonceSize) || W(2 BE) || H(2 BE) || W×H×Channels body bytes.
func bodyOfCTRS(ct []byte) []byte {
	header := 2*NonceSize + 4
	w := int(binary.BigEndian.Uint16(ct[2*NonceSize : 2*NonceSize+2]))
	h := int(binary.BigEndian.Uint16(ct[2*NonceSize+2 : 2*NonceSize+4]))
	total := w * h
	return ct[header : header+total*Channels]
}

// xorBytesRS returns a XOR b, truncated to min(len(a), len(b)).
func xorBytesRS(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// mkSeed128RS wraps SeedFromComponents128 for the below-spec adapters
// with panic-on-error. Test-fixture only.
func mkSeed128RS(t *testing.T, hf HashFunc128, comps []uint64) *Seed128 {
	t.Helper()
	s, err := SeedFromComponents128(hf, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents128: %v", err)
	}
	return s
}

// rsCell is one row of the matrix — everything needed to identify the
// cell, the χ² measurement itself, and the sample size the χ² was
// computed over.
type rsCell struct {
	Primitive        string  `json:"primitive"`
	Axis             string  `json:"axis"`
	DeltaKind        string  `json:"delta_kind"`
	PlaintextKind    string  `json:"plaintext_kind"`
	PlaintextBytes   int     `json:"plaintext_bytes"`
	BodyBytes        int     `json:"body_bytes"`
	Chi2             float64 `json:"chi2"`
	Chi2DF           int     `json:"chi2_df"`
	BitBalMeanAbs    float64 `json:"bit_bal_mean_abs"`
	BitBalMaxAbs     float64 `json:"bit_bal_max_abs"`
	Container0Bytes  int     `json:"container_0_bytes"`
	Container1Bytes  int     `json:"container_1_bytes"`
	MatchedContainer bool    `json:"matched_container_size"`
}

// rsRun is the top-level JSON emission — configuration + all cells.
type rsRun struct {
	Config struct {
		KeyBits        int      `json:"key_bits"`
		Primitives     []string `json:"primitives"`
		Axes           []string `json:"axes"`
		DeltaKinds     []string `json:"delta_kinds"`
		PlaintextKinds []string `json:"plaintext_kinds"`
		PlaintextBytes int      `json:"plaintext_bytes"`
		NonceSeed      uint64   `json:"nonce_seed"`
	} `json:"config"`
	Cells []rsCell `json:"cells"`
}

// ---------------------------------------------------------------------------
// Positive control — pre-v0.3.0 axis-hit reproduction via process128Cfg
// (Single Ouroboros, no interlock overlay, no 3-snake split). Confirms
// the probe methodology matches the pre-v0.3.0 42M / 57M axis-hit
// records to within a small multiplier — proves the probe is sensitive
// and the neutralised-cluster comparison below is real.
// ---------------------------------------------------------------------------

// TestRedTeamRelatedSeedControl reproduces one pre-v0.3.0 axis-hit cell
// per below-spec primitive (CRC128 + FNV-1a) on the `data` axis with
// the `bit_high` Δ pattern (the row that scored 42M / 57M in Phase 2e
// archived data). The test drives `process128Cfg` directly to bypass
// the v0.3.0 barrier — this is the retired Single Ouroboros /
// overlay-disengaged shape that the pre-v0.3.0 record targeted.
//
// Success criterion: axis-hit χ² for the two below-spec primitives
// lands in the same order of magnitude as the pre-v0.3.0 42M / 57M
// records. A specific tolerance is not asserted here (the seeds and
// nonce differ across runs); the numbers are recorded for terminal-
// stage side-by-side comparison with the matrix under
// `Encrypt3x128Cfg`.
func TestRedTeamRelatedSeedControl(t *testing.T) {
	if testing.Short() {
		t.Skip("related-seed control probe: skipped under -short")
	}

	const nonceSeed uint64 = 0xA17B1CE
	nonce := deriveFixedNonceRS(nonceSeed, NonceSize)
	setBrokenTestNonce(t, nonce)

	// Two independent PRNG streams for base seeds and plaintext so the
	// plaintext is invariant across primitives (fair comparison).
	baseNoise := drawBaseComponentsRS(nonceSeed, 0x1111111111111111, rsKeyComponents)
	baseData := drawBaseComponentsRS(nonceSeed, 0x2222222222222222, rsKeyComponents)
	baseStart := drawBaseComponentsRS(nonceSeed, 0x3333333333333333, rsKeyComponents)
	ptRng := rand.New(rand.NewSource(int64(nonceSeed ^ 0x4444444444444444)))
	plaintext := generatePlaintextRS(ptRng, rsPlaintextBytes, "random")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}

	deltaKind := "bit_high"
	delta := rsDeltaComponents(deltaKind)

	results := make([]map[string]any, 0, len(primitives))

	for _, prim := range primitives {
		// Baseline seeds via components (all three axes).
		noiseSeed0 := mkSeed128RS(t, prim.hf, baseNoise)
		dataSeed0 := mkSeed128RS(t, prim.hf, baseData)
		startSeed0 := mkSeed128RS(t, prim.hf, baseStart)

		// Variant: apply Δ to dataSeed components (data axis, matching
		// the pre-v0.3.0 row that scored 42M / 57M).
		dataVar := make([]uint64, rsKeyComponents)
		copy(dataVar, baseData)
		for i, d := range delta {
			dataVar[i] ^= d
		}
		dataSeed1 := mkSeed128RS(t, prim.hf, dataVar)

		// Container sized to hold the plaintext with a little margin.
		totalPixels := (len(plaintext)*8+DataBitsPerPixel-1)/DataBitsPerPixel + 8

		// Pre-v0.3.0 methodology filled the container with a CSPRNG
		// background before process128Cfg overwrote the data-carrying
		// pixels. Pixels NOT touched by process128Cfg keep the
		// CSPRNG residue, contributing near-uniform XOR to D; the
		// signal is concentrated in the data-carrying region. Two
		// independent draws are used (one per ciphertext) so untouched
		// pixels XOR to uniform random — this matches the archived
		// Phase 2e sample-generation shape.
		encodeOnce := func(ns, ds, ss *Seed128) []byte {
			ctrl, err := generateRandomBytes(totalPixels * Channels)
			if err != nil {
				t.Fatalf("generateRandomBytes: %v", err)
			}
			process128Cfg(nil, ns, ds, ss, nonce, ctrl, totalPixels, 1, plaintext, true, 1)
			return ctrl
		}

		ct0 := encodeOnce(noiseSeed0, dataSeed0, startSeed0)
		ct1 := encodeOnce(noiseSeed0, dataSeed1, startSeed0)
		diff := xorBytesRS(ct0, ct1)

		chi2 := byteChi2RS(diff)
		meanAbs, maxAbs := bitBalanceRS(diff)

		t.Logf("CONTROL %-6s axis=data Δ=%s chi2=%.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d",
			prim.name, deltaKind, chi2, meanAbs, maxAbs, len(diff))

		results = append(results, map[string]any{
			"primitive":         prim.name,
			"axis":              "data",
			"delta_kind":        deltaKind,
			"plaintext_kind":    "random",
			"plaintext_bytes":   len(plaintext),
			"container_bytes":   len(ct0),
			"chi2":              chi2,
			"chi2_df":           255,
			"bit_bal_mean_abs":  meanAbs,
			"bit_bal_max_abs":   maxAbs,
			"probe_shape":       "process128Cfg (Single Ouroboros, no barrier)",
			"pre_v030_baseline": map[string]float64{"CRC128": 42454524, "FNV-1a": 56680753}[prim.name],
		})
	}

	emitJSONRS(t, "related_seed_control", map[string]any{
		"description":     "pre-v0.3.0 axis-hit reproduction via process128Cfg",
		"pre_v030_source": "archive/REDTEAM-v0.2.md § Phase 2e",
		"pre_v030_target": map[string]float64{"CRC128": 42454524, "FNV-1a": 56680753},
		"pre_v030_floor":  6100000.0,
		"cells":           results,
	})
}

// ---------------------------------------------------------------------------
// v0.3.0 architectural floor probe — reveals what the ciphertext-XOR χ²
// looks like under the SHIPPED barrier + same-nonce with NO seed Δ
// applied. This is the floor every axis is measured against: because
// each Encrypt3x128Cfg call draws independent CSPRNG for the container
// background AND for the payload-fill tail, D under identical seeds is
// NOT zero — it carries the "7 data-bits identical + 1 noise-bit
// CSPRNG XOR at noisePos" signal on touched pixels plus a uniform
// contribution from the fill region. The resulting floor χ² is the
// per-encrypt architectural artefact of the barrier's noisePos + CSPRNG
// fill design, independent of any primitive.
// ---------------------------------------------------------------------------

// TestRedTeamRelatedSeedNoDeltaFloor measures the χ² floor under the
// v0.3.0 shipped API with IDENTICAL seeds + same nonce + same
// plaintext. Emits per-primitive floor values so the matrix's per-axis
// χ² can be quoted "over floor" — a Δ that ONLY raises χ² to the
// floor level (~architectural constant) is NOT a primitive-attributable
// leak, it is the same CSPRNG-XOR artefact any two encrypt calls
// produce.
func TestRedTeamRelatedSeedNoDeltaFloor(t *testing.T) {
	if testing.Short() {
		t.Skip("no-Δ floor probe: skipped under -short")
	}

	const nonceSeed uint64 = 0xA17B1CE
	nonce := deriveFixedNonceRS(nonceSeed, NonceSize)
	setBrokenTestNonce(t, nonce)

	baseComponents := map[string][]uint64{}
	for _, axis := range rsAxes {
		baseComponents[axis] = drawBaseComponentsRS(nonceSeed, rsStreamTags[axis], rsKeyComponents)
	}

	ptRandom := generatePlaintextRS(rand.New(rand.NewSource(int64(nonceSeed^0x5555555555555555))), rsPlaintextBytes, "random")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}

	floors := []map[string]any{}

	for _, prim := range primitives {
		mk := func() *Seed128 {
			// Reuse the same baseline components across ALL 8 seeds
			// for the invariant. Note: Encrypt3x128Cfg rejects seed
			// pointer collisions, so we build 8 SEPARATE seed handles
			// carrying the SAME 8 baseline component vectors.
			return mkSeed128RS(t, prim.hf, baseComponents["noiseSeed"])
		}
		_ = mk
		base := [8]*Seed128{
			mkSeed128RS(t, prim.hf, baseComponents["noiseSeed"]),
			mkSeed128RS(t, prim.hf, baseComponents["lockSeed"]),
			mkSeed128RS(t, prim.hf, baseComponents["dataSeed1"]),
			mkSeed128RS(t, prim.hf, baseComponents["dataSeed2"]),
			mkSeed128RS(t, prim.hf, baseComponents["dataSeed3"]),
			mkSeed128RS(t, prim.hf, baseComponents["startSeed1"]),
			mkSeed128RS(t, prim.hf, baseComponents["startSeed2"]),
			mkSeed128RS(t, prim.hf, baseComponents["startSeed3"]),
		}

		ct0, err := Encrypt3x128Cfg(nil, base[0], base[1], base[2], base[3], base[4], base[5], base[6], base[7], ptRandom)
		if err != nil {
			t.Fatalf("baseline Encrypt3x128Cfg %s: %v", prim.name, err)
		}
		ct1, err := Encrypt3x128Cfg(nil, base[0], base[1], base[2], base[3], base[4], base[5], base[6], base[7], ptRandom)
		if err != nil {
			t.Fatalf("re-encrypt Encrypt3x128Cfg %s: %v", prim.name, err)
		}
		body0 := bodyOfCTRS(ct0)
		body1 := bodyOfCTRS(ct1)
		diff := xorBytesRS(body0, body1)
		chi2 := byteChi2RS(diff)
		meanAbs, maxAbs := bitBalanceRS(diff)
		t.Logf("FLOOR  %-6s NO_Δ chi2=%10.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d",
			prim.name, chi2, meanAbs, maxAbs, len(diff))
		floors = append(floors, map[string]any{
			"primitive":        prim.name,
			"chi2":             chi2,
			"chi2_df":          255,
			"bit_bal_mean_abs": meanAbs,
			"bit_bal_max_abs":  maxAbs,
			"body_bytes":       len(diff),
			"note":             "two encrypts, identical seeds, same nonce; CSPRNG-XOR artefact of noise-bit + fill",
		})
	}

	emitJSONRS(t, "related_seed_floor", map[string]any{
		"description": "no-Δ χ² floor under v0.3.0 shipped Encrypt3x128Cfg",
		"floors":      floors,
	})
}

// ---------------------------------------------------------------------------
// v0.3.0 matrix — 8 axes × 3 Δ patterns × 2 plaintext kinds × 2 below-spec
// primitives = 96 cells. Each cell computes ct_0 ⊕ ct_1 body χ² against
// df=255 uniform expectation via the shipped Encrypt3x128Cfg API with
// the always-on 48-bit Interlocked Barrier. Same-nonce forced through
// setBrokenTestNonce; production callers cannot reach that path.
// ---------------------------------------------------------------------------

// rsAxes is the 8-seed axis list matching the Encrypt3x128Cfg
// signature. `noise` and `lock` share the noiseSeed/lockSeed roles; the
// three data/start axes correspond to the three parallel snake tracks.
var rsAxes = []string{
	"noiseSeed", "lockSeed",
	"dataSeed1", "dataSeed2", "dataSeed3",
	"startSeed1", "startSeed2", "startSeed3",
}

// rsStreamTags is the disjoint per-axis PRNG stream tag so baseline
// components for each of the 8 seeds are independent but reproducible.
var rsStreamTags = map[string]uint64{
	"noiseSeed":  0xAA00000000000001,
	"lockSeed":   0xAA00000000000002,
	"dataSeed1":  0xAA00000000000003,
	"dataSeed2":  0xAA00000000000004,
	"dataSeed3":  0xAA00000000000005,
	"startSeed1": 0xAA00000000000006,
	"startSeed2": 0xAA00000000000007,
	"startSeed3": 0xAA00000000000008,
}

// TestRedTeamRelatedSeedMatrix runs the full 96-cell matrix under
// Encrypt3x128Cfg + always-on Interlocked Barrier. Each cell forces a
// 1-bit Δ on exactly one seed axis, holds every other seed + the nonce
// + the plaintext fixed, and computes the ciphertext-body XOR χ².
//
// Runtime: ~5-15 minutes wall clock at 512 KiB plaintext × 192
// encrypts × two below-spec primitives. Encrypt3x128Cfg uses
// runtime.NumCPU() workers, so wall time scales with cores.
func TestRedTeamRelatedSeedMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("related-seed matrix: skipped under -short (192 512-KiB encrypts)")
	}

	const nonceSeed uint64 = 0xA17B1CE
	nonce := deriveFixedNonceRS(nonceSeed, NonceSize)
	setBrokenTestNonce(t, nonce)

	baseComponents := map[string][]uint64{}
	for _, axis := range rsAxes {
		baseComponents[axis] = drawBaseComponentsRS(nonceSeed, rsStreamTags[axis], rsKeyComponents)
	}

	// Plaintexts: shared across all cells for a given plaintext kind.
	ptRandom := generatePlaintextRS(rand.New(rand.NewSource(int64(nonceSeed^0x5555555555555555))), rsPlaintextBytes, "random")
	ptAscii := generatePlaintextRS(rand.New(rand.NewSource(int64(nonceSeed^0x6666666666666666))), rsPlaintextBytes, "ascii")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}

	deltaKinds := []string{"bit0", "bit_mid", "bit_high"}
	plaintextKinds := []string{"random", "ascii"}

	run := rsRun{}
	run.Config.KeyBits = rsKeyComponents * 64
	for _, p := range primitives {
		run.Config.Primitives = append(run.Config.Primitives, p.name)
	}
	run.Config.Axes = append([]string{}, rsAxes...)
	run.Config.DeltaKinds = append([]string{}, deltaKinds...)
	run.Config.PlaintextKinds = append([]string{}, plaintextKinds...)
	run.Config.PlaintextBytes = rsPlaintextBytes
	run.Config.NonceSeed = nonceSeed

	// buildBaseline constructs the 8 baseline seeds under primitive p —
	// same components across all cells for that primitive; only the
	// axis-specific variant seed differs.
	buildBaseline := func(hf HashFunc128) [8]*Seed128 {
		return [8]*Seed128{
			mkSeed128RS(t, hf, baseComponents["noiseSeed"]),
			mkSeed128RS(t, hf, baseComponents["lockSeed"]),
			mkSeed128RS(t, hf, baseComponents["dataSeed1"]),
			mkSeed128RS(t, hf, baseComponents["dataSeed2"]),
			mkSeed128RS(t, hf, baseComponents["dataSeed3"]),
			mkSeed128RS(t, hf, baseComponents["startSeed1"]),
			mkSeed128RS(t, hf, baseComponents["startSeed2"]),
			mkSeed128RS(t, hf, baseComponents["startSeed3"]),
		}
	}

	axisIndex := map[string]int{
		"noiseSeed": 0, "lockSeed": 1,
		"dataSeed1": 2, "dataSeed2": 3, "dataSeed3": 4,
		"startSeed1": 5, "startSeed2": 6, "startSeed3": 7,
	}

	for _, prim := range primitives {
		base := buildBaseline(prim.hf)
		for _, axis := range rsAxes {
			for _, dk := range deltaKinds {
				delta := rsDeltaComponents(dk)
				varComps := make([]uint64, rsKeyComponents)
				copy(varComps, baseComponents[axis])
				for i, d := range delta {
					varComps[i] ^= d
				}
				varSeed := mkSeed128RS(t, prim.hf, varComps)
				for _, ptk := range plaintextKinds {
					var pt []byte
					if ptk == "random" {
						pt = ptRandom
					} else {
						pt = ptAscii
					}

					// Baseline encrypt.
					ct0, err := Encrypt3x128Cfg(nil, base[0], base[1], base[2], base[3], base[4], base[5], base[6], base[7], pt)
					if err != nil {
						t.Fatalf("baseline Encrypt3x128Cfg %s/%s/%s/%s: %v", prim.name, axis, dk, ptk, err)
					}

					// Variant: swap in varSeed on `axis`.
					var variant [8]*Seed128
					variant = base
					variant[axisIndex[axis]] = varSeed
					ct1, err := Encrypt3x128Cfg(nil, variant[0], variant[1], variant[2], variant[3], variant[4], variant[5], variant[6], variant[7], pt)
					if err != nil {
						t.Fatalf("variant Encrypt3x128Cfg %s/%s/%s/%s: %v", prim.name, axis, dk, ptk, err)
					}

					body0 := bodyOfCTRS(ct0)
					body1 := bodyOfCTRS(ct1)
					matched := len(body0) == len(body1)
					diff := xorBytesRS(body0, body1)
					chi2 := byteChi2RS(diff)
					meanAbs, maxAbs := bitBalanceRS(diff)

					cell := rsCell{
						Primitive:        prim.name,
						Axis:             axis,
						DeltaKind:        dk,
						PlaintextKind:    ptk,
						PlaintextBytes:   len(pt),
						BodyBytes:        len(diff),
						Chi2:             chi2,
						Chi2DF:           255,
						BitBalMeanAbs:    meanAbs,
						BitBalMaxAbs:     maxAbs,
						Container0Bytes:  len(ct0),
						Container1Bytes:  len(ct1),
						MatchedContainer: matched,
					}
					run.Cells = append(run.Cells, cell)

					t.Logf("%-6s axis=%-11s Δ=%-8s pt=%-6s chi2=%10.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d match=%v",
						prim.name, axis, dk, ptk, chi2, meanAbs, maxAbs, len(diff), matched)
				}
			}
		}
	}

	// Sanity floors: report per-primitive max χ² and identify axis-hit
	// outliers relative to the pre-v0.3.0 42M/57M baseline and the
	// neutralised 6.1M cluster.
	summary := map[string]map[string]any{}
	for _, prim := range primitives {
		var maxChi float64
		var maxCell rsCell
		var nonNoiseMaxChi float64
		var nonNoiseMaxCell rsCell
		for _, c := range run.Cells {
			if c.Primitive != prim.name {
				continue
			}
			if c.Chi2 > maxChi {
				maxChi = c.Chi2
				maxCell = c
			}
			if strings.HasPrefix(c.Axis, "data") || strings.HasPrefix(c.Axis, "start") || c.Axis == "lockSeed" {
				if c.Chi2 > nonNoiseMaxChi {
					nonNoiseMaxChi = c.Chi2
					nonNoiseMaxCell = c
				}
			}
		}
		t.Logf("SUMMARY %-6s: max_chi2=%10.1f on axis=%s Δ=%s pt=%s",
			prim.name, maxChi, maxCell.Axis, maxCell.DeltaKind, maxCell.PlaintextKind)
		t.Logf("SUMMARY %-6s: max_chi2 excluding noiseSeed axis: %10.1f on axis=%s Δ=%s pt=%s",
			prim.name, nonNoiseMaxChi, nonNoiseMaxCell.Axis, nonNoiseMaxCell.DeltaKind, nonNoiseMaxCell.PlaintextKind)
		summary[prim.name] = map[string]any{
			"max_chi2_all_axes":         maxChi,
			"max_chi2_all_axes_cell":    maxCell,
			"max_chi2_excl_noise":       nonNoiseMaxChi,
			"max_chi2_excl_noise_cell":  nonNoiseMaxCell,
			"pre_v030_axis_hit_target":  map[string]float64{"CRC128": 42454524, "FNV-1a": 56680753}[prim.name],
			"pre_v030_neutralised_band": 6100000.0,
		}
	}

	emitJSONRS(t, "related_seed_matrix", map[string]any{
		"run":     run,
		"summary": summary,
	})
}
