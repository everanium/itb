//go:build redteam

package itb

// Related-nonce differential re-verification under the shipped dual-nonce
// wire (`[main_nonce (N)][interlock_nonce (N)][W][H][container]`, header
// size `2*N+4`). Companion to `redteam_related_nonce_test.go`, which
// applies a 1-bit Δ that perturbs BOTH nonce slots simultaneously (its
// `setBrokenTestNonce` helper installs the same byte value into both
// overrides). The dual-nonce architecture surfaces two independent
// nonce inputs — `main_nonce` and `interlock_nonce` — and this file
// isolates the two-way decomposition:
//
//   Scenario A — dual-slot Δ. Applies the 1-bit Δ to both nonces
//     simultaneously. Reproduces the historical joint-Δ measurement
//     that `redteam_related_nonce_test.go` records under `setBrokenTestNonce`.
//
//   Scenario B — main-only Δ. Applies the Δ to `main_nonce` only;
//     `interlock_nonce` matches across the pair. Isolates the seven
//     main-nonce-keyed derivation slots (per-pixel `noisePos`, per-snake
//     `rotation` + `channelXOR`, per-snake `startPixel`) — the interlock
//     `lockSeed` slot receives the same nonce byte value on both sides
//     of the pair.
//
//   Scenario C — interlock-only Δ. Applies the Δ to `interlock_nonce`
//     only; `main_nonce` matches. Isolates the interlock permutation slot.
//
// Attacker-realism (attacker-realism discipline): all statistics operate on
// public ciphertext bytes only. Seed components are never consulted in
// the decision path. The forced-nonce lab hooks (`setBrokenTestNoncePair`,
// `setBrokenTestMainNonceOnly`, `setBrokenTestInterlockNonceOnly` — defined
// in `redteam_nonce_reuse_dualnonce_test.go`) are probe inputs, not
// attacker capabilities. A production caller cannot force either nonce
// because `generateNonceCfg` and `generateInterlockNonceCfg` both draw
// independently from `crypto/rand`.
//
// The `decodeWireDualNR` parser and the wire-body statistics also live
// in the sibling `redteam_nonce_reuse_dualnonce_test.go` file (same
// package, same build tag).
//
// Emission: `$HOME/scratch/redteam/related_nonce_dualnonce/<name>.json`
// (per the working-tree layout). Override the parent directory
// via `REDTEAM_RELATED_NONCE_DUALNONCE_OUTPUT_DIR`.

import (
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// outRNDualDir is the shared scratch subdir for dual-nonce related-nonce
// probes. Resolved via redteamOutputDir; see that helper for the
// default + env-override contract.
var outRNDualDir = redteamOutputDir("related_nonce_dualnonce")

// emitJSONRNDual writes a compact JSON record. Non-fatal on error.
func emitJSONRNDual(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(outRNDualDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", outRNDualDir, err)
		return
	}
	path := filepath.Join(outRNDualDir, name+".json")
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

// rnDualScenario selects the nonce slot the 1-bit Δ perturbs across the
// compared pair.
type rnDualScenario int

const (
	rnScenarioDual rnDualScenario = iota // both nonces receive Δ
	rnScenarioMain                       // main only receives Δ
	rnScenarioIL                         // interlock only receives Δ
)

func (s rnDualScenario) String() string {
	switch s {
	case rnScenarioDual:
		return "A (dual-slot Δ)"
	case rnScenarioMain:
		return "B (main only Δ)"
	case rnScenarioIL:
		return "C (interlock only Δ)"
	}
	return "unknown"
}

// rnDualCell aggregates one (scenario, primitive, Δ, plaintext) result.
// Fields mirror the historical `rnCell` so downstream aggregators can
// consume both matrices with the same schema.
type rnDualCell struct {
	Scenario         string  `json:"scenario"`
	Primitive        string  `json:"primitive"`
	DeltaKind        string  `json:"delta_kind"`
	DeltaByteIdx     int     `json:"delta_byte_idx"`
	DeltaBitIdx      int     `json:"delta_bit_idx"`
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

// runRelatedNonceDualCell executes one (scenario × primitive × Δ ×
// plaintext) cell.  The base main / interlock nonce pair is
// deterministically derived from the shared `rnBaseNonceSeed` XORed
// with a per-slot stream tag so the two slots start out byte-distinct
// even under Scenarios B / C (where one of the two remains fixed
// across the pair).
func runRelatedNonceDualCell(t *testing.T, scenario rnDualScenario, primName string, hf HashFunc128, dp struct {
	name    string
	byteIdx int
	bitIdx  uint
}, ptKind string, pt []byte, base map[string][]uint64) rnDualCell {
	t.Helper()

	// Distinct base main / interlock nonces (matches shipped
	// generateNoncePairCfg invariant `main != interlock`).
	baseMain := deriveFixedNonceRN(rnBaseNonceSeed ^ 0x1000000000000001)
	baseIL := deriveFixedNonceRN(rnBaseNonceSeed ^ 0x1000000000000002)

	// Δ mask.
	deltaMask := rnNonceDelta(dp.byteIdx, dp.bitIdx)
	variantMain := make([]byte, NonceSize)
	variantIL := make([]byte, NonceSize)
	for i := 0; i < NonceSize; i++ {
		variantMain[i] = baseMain[i]
		variantIL[i] = baseIL[i]
	}
	switch scenario {
	case rnScenarioDual:
		for i := 0; i < NonceSize; i++ {
			variantMain[i] ^= deltaMask[i]
			variantIL[i] ^= deltaMask[i]
		}
	case rnScenarioMain:
		for i := 0; i < NonceSize; i++ {
			variantMain[i] ^= deltaMask[i]
		}
	case rnScenarioIL:
		for i := 0; i < NonceSize; i++ {
			variantIL[i] ^= deltaMask[i]
		}
	}

	seeds := rnBuild8Seeds(t, hf, base)

	// Baseline encrypt — install (baseMain, baseIL) via the dual
	// override helper from redteam_nonce_reuse_dualnonce_test.go.
	setBrokenTestNoncePair(t, baseMain, baseIL)
	ct0, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
	if err != nil {
		t.Fatalf("baseline Encrypt3x128Cfg %s/%s/%s/%s: %v", scenario, primName, dp.name, ptKind, err)
	}

	// Variant encrypt.
	setBrokenTestNoncePair(t, variantMain, variantIL)
	ct1, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
	if err != nil {
		t.Fatalf("variant Encrypt3x128Cfg %s/%s/%s/%s: %v", scenario, primName, dp.name, ptKind, err)
	}

	// Sanity: the collision invariant on the un-Δ'd slot holds on the wire.
	layout0 := decodeWireDualNR(ct0)
	layout1 := decodeWireDualNR(ct1)
	mainCollide := string(layout0.mainNonce) == string(layout1.mainNonce)
	ilCollide := string(layout0.interlockNonce) == string(layout1.interlockNonce)
	switch scenario {
	case rnScenarioDual:
		if mainCollide || ilCollide {
			t.Fatalf("scenarioDual %s/%s/%s: expected both slots perturbed, mainCollide=%v ilCollide=%v", primName, dp.name, ptKind, mainCollide, ilCollide)
		}
	case rnScenarioMain:
		if mainCollide || !ilCollide {
			t.Fatalf("scenarioMain %s/%s/%s: expected main-only Δ, mainCollide=%v ilCollide=%v", primName, dp.name, ptKind, mainCollide, ilCollide)
		}
	case rnScenarioIL:
		if !mainCollide || ilCollide {
			t.Fatalf("scenarioIL %s/%s/%s: expected interlock-only Δ, mainCollide=%v ilCollide=%v", primName, dp.name, ptKind, mainCollide, ilCollide)
		}
	}

	body0 := layout0.body
	body1 := layout1.body
	matched := len(body0) == len(body1)
	diff := xorBytesRN(body0, body1)
	chi2 := byteChi2RS(diff)
	meanAbs, maxAbs := bitBalanceRS(diff)

	return rnDualCell{
		Scenario:         scenario.String(),
		Primitive:        primName,
		DeltaKind:        dp.name,
		DeltaByteIdx:     dp.byteIdx,
		DeltaBitIdx:      int(dp.bitIdx),
		PlaintextKind:    ptKind,
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
}

// TestRedTeamRelatedNonceDualNonceHeadline is a ~15-second smoke that
// probes one Δ pattern (bit_low) × one plaintext kind (random) under
// the three scenarios and one PRF-grade primitive (BLAKE3-128), so
// the REDTEAM.md refresh's headline numbers are reproducible without
// running the full matrix.
func TestRedTeamRelatedNonceDualNonceHeadline(t *testing.T) {
	baseComps := rnBaseComponents(rnBaseNonceSeed)
	hf := makeBlake3Hash128CPA(0xB13A_5AFE_15AF_E5EE)
	// Single Δ pattern + single plaintext for the smoke — 512 KiB matches
	// the historical matrix so numbers line up with `related_nonce_matrix`.
	dp := struct {
		name    string
		byteIdx int
		bitIdx  uint
	}{"bit_low", 0, 0}
	seedVar := uint64(rnBaseNonceSeed)
	pt := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x7A7A5A5A5A5A7A7A))), rnPlaintextBytes, "random")

	scenarios := []rnDualScenario{rnScenarioDual, rnScenarioMain, rnScenarioIL}
	var cells []rnDualCell
	for _, sc := range scenarios {
		cell := runRelatedNonceDualCell(t, sc, "BLAKE3-128", hf, dp, "random", pt, baseComps)
		cells = append(cells, cell)
		t.Logf("Headline BLAKE3-128 %s Δ=%s pt=random: chi2=%12.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d",
			sc, dp.name, cell.Chi2, cell.BitBalMeanAbs, cell.BitBalMaxAbs, cell.BodyBytes)
	}

	emitJSONRNDual(t, "headline_blake3", map[string]any{
		"description":     "Headline chi2 / bit-balance numbers per dual-nonce scenario under PRF-grade BLAKE3-128 with one Δ pattern (bit_low) and one plaintext kind (random).",
		"plaintext_bytes": rnPlaintextBytes,
		"cells":           cells,
	})
}

// TestRedTeamRelatedNonceDualNonceMatrix is the full 3-scenario × 2-
// primitive × 6-Δ × 2-plaintext grid (72 cells) that companions the
// historical joint-Δ matrix in `redteam_related_nonce_test.go`. Emits
// one JSON record with all cells. Wall clock ~10-15 minutes on a modern
// desktop at 512 KiB plaintext × 144 encrypts.
//
// Env-gated by `ITB_RELATED_NONCE_DUALNONCE_MATRIX=1` so the CI/local
// default `go test -tags redteam` run does not incur the full matrix
// cost; the headline smoke above provides the fast reproduction path.
func TestRedTeamRelatedNonceDualNonceMatrix(t *testing.T) {
	if os.Getenv("ITB_RELATED_NONCE_DUALNONCE_MATRIX") != "1" {
		t.Skip("dual-nonce related-nonce matrix: set ITB_RELATED_NONCE_DUALNONCE_MATRIX=1 to enable (72 cells × 512 KiB, ~10-15 min)")
	}
	if testing.Short() {
		t.Skip("dual-nonce related-nonce matrix: skipped under -short")
	}

	baseComps := rnBaseComponents(rnBaseNonceSeed)
	seedVar := uint64(rnBaseNonceSeed)
	ptRandom := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x2A2A555555550001))), rnPlaintextBytes, "random")
	ptAscii := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x15552A2A2A2A0001))), rnPlaintextBytes, "ascii")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}
	plaintextKinds := []string{"random", "ascii"}
	scenarios := []rnDualScenario{rnScenarioDual, rnScenarioMain, rnScenarioIL}

	var cells []rnDualCell
	for _, sc := range scenarios {
		for _, prim := range primitives {
			for _, dp := range rnDeltaPatterns {
				for _, ptk := range plaintextKinds {
					var pt []byte
					if ptk == "random" {
						pt = ptRandom
					} else {
						pt = ptAscii
					}
					cell := runRelatedNonceDualCell(t, sc, prim.name, prim.hf, struct {
						name    string
						byteIdx int
						bitIdx  uint
					}{dp.name, dp.byteIdx, dp.bitIdx}, ptk, pt, baseComps)
					cells = append(cells, cell)
					t.Logf("%s %-6s Δ=%-14s (byte=%2d bit=%d) pt=%-6s chi2=%10.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d match=%v",
						sc, prim.name, dp.name, dp.byteIdx, dp.bitIdx, ptk,
						cell.Chi2, cell.BitBalMeanAbs, cell.BitBalMaxAbs,
						cell.BodyBytes, cell.MatchedContainer)
				}
			}
		}
	}

	// Per-(scenario, primitive) min / mean / max χ² summary — mirrors the
	// historical matrix summary so the two ledgers read the same way.
	type sumKey struct {
		scenario rnDualScenario
		prim     string
	}
	byKey := map[sumKey][]float64{}
	for _, sc := range scenarios {
		for _, prim := range primitives {
			byKey[sumKey{sc, prim.name}] = nil
		}
	}
	for _, c := range cells {
		var sc rnDualScenario
		switch c.Scenario {
		case rnScenarioDual.String():
			sc = rnScenarioDual
		case rnScenarioMain.String():
			sc = rnScenarioMain
		case rnScenarioIL.String():
			sc = rnScenarioIL
		}
		k := sumKey{sc, c.Primitive}
		byKey[k] = append(byKey[k], c.Chi2)
	}
	summary := map[string]any{}
	for k, xs := range byKey {
		if len(xs) == 0 {
			continue
		}
		var mn, mx, sum float64
		mn = xs[0]
		mx = xs[0]
		for _, v := range xs {
			if v < mn {
				mn = v
			}
			if v > mx {
				mx = v
			}
			sum += v
		}
		summary[fmt.Sprintf("%s / %s", k.scenario.String(), k.prim)] = map[string]any{
			"min_chi2":  mn,
			"mean_chi2": sum / float64(len(xs)),
			"max_chi2":  mx,
			"cells":     len(xs),
		}
		t.Logf("SUMMARY %s / %-6s: min=%9.1f mean=%9.1f max=%9.1f (n=%d)",
			k.scenario, k.prim, mn, sum/float64(len(xs)), mx, len(xs))
	}

	emitJSONRNDual(t, "related_nonce_dualnonce_matrix", map[string]any{
		"description":     "Related-nonce 1-bit Δ matrix under three dual-nonce scenarios (A dual-slot, B main-only, C interlock-only) × two primitives × six Δ patterns × two plaintext kinds.",
		"plaintext_bytes": rnPlaintextBytes,
		"key_bits":        rnKeyComponents * 64,
		"nonce_bits":      NonceSize * 8,
		"df255_1sigma":    323.0,
		"cells":           cells,
		"summary":         summary,
	})
}

// TestRedTeamRelatedNonceDualNonceScenarioCScaled re-runs Scenario C
// (interlock-only Δ) at 4× the baseline plaintext size (2 MiB vs 512
// KiB) to test whether the slight χ² excess at 512 KiB (CRC128 max
// 505.8 / FNV-1a max 547.8, above the one-sided 3σ ~323) is a stable
// permutation-boundary artefact or a slowly-growing signal.
//
// Discriminator: if the residue is a fixed permutation-boundary
// contribution, χ² is data-size-independent and stays near the same
// value at 4× data. If a signal channel is present, χ² scales with
// plaintext size and the max moves proportionally to N.
//
// Scenarios A (dual-slot) and B (main-only) collapsed to the one-sided
// 3σ band at the baseline size and are not re-run here — the reviewer
// question is scoped to C. The 6 Δ × 2 primitive × 2 plaintext kind =
// 24 cells matrix is preserved so the max χ² estimator has the same
// quality as the baseline matrix's per-(scenario, primitive) slice.
//
// Env-gated by `ITB_RELATED_NONCE_DUAL_SCENARIO_C_SCALED=1`. Wall clock
// ~15–25 min (24 cells × 2 MiB plaintext × 2 encrypts per cell).
func TestRedTeamRelatedNonceDualNonceScenarioCScaled(t *testing.T) {
	if os.Getenv("ITB_RELATED_NONCE_DUAL_SCENARIO_C_SCALED") != "1" {
		t.Skip("scaled dual-nonce Scenario C: set ITB_RELATED_NONCE_DUAL_SCENARIO_C_SCALED=1 to enable (24 cells × 2 MiB, ~15-25 min)")
	}
	if testing.Short() {
		t.Skip("scaled dual-nonce Scenario C: skipped under -short")
	}

	const scaledPlaintextBytes = 4 * rnPlaintextBytes // 2 MiB

	baseComps := rnBaseComponents(rnBaseNonceSeed)
	seedVar := uint64(rnBaseNonceSeed)
	ptRandom := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x2A2A555555550001))), scaledPlaintextBytes, "random")
	ptAscii := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x15552A2A2A2A0001))), scaledPlaintextBytes, "ascii")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}
	plaintextKinds := []string{"random", "ascii"}

	// Scenario C only — the reviewer question point.
	sc := rnScenarioIL

	var cells []rnDualCell
	for _, prim := range primitives {
		for _, dp := range rnDeltaPatterns {
			for _, ptk := range plaintextKinds {
				var pt []byte
				if ptk == "random" {
					pt = ptRandom
				} else {
					pt = ptAscii
				}
				cell := runRelatedNonceDualCell(t, sc, prim.name, prim.hf, struct {
					name    string
					byteIdx int
					bitIdx  uint
				}{dp.name, dp.byteIdx, dp.bitIdx}, ptk, pt, baseComps)
				cells = append(cells, cell)
				t.Logf("%s %-6s Δ=%-14s (byte=%2d bit=%d) pt=%-6s chi2=%10.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d",
					sc, prim.name, dp.name, dp.byteIdx, dp.bitIdx, ptk,
					cell.Chi2, cell.BitBalMeanAbs, cell.BitBalMaxAbs, cell.BodyBytes)
			}
		}
	}

	// Per-primitive min / mean / max summary — mirrors the baseline
	// matrix's reporting shape so the two ledgers read the same way.
	byPrim := map[string][]float64{}
	for _, c := range cells {
		byPrim[c.Primitive] = append(byPrim[c.Primitive], c.Chi2)
	}
	summary := map[string]any{}
	for prim, xs := range byPrim {
		if len(xs) == 0 {
			continue
		}
		var mn, mx, sum float64
		mn = xs[0]
		mx = xs[0]
		for _, v := range xs {
			if v < mn {
				mn = v
			}
			if v > mx {
				mx = v
			}
			sum += v
		}
		summary[fmt.Sprintf("%s / %s", sc.String(), prim)] = map[string]any{
			"min_chi2":  mn,
			"mean_chi2": sum / float64(len(xs)),
			"max_chi2":  mx,
			"cells":     len(xs),
		}
		t.Logf("SUMMARY %s / %-6s: min=%9.1f mean=%9.1f max=%9.1f (n=%d)",
			sc, prim, mn, sum/float64(len(xs)), mx, len(xs))
	}

	emitJSONRNDual(t, "scenario_c_scaled_matrix", map[string]any{
		"description":         "Scenario C (interlock-only Δ) re-run at 4× baseline plaintext (2 MiB) to test artefact-vs-signal for the +3σ residue.",
		"plaintext_bytes":     scaledPlaintextBytes,
		"baseline_plaintext":  rnPlaintextBytes,
		"scale_factor":        4,
		"key_bits":            rnKeyComponents * 64,
		"nonce_bits":          NonceSize * 8,
		"df255_1sided_3sigma": 323.0,
		"cells":               cells,
		"summary":             summary,
	})
}

// generateLowEntropyPlaintext produces a `two_symbol` plaintext of the
// requested size where each byte is drawn independently and uniformly
// from {0x00, 0xFF}. Per-byte histogram entropy ≈ 1 bit/byte (two
// equiprobable byte values); per-bit balance stays at 0.5 (both symbols
// carry identical 0/1 counts across their eight bit positions), so any
// residue observed cannot be attributed to an artificial bit-level bias
// in the input.
func generateLowEntropyPlaintext(rng *rand.Rand, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		if rng.Intn(2) == 0 {
			out[i] = 0x00
		} else {
			out[i] = 0xFF
		}
	}
	return out
}

// TestRedTeamRelatedNonceDualNonceScenarioCLowEntropy runs Scenario C
// (interlock-only Δ) at 2 MiB across three plaintext-entropy points to
// discriminate whether the sub-linear χ² growth observed on the ASCII
// axis under `TestRedTeamRelatedNonceDualNonceScenarioCScaled` is
// coupled to input-byte distribution or arises from a mechanism
// independent of plaintext entropy.
//
// Three plaintexts of identical size 2 MiB:
//
//   - `random`     — ≈ 8   bits/byte (uniform-over-256 baseline).
//   - `ascii`      — ≈ 4.5 bits/byte (≈ 95 printable values).
//   - `two_symbol` — ≈ 1   bit/byte (bytes drawn independently from
//     {0x00, 0xFF} with p = 0.5).
//
// Ordering test (attacker-realism: statistics on public ciphertext
// bytes only; seed components never consulted in the decision path):
//
//   - coupling model corroborated: χ²(two_symbol) > χ²(ascii) > χ²(random)
//     — residue scales monotone with the inverse of input-byte entropy.
//   - coupling model rejected: χ²(two_symbol) ≤ χ²(ascii) — the
//     mechanism is not input-entropy-coupled and a different attribution
//     is required for the ASCII sub-linear growth.
//
// Matrix: 3 pt × 6 Δ × 2 primitive = 36 cells × 2 MiB × 2 encrypts.
// Wall clock ≈ 7–10 min.
//
// Env-gated by `ITB_RELATED_NONCE_DUAL_SCENARIO_C_LOWENT=1`.
func TestRedTeamRelatedNonceDualNonceScenarioCLowEntropy(t *testing.T) {
	if os.Getenv("ITB_RELATED_NONCE_DUAL_SCENARIO_C_LOWENT") != "1" {
		t.Skip("low-entropy Scenario C: set ITB_RELATED_NONCE_DUAL_SCENARIO_C_LOWENT=1 to enable (36 cells × 2 MiB, ~7-10 min)")
	}
	if testing.Short() {
		t.Skip("low-entropy Scenario C: skipped under -short")
	}

	const plaintextBytes = 4 * rnPlaintextBytes // 2 MiB — matches scaled test size

	baseComps := rnBaseComponents(rnBaseNonceSeed)
	seedVar := uint64(rnBaseNonceSeed)
	ptRandom := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x2A2A555555550001))), plaintextBytes, "random")
	ptAscii := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x15552A2A2A2A0001))), plaintextBytes, "ascii")
	ptTwoSymbol := generateLowEntropyPlaintext(rand.New(rand.NewSource(int64(seedVar^0x7373737373730001))), plaintextBytes)

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}
	ptKinds := []struct {
		name string
		data []byte
	}{
		{"random", ptRandom},
		{"ascii", ptAscii},
		{"two_symbol", ptTwoSymbol},
	}

	// Scenario C only — the reviewer's ordering-test scope.
	sc := rnScenarioIL

	var cells []rnDualCell
	for _, prim := range primitives {
		for _, dp := range rnDeltaPatterns {
			for _, pt := range ptKinds {
				cell := runRelatedNonceDualCell(t, sc, prim.name, prim.hf, struct {
					name    string
					byteIdx int
					bitIdx  uint
				}{dp.name, dp.byteIdx, dp.bitIdx}, pt.name, pt.data, baseComps)
				cells = append(cells, cell)
				t.Logf("%s %-6s Δ=%-14s (byte=%2d bit=%d) pt=%-10s chi2=%10.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d",
					sc, prim.name, dp.name, dp.byteIdx, dp.bitIdx, pt.name,
					cell.Chi2, cell.BitBalMeanAbs, cell.BitBalMaxAbs, cell.BodyBytes)
			}
		}
	}

	// Per-(primitive, pt-kind) min / mean / max — the ordering-test slice.
	type sumKey struct {
		prim string
		ptk  string
	}
	byKey := map[sumKey][]float64{}
	for _, c := range cells {
		byKey[sumKey{c.Primitive, c.PlaintextKind}] = append(byKey[sumKey{c.Primitive, c.PlaintextKind}], c.Chi2)
	}
	summary := map[string]any{}
	for _, prim := range primitives {
		for _, pt := range ptKinds {
			k := sumKey{prim.name, pt.name}
			xs := byKey[k]
			if len(xs) == 0 {
				continue
			}
			var mn, mx, sum float64
			mn = xs[0]
			mx = xs[0]
			for _, v := range xs {
				if v < mn {
					mn = v
				}
				if v > mx {
					mx = v
				}
				sum += v
			}
			summary[fmt.Sprintf("%s / %s / %s", sc.String(), prim.name, pt.name)] = map[string]any{
				"min_chi2":  mn,
				"mean_chi2": sum / float64(len(xs)),
				"max_chi2":  mx,
				"cells":     len(xs),
			}
			t.Logf("SUMMARY %s / %-6s / %-10s: min=%9.1f mean=%9.1f max=%9.1f (n=%d)",
				sc, prim.name, pt.name, mn, sum/float64(len(xs)), mx, len(xs))
		}
	}

	emitJSONRNDual(t, "scenario_c_low_entropy_matrix", map[string]any{
		"description":           "Scenario C (interlock-only Δ) at 2 MiB across three plaintext-entropy points (random ≈ 8 bits/byte, ascii ≈ 4.5, two_symbol ≈ 1) to discriminate input-entropy coupling from entropy-independent mechanisms.",
		"plaintext_bytes":       plaintextBytes,
		"entropy_bits_per_byte": map[string]float64{"random": 8.0, "ascii": 4.5, "two_symbol": 1.0},
		"key_bits":              rnKeyComponents * 64,
		"nonce_bits":            NonceSize * 8,
		"df255_1sided_3sigma":   323.0,
		"cells":                 cells,
		"summary":               summary,
	})
}

// TestRedTeamRelatedNonceDualNonceScenarioCTwoSymbolRecovery directly
// measures per-byte plaintext recovery under Scenario C (interlock-only
// Δ) with `two_symbol` plaintext. The scaled + low-entropy probes above
// showed that the diff bit-balance lifts to ≈ 0.22–0.27 under
// `two_symbol` pt (vs ≈ 0.004 on realistic pt). The elevated
// bit-balance is a distributional artefact of the plaintext's per-byte
// extremity; this probe verifies directly that it does not translate
// to a per-byte plaintext-recovery channel — the reviewer's honest gap
// between "distributional deviation" and "recovery = 0/N".
//
// Attacker setup (attacker-realism: statistics on public ciphertext
// bytes only; seed components never consulted in the decision path):
//
//   - N independent trials with a fresh 8-seed bundle drawn per trial
//     from an independent nonce-seed stream.
//   - Fresh `two_symbol` plaintext per trial (bytes drawn independently
//     from {0x00, 0xFF} with p = 0.5).
//   - Encrypted twice under a Scenario C pair: `main_nonce` fixed,
//     `interlock_nonce` differs by a 1-bit Δ. Attacker sees the two
//     wire body byte streams (ct0_body, ct1_body).
//   - Attacker knows pt is `two_symbol` and attempts to guess each
//     pt byte position via one of four naive attacker-realistic
//     decoders. The attacker does not know the mask permutation, so
//     position-specific decoders fall back to the identity pt-byte-
//     position → wire-byte-position mapping (the naive default).
//
// Decoders tested (each a total function of the observed wire bytes,
// producing a byte guess in {0x00, 0xFF}):
//
//	D0 — constant 0x00. Baseline; yields 0.500 exactly under uniform
//	     two_symbol (half of pt bytes are 0x00 by construction).
//	D1 — high-bit threshold on ct0_body[i]:
//	     guess = 0x00 if (ct0_body[i] & 0x80) == 0 else 0xFF.
//	D2 — high-bit threshold on ct0_body[i] XOR ct1_body[i]:
//	     guess = 0x00 if ((ct0[i] ^ ct1[i]) & 0x80) == 0 else 0xFF.
//	D3 — popcount threshold on ct0_body[i]:
//	     guess = 0x00 if popcount(ct0[i]) < 4 else 0xFF.
//
// Per-decoder success rate is `correct guesses / total guesses` across
// all trials × all pt byte positions. Under a null channel each
// decoder yields 0.500 ± 3 × sqrt(0.25 / total). At N = 2000 trials ×
// 512 pt bytes the total is 1024000 guesses per decoder and the 3σ
// null bound is ≈ 0.5015. Any decoder exceeding this bound raises the
// test as a fail — the reviewer's closure condition ("recovery = 0/N
// verified") holds when every tested decoder sits below the bound.
//
// Env-gated by `ITB_RELATED_NONCE_DUAL_SCENARIO_C_LOWENT_RECOVERY=1`.
// Wall clock ≈ 30–60 s.
func TestRedTeamRelatedNonceDualNonceScenarioCTwoSymbolRecovery(t *testing.T) {
	if os.Getenv("ITB_RELATED_NONCE_DUAL_SCENARIO_C_LOWENT_RECOVERY") != "1" {
		t.Skip("two_symbol recovery probe: set ITB_RELATED_NONCE_DUAL_SCENARIO_C_LOWENT_RECOVERY=1 to enable (~30-60 s)")
	}
	if testing.Short() {
		t.Skip("two_symbol recovery probe: skipped under -short")
	}

	const (
		Ntrials = 2000
		ptBytes = 512
	)

	hf := crc128BrokenLab

	baseMain := deriveFixedNonceRN(rnBaseNonceSeed ^ 0x1000000000000001)
	baseIL := deriveFixedNonceRN(rnBaseNonceSeed ^ 0x1000000000000002)
	deltaMask := rnNonceDelta(0, 0) // bit_low Δ on interlock nonce byte 0 bit 0
	variantIL := make([]byte, NonceSize)
	for i := 0; i < NonceSize; i++ {
		variantIL[i] = baseIL[i] ^ deltaMask[i]
	}

	var totalGuesses int64
	var d0Correct, d1Correct, d2Correct, d3Correct int64

	for trial := 0; trial < Ntrials; trial++ {
		// Fresh 8-seed bundle per trial via an independent nonce-seed stream.
		trialSeed := rnBaseNonceSeed ^ (0xDA7ABE05C0DE0000 + uint64(trial))
		baseComps := rnBaseComponents(trialSeed)
		seeds := rnBuild8Seeds(t, hf, baseComps)

		// Fresh two_symbol pt per trial.
		rng := rand.New(rand.NewSource(int64(0xC0DEBEEF7A5A0000 + uint64(trial))))
		pt := generateLowEntropyPlaintext(rng, ptBytes)

		// Baseline encrypt (baseMain, baseIL).
		setBrokenTestNoncePair(t, baseMain, baseIL)
		ct0, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
		if err != nil {
			t.Fatalf("baseline encrypt trial %d: %v", trial, err)
		}

		// Variant encrypt (baseMain, variantIL) — Scenario C interlock-only Δ.
		setBrokenTestNoncePair(t, baseMain, variantIL)
		ct1, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
		if err != nil {
			t.Fatalf("variant encrypt trial %d: %v", trial, err)
		}

		body0 := decodeWireDualNR(ct0).body
		body1 := decodeWireDualNR(ct1).body

		for i := 0; i < len(pt); i++ {
			actual := pt[i]

			// D0 — constant 0x00.
			if actual == 0x00 {
				d0Correct++
			}

			// D1 / D3 — decoders on ct0_body[i].
			if i < len(body0) {
				b := body0[i]
				var g1, g3 byte
				if b&0x80 == 0 {
					g1 = 0x00
				} else {
					g1 = 0xFF
				}
				if bits.OnesCount8(b) < 4 {
					g3 = 0x00
				} else {
					g3 = 0xFF
				}
				if g1 == actual {
					d1Correct++
				}
				if g3 == actual {
					d3Correct++
				}
			}

			// D2 — decoder on (ct0_body[i] XOR ct1_body[i]).
			if i < len(body0) && i < len(body1) {
				d := body0[i] ^ body1[i]
				var g2 byte
				if d&0x80 == 0 {
					g2 = 0x00
				} else {
					g2 = 0xFF
				}
				if g2 == actual {
					d2Correct++
				}
			}

			totalGuesses++
		}
	}

	if totalGuesses == 0 {
		t.Fatalf("no guesses recorded")
	}

	tg := float64(totalGuesses)
	d0Rate := float64(d0Correct) / tg
	d1Rate := float64(d1Correct) / tg
	d2Rate := float64(d2Correct) / tg
	d3Rate := float64(d3Correct) / tg

	sigmaPer := math.Sqrt(0.25 / tg)
	upper3 := 0.5 + 3*sigmaPer

	t.Logf("Total per-decoder guesses: %d (N=%d trials × %d pt bytes)", totalGuesses, Ntrials, ptBytes)
	t.Logf("Per-guess sigma under null: %.6f; 3-sigma null bound: %.6f", sigmaPer, upper3)
	t.Logf("D0 constant 0x00                    : %.6f", d0Rate)
	t.Logf("D1 high-bit(ct0[i])                 : %.6f (bound %.6f)", d1Rate, upper3)
	t.Logf("D2 high-bit(ct0[i] XOR ct1[i])      : %.6f (bound %.6f)", d2Rate, upper3)
	t.Logf("D3 popcount(ct0[i]) < 4             : %.6f (bound %.6f)", d3Rate, upper3)

	fail := false
	if d1Rate > upper3 {
		t.Errorf("D1 high-bit(ct0[i]) recovery %.6f exceeds 3-sigma null bound %.6f", d1Rate, upper3)
		fail = true
	}
	if d2Rate > upper3 {
		t.Errorf("D2 high-bit(diff[i]) recovery %.6f exceeds 3-sigma null bound %.6f", d2Rate, upper3)
		fail = true
	}
	if d3Rate > upper3 {
		t.Errorf("D3 popcount(ct0[i]) recovery %.6f exceeds 3-sigma null bound %.6f", d3Rate, upper3)
		fail = true
	}

	if !fail {
		t.Logf("All decoders within 3-sigma null bound: pt-byte recovery = 0/%d over the tested decoder family verified.", totalGuesses)
	}

	emitJSONRNDual(t, "scenario_c_two_symbol_recovery", map[string]any{
		"description":       "Direct per-byte plaintext-recovery probe under Scenario C + two_symbol pt: four naive attacker decoders vs uniform-random baseline. Closes the gap between distributional bit-balance ≈ 0.22–0.27 under two_symbol and per-byte recovery.",
		"trials":            Ntrials,
		"pt_bytes":          ptBytes,
		"total_guesses":     totalGuesses,
		"sigma_per_guess":   sigmaPer,
		"null_3sigma_bound": upper3,
		"primitive":         "CRC128",
		"delta_pattern":     "bit_low (interlock nonce byte 0 bit 0)",
		"d0_constant_0x00":  d0Rate,
		"d1_highbit_ct0":    d1Rate,
		"d2_highbit_diff":   d2Rate,
		"d3_popcount_ct0":   d3Rate,
	})
}
