//go:build redteam

package itb

// Related-nonce differential re-verification under the v0.3.0 dual-nonce
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
// Attacker-realism (CLAUDE.md discipline): all statistics operate on
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
// (per CLAUDE.md working-tree layout). Override the parent directory
// via `REDTEAM_RELATED_NONCE_DUALNONCE_OUTPUT_DIR`.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// tmpRNDualDir is the shared scratch subdir for dual-nonce related-nonce
// probes. Resolved via redteamOutputDir; see that helper for the
// default + env-override contract.
var tmpRNDualDir = redteamOutputDir("related_nonce_dualnonce")

// emitJSONRNDual writes a compact JSON record. Non-fatal on error.
func emitJSONRNDual(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpRNDualDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpRNDualDir, err)
		return
	}
	path := filepath.Join(tmpRNDualDir, name+".json")
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
