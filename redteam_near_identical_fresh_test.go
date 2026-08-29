//go:build redteam

package itb

// Fresh-nonce cross-message near-identical distinguisher re-verification
// against the v0.3.0 architecture (always-on 48-bit Interlocked Barrier +
// Triple Ouroboros + 8 mandatory seeds) with FNV-1a keyed onto every
// one of the 8 mandatory seed roles. Companion to
// `redteam_cpa_broken_test.go`; extends the fresh-nonce broken-primitive
// scaffolding from a single-message wire-distinguisher posture to a
// cross-message pair-distinguisher posture.
//
// Threat model. Attacker capability is shipped-API chosen-plaintext:
// the attacker holds an encryption oracle and can submit any plaintext
// they choose, and each call draws a fresh nonce from `crypto/rand`
// (the shipped `generateNonceCfg` path — no `testNonceOverride` is
// installed in this file). The attacker submits pairs `(P1, P2)` where
// `P2 = P1 XOR delta` for a chosen bit-position delta (or `P1', P2'`
// independent random as the control), receives `(C1, C2)`, and tries
// to distinguish "near-identical plaintexts encrypted under distinct
// fresh nonces" from "independent plaintexts encrypted under distinct
// fresh nonces". If the wire byte-histogram of the near-identical pair
// differs statistically from the independent-pair aggregate, the
// attacker gains a traffic-analysis distinguisher — knowing "these two
// wires came from very-similar underlying messages" is a real leak
// even if the plaintext bytes stay hidden. Under nonce reuse the
// `redteam_nonce_reuse_test.go` Layer A probe records a byte-equal
// rate of ~16× the 1/256 floor at 512 B on the near-identical pair
// shape; this probe measures the same shape under fresh nonces to
// isolate the "the mandatory internal nonce alone closes the
// traffic-analysis residue" claim from the "nonce reuse remains the
// only condition surfacing any signal" claim.
//
// Measurement surface. For each (plaintext size, delta position,
// category) cell the probe:
//
//   1. Samples N pairs `(P1, P2)` — near-identical (`P2 = P1 XOR
//      delta_mask`) or independent-random control.
//   2. Encrypts each side under an independent fresh CSPRNG nonce via
//      `Encrypt3x128Cfg` with the same 8 FNV-1a-keyed seeds.
//   3. Accumulates the pooled 256-bin byte-histogram of `body(C1) XOR
//      body(C2)` and counts byte-equal positions.
//   4. Computes:
//        - per-cell byte-XOR chi² vs df=255 uniform
//        - per-cell byte-equal rate vs the 1/256 independent-stream floor
//        - two-sample homogeneity chi² between the near-identical cell
//          and the independent-pair control at the same size and delta
//          position (df=255)
//
// Wall-clock. Default N = 80 pairs per cell → 4 sizes × 6 delta positions
// × 2 categories = 48 cells × 2 × 80 = 7680 encryptions. Encrypt3x128Cfg
// parallelises across `runtime.NumCPU()`; typical wall clock is under
// five minutes on an 8-core host. Override via `ITB_NIF_N`.
//
// Attacker-realism (CLAUDE.md discipline).
//   - Every ingested byte is a public wire byte reachable by any
//     observer with a copy of the two ciphertexts. The chi² and
//     byte-equal statistics are inherently attacker-visible.
//   - No seed / nonce / mask / rotation / noise-position value is read
//     in any decision path. The 8-seed component vectors are drawn from
//     a deterministic PRNG for reproducibility; the values themselves
//     are not consulted after the seeds are constructed.
//   - The plaintexts themselves are attacker-chosen (the delta is the
//     attacker's own probe). No lab-only peek is invoked.
//
// Emission. `tmp/redteam/near_identical_fresh/<name>.json` (repo-
// gitignored) for downstream aggregation.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// tmpNIFDir is the shared scratch subdir all near-identical-fresh probes
// below emit into. Relative to the package directory.
const tmpNIFDir = "tmp/redteam/near_identical_fresh"

// nifKeyComponents keeps the 1024-bit key width the related-seed /
// related-nonce / CPA probes settled on so container geometry and
// PRF-scaffold coverage stay comparable across the broken-primitive
// track.
const nifKeyComponents = 16

// nifDefaultN is the sample size per (size, delta, category) cell when
// the `ITB_NIF_N` env override is unset. Chosen large enough that the
// pooled body-XOR byte histogram carries ≥ 30 000 samples per bin at
// the smallest tested plaintext size (128 B → container body ≈ 2900 B →
// N = 80 pooled body-XOR bytes ≈ 232 000 → ~ 907 per bin).
const nifDefaultN = 80

// nifBaseSeed is the deterministic seed for the 8 seed-component
// vectors. Disjoint from the CPA / related-seed / related-nonce probe
// base seeds so ledgers do not accidentally share fixture material.
const nifBaseSeed uint64 = 0xF1F1F1F1A5A5A5A5

// emitJSONNIF writes a compact JSON record under
// `tmpNIFDir/<name>.json` for downstream aggregation. Errors are
// logged, not fatal.
func emitJSONNIF(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpNIFDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpNIFDir, err)
		return
	}
	path := filepath.Join(tmpNIFDir, name+".json")
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

// nifStreamTags is the disjoint per-axis PRNG stream tag so baseline
// components for each of the 8 seeds are independent but reproducible.
// Tags are chosen distinct from `cpaStreamTags` / `rsStreamTags` /
// `rnBaseComponents`'s tags so seed values do not overlap across
// ledgers.
var nifStreamTags = map[string]uint64{
	"noiseSeed":  0xF10000000000A001,
	"lockSeed":   0xF10000000000A002,
	"dataSeed1":  0xF10000000000A003,
	"dataSeed2":  0xF10000000000A004,
	"dataSeed3":  0xF10000000000A005,
	"startSeed1": 0xF10000000000A006,
	"startSeed2": 0xF10000000000A007,
	"startSeed3": 0xF10000000000A008,
}

// nifDrawComponents pulls n uint64s from a deterministic PRNG stream
// keyed by (nifBaseSeed, streamTag).
func nifDrawComponents(streamTag uint64, n int) []uint64 {
	rng := rand.New(rand.NewSource(int64(nifBaseSeed ^ streamTag)))
	out := make([]uint64, n)
	for i := range out {
		out[i] = rng.Uint64()
	}
	return out
}

// nifBuild8Seeds constructs the 8 mandatory Seed128 handles under
// primitive `hf` keyed by disjoint deterministic PRNG streams.
// `Encrypt3x128Cfg` rejects seed pointer collisions; each role
// receives a unique component vector.
func nifBuild8Seeds(t *testing.T, hf HashFunc128) [8]*Seed128 {
	t.Helper()
	tags := []string{
		"noiseSeed", "lockSeed",
		"dataSeed1", "dataSeed2", "dataSeed3",
		"startSeed1", "startSeed2", "startSeed3",
	}
	var out [8]*Seed128
	for i, tag := range tags {
		comps := nifDrawComponents(nifStreamTags[tag], nifKeyComponents)
		s, err := SeedFromComponents128(hf, comps...)
		if err != nil {
			t.Fatalf("SeedFromComponents128 %s: %v", tag, err)
		}
		out[i] = s
	}
	return out
}

// bodyOfCTNIF slices the ciphertext body out of a v0.3.0 wire (nonce +
// dimension header dropped). Layout: main_nonce (NonceSize) ||
// interlock_nonce (NonceSize) || W(2 BE) || H(2 BE) || W*H*Channels
// body bytes.
func bodyOfCTNIF(ct []byte) []byte {
	header := 2*NonceSize + 4
	w := int(binary.BigEndian.Uint16(ct[2*NonceSize : 2*NonceSize+2]))
	h := int(binary.BigEndian.Uint16(ct[2*NonceSize+2 : 2*NonceSize+4]))
	total := w * h
	return ct[header : header+total*Channels]
}

// xorInto stores `a XOR b` into `dst`. `dst`, `a`, `b` must all share
// the same length. Returns the number of positions where `a[i] == b[i]`
// (i.e. `dst[i] == 0x00`), so the caller does not walk the buffer twice.
func xorInto(dst, a, b []byte) int {
	n := len(a)
	eq := 0
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
		if dst[i] == 0 {
			eq++
		}
	}
	return eq
}

// ---------------------------------------------------------------------------
// Delta position generators. Each returns a byte-index / bit-mask pair
// that flips one or a few bits in a plaintext of the given size. The
// spread generator flips 4 bits distributed across the payload; the
// single-bit generators flip one bit at the named position. All bit
// selections are attacker-chosen (public strategy) so the plaintext
// pair reads as an attacker-realistic near-identical probe.
// ---------------------------------------------------------------------------

// nifDeltaSpec bundles a delta position's name with a function that
// returns the byte-XOR mask (same length as the plaintext) that
// transforms `P1` into `P2 = P1 XOR mask`.
type nifDeltaSpec struct {
	name string
	mask func(size int) []byte
}

func nifDeltaByte0Bit0(size int) []byte {
	m := make([]byte, size)
	if size > 0 {
		m[0] = 1 << 0
	}
	return m
}

func nifDeltaByte0Bit7(size int) []byte {
	m := make([]byte, size)
	if size > 0 {
		m[0] = 1 << 7
	}
	return m
}

func nifDeltaMidBit3(size int) []byte {
	m := make([]byte, size)
	if size > 0 {
		m[size/2] = 1 << 3
	}
	return m
}

func nifDeltaEndBit0(size int) []byte {
	m := make([]byte, size)
	if size > 0 {
		m[size-1] = 1 << 0
	}
	return m
}

func nifDeltaEndBit7(size int) []byte {
	m := make([]byte, size)
	if size > 0 {
		m[size-1] = 1 << 7
	}
	return m
}

// nifDeltaSpreadHW4 flips 4 bits distributed across the plaintext:
// byte 0 bit 0, byte size/4 bit 2, byte size/2 bit 5, byte 3*size/4
// bit 7. Simulates a multi-bit attacker delta rather than a single
// bit-flip.
func nifDeltaSpreadHW4(size int) []byte {
	m := make([]byte, size)
	if size == 0 {
		return m
	}
	m[0] |= 1 << 0
	if size >= 4 {
		m[size/4] |= 1 << 2
	}
	if size >= 2 {
		m[size/2] |= 1 << 5
	}
	if size >= 4 {
		m[3*size/4] |= 1 << 7
	}
	return m
}

var nifDeltaSpecs = []nifDeltaSpec{
	{"byte0_bit0", nifDeltaByte0Bit0},
	{"byte0_bit7", nifDeltaByte0Bit7},
	{"mid_bit3", nifDeltaMidBit3},
	{"end_bit0", nifDeltaEndBit0},
	{"end_bit7", nifDeltaEndBit7},
	{"spread_hw4", nifDeltaSpreadHW4},
}

// ---------------------------------------------------------------------------
// Statistical helpers. Named `*NIF` to keep this file's namespace
// self-contained; the `*CPA` and `*NR` variants in sibling files
// implement the same formulas over their own data flow.
// ---------------------------------------------------------------------------

// addToHistNIF adds `data`'s byte counts to `hist` (256 bins).
func addToHistNIF(hist []int, data []byte) {
	for _, b := range data {
		hist[b]++
	}
}

// chi2UniformNIF computes Pearson chi² of `hist` (256 bins, total
// observations `total`) against a uniform expectation. df = 255;
// one-sided 3σ upper bound of χ²(df=255) ≈ 323.
func chi2UniformNIF(hist []int, total int) float64 {
	if total == 0 {
		return 0
	}
	exp := float64(total) / 256.0
	var chi2 float64
	for i := 0; i < 256; i++ {
		d := float64(hist[i]) - exp
		chi2 += (d * d) / exp
	}
	return chi2
}

// chi2HomogeneityNIF computes the two-sample chi² homogeneity statistic
// between two 256-bin histograms with totals `totalA`, `totalB`. df =
// 255. Under H0 (both samples drawn from the same underlying
// distribution) the statistic follows χ²(df=255): mean 255, variance
// 510, one-sided 3σ upper bound ≈ 323. A value outside the uniform band
// signals distributional distinguishability at the tested sample size.
func chi2HomogeneityNIF(a, b []int, totalA, totalB int) float64 {
	if totalA == 0 || totalB == 0 {
		return 0
	}
	N := float64(totalA + totalB)
	fA := float64(totalA)
	fB := float64(totalB)
	var chi2 float64
	for i := 0; i < 256; i++ {
		row := float64(a[i] + b[i])
		if row == 0 {
			continue
		}
		expA := row * fA / N
		expB := row * fB / N
		if expA > 0 {
			d := float64(a[i]) - expA
			chi2 += (d * d) / expA
		}
		if expB > 0 {
			d := float64(b[i]) - expB
			chi2 += (d * d) / expB
		}
	}
	return chi2
}

// resolveNIFSampleSize honours the `ITB_NIF_N` env override.
func resolveNIFSampleSize() int {
	if v := os.Getenv("ITB_NIF_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return nifDefaultN
}

// ---------------------------------------------------------------------------
// nifCell / nifRun JSON schemas.
// ---------------------------------------------------------------------------

type nifCell struct {
	Size            int     `json:"plaintext_size"`
	Delta           string  `json:"delta_position"`
	Category        string  `json:"category"`
	SampleN         int     `json:"sample_pairs"`
	PooledBodyBytes int     `json:"pooled_body_xor_bytes"`
	ByteEqualCount  int     `json:"byte_equal_count"`
	ByteEqualRate   float64 `json:"byte_equal_rate"`
	IndepFloor      float64 `json:"indep_floor_1_over_256"`
	FloorRatio      float64 `json:"vs_1_over_256_floor"`
	Chi2UniformDF   int     `json:"chi2_uniform_df"`
	Chi2Uniform     float64 `json:"chi2_uniform_body_xor"`
}

type nifHomogRow struct {
	Size           int     `json:"plaintext_size"`
	Delta          string  `json:"delta_position"`
	SampleN        int     `json:"sample_pairs"`
	Chi2Homog      float64 `json:"chi2_homogeneity_near_id_vs_indep"`
	Chi2DF         int     `json:"chi2_df"`
	UniformBandTop float64 `json:"uniform_band_3sigma_top"`
	Verdict        string  `json:"verdict"`
}

type nifRun struct {
	Config struct {
		KeyBits         int      `json:"key_bits"`
		Primitive       string   `json:"primitive"`
		Sizes           []int    `json:"sizes"`
		Deltas          []string `json:"delta_positions"`
		Categories      []string `json:"categories"`
		SampleN         int      `json:"sample_pairs_per_cell"`
		CipherEntry     string   `json:"cipher_entry"`
		NoncePolicy     string   `json:"nonce_policy"`
		AttackerPosture string   `json:"attacker_posture"`
		WirePath        string   `json:"wire_path"`
	} `json:"config"`
	Cells       []nifCell     `json:"cells"`
	Homogeneity []nifHomogRow `json:"homogeneity"`
	Baseline    struct {
		Kind                       string  `json:"kind"`
		Source                     string  `json:"source"`
		NonceReuseNearIdenticalBER float64 `json:"nonce_reuse_near_id_byte_equal_rate_at_512B"`
		NonceReuseFloorRatio       float64 `json:"nonce_reuse_floor_ratio_at_512B"`
		NoteFreshVsReuse           string  `json:"note_fresh_vs_reuse"`
	} `json:"baseline"`
}

// ---------------------------------------------------------------------------
// TestRedTeamNearIdenticalFreshNonce — the load-bearing cross-message
// pair-distinguisher probe.
//
// For each (plaintext size, delta position, category) cell: sample N
// pairs, encrypt each side under an independent fresh CSPRNG nonce,
// accumulate the pooled `body(C1) XOR body(C2)` byte histogram and the
// byte-equal count. Compute per-cell body-XOR chi² vs df=255 uniform
// and per-cell byte-equal rate vs the 1/256 floor. Per (size, delta),
// compute the two-sample homogeneity chi² between the near-identical
// cell and the independent-pair control. A homogeneity chi² inside the
// df=255 uniform band means the near-identical pair's wire is
// indistinguishable from the independent-pair wire at the tested
// sample size — i.e. the fresh-nonce mandatory nonce alone closes the
// traffic-analysis distinguisher the nonce-reuse Layer A probe records
// at ≈16× the 1/256 floor on the same pair shape.
// ---------------------------------------------------------------------------

func TestRedTeamNearIdenticalFreshNonce(t *testing.T) {
	if testing.Short() {
		t.Skip("Near-identical-fresh matrix: skipped under -short")
	}

	sampleN := resolveNIFSampleSize()

	sizes := []int{128, 512, 4096, 16384}
	categories := []string{"near_identical", "independent_control"}

	// Single primitive arm — the below-spec FNV-1a hypothesis. The
	// PRF-grade reference arm is architecturally covered by the CPA
	// probe's homogeneity finding (FNV-1a↔BLAKE3 in-band on every
	// chosen-plaintext kind); reproducing it under the pair-shape
	// here would multiply wall-clock without a distinct closure
	// argument. The load-bearing observable is the CROSS-CATEGORY
	// homogeneity chi² between near-identical and independent pairs
	// at the same primitive arm.
	seeds := nifBuild8Seeds(t, fnv1a128BrokenLab)

	run := nifRun{}
	run.Config.KeyBits = nifKeyComponents * 64
	run.Config.Primitive = "FNV-1a (fnv1a128BrokenLab on every seed role)"
	run.Config.Sizes = sizes
	for _, d := range nifDeltaSpecs {
		run.Config.Deltas = append(run.Config.Deltas, d.name)
	}
	run.Config.Categories = categories
	run.Config.SampleN = sampleN
	run.Config.CipherEntry = "Encrypt3x128Cfg"
	run.Config.NoncePolicy = "fresh CSPRNG per Encrypt call (generateNonceCfg, testNonceOverride NOT installed)"
	run.Config.AttackerPosture = "chosen-plaintext near-identical pair, fresh nonces per call; attacker submits P1 and P2 = P1 XOR delta_mask, oracle draws distinct fresh nonces"
	run.Config.WirePath = "container body (nonce + W + H dimension header dropped) XOR-aligned per pair"

	// Per-plaintext-size PRNG for the base plaintexts. Deterministic
	// so a re-run reproduces the same sample corpus. Runtime uint64
	// -> int64 cast: the compile-time overflow check on a const XOR
	// of two 64-bit values does not permit a direct int64 literal
	// cast when the top bit is set; a variable-typed uint64 first
	// converts freely at runtime.
	seedVar := uint64(nifBaseSeed) ^ uint64(0x2718281828459045)
	rngBase := rand.New(rand.NewSource(int64(seedVar)))

	// Aggregate structures: hists per (size, delta, category) so the
	// homogeneity pass has direct access after the sampling loop.
	type cellKey struct {
		size  int
		delta string
	}
	nearHists := map[cellKey][]int{}
	indepHists := map[cellKey][]int{}
	nearTotals := map[cellKey]int{}
	indepTotals := map[cellKey]int{}

	for _, size := range sizes {
		for _, dspec := range nifDeltaSpecs {
			deltaMask := dspec.mask(size)

			for _, cat := range categories {
				hist := make([]int, 256)
				var pooled int
				byteEq := 0

				for i := 0; i < sampleN; i++ {
					p1 := make([]byte, size)
					p2 := make([]byte, size)
					rngBase.Read(p1)
					switch cat {
					case "near_identical":
						copy(p2, p1)
						for j := range p2 {
							p2[j] ^= deltaMask[j]
						}
					case "independent_control":
						rngBase.Read(p2)
					}
					c1, err := Encrypt3x128Cfg(nil,
						seeds[0], seeds[1], seeds[2], seeds[3], seeds[4],
						seeds[5], seeds[6], seeds[7], p1)
					if err != nil {
						t.Fatalf("Encrypt3x128Cfg %d/%s/%s p1 iter=%d: %v", size, dspec.name, cat, i, err)
					}
					c2, err := Encrypt3x128Cfg(nil,
						seeds[0], seeds[1], seeds[2], seeds[3], seeds[4],
						seeds[5], seeds[6], seeds[7], p2)
					if err != nil {
						t.Fatalf("Encrypt3x128Cfg %d/%s/%s p2 iter=%d: %v", size, dspec.name, cat, i, err)
					}
					b1 := bodyOfCTNIF(c1)
					b2 := bodyOfCTNIF(c2)
					if len(b1) != len(b2) {
						// The container geometry is deterministic in the
						// plaintext length, so bodies must match for
						// same-size P1/P2. A mismatch would be a wire
						// invariant violation.
						t.Fatalf("body length mismatch %d/%s/%s iter=%d: %d != %d",
							size, dspec.name, cat, i, len(b1), len(b2))
					}
					xor := make([]byte, len(b1))
					eq := xorInto(xor, b1, b2)
					byteEq += eq
					addToHistNIF(hist, xor)
					pooled += len(xor)
				}

				const indepFloor = 1.0 / 256.0
				byteEqRate := float64(byteEq) / float64(pooled)
				chi2 := chi2UniformNIF(hist, pooled)
				floorRatio := byteEqRate / indepFloor

				cell := nifCell{
					Size:            size,
					Delta:           dspec.name,
					Category:        cat,
					SampleN:         sampleN,
					PooledBodyBytes: pooled,
					ByteEqualCount:  byteEq,
					ByteEqualRate:   byteEqRate,
					IndepFloor:      indepFloor,
					FloorRatio:      floorRatio,
					Chi2UniformDF:   255,
					Chi2Uniform:     chi2,
				}
				run.Cells = append(run.Cells, cell)

				key := cellKey{size, dspec.name}
				if cat == "near_identical" {
					nearHists[key] = hist
					nearTotals[key] = pooled
				} else {
					indepHists[key] = hist
					indepTotals[key] = pooled
				}

				t.Logf("size=%5d delta=%-10s cat=%-19s N=%d pooled=%d body_xor_chi2=%9.1f byte_eq_rate=%.5f (%.2fx floor)",
					size, dspec.name, cat, sampleN, pooled, chi2, byteEqRate, floorRatio)
			}
		}
	}

	// Two-sample homogeneity between near-identical and independent
	// aggregates at every (size, delta). df = 255; one-sided 3σ upper
	// bound ≈ 323.
	const bandTop = 323.0
	for _, size := range sizes {
		for _, dspec := range nifDeltaSpecs {
			key := cellKey{size, dspec.name}
			hA := nearHists[key]
			hB := indepHists[key]
			nA := nearTotals[key]
			nB := indepTotals[key]
			chi2 := chi2HomogeneityNIF(hA, hB, nA, nB)
			verdict := "in df=255 uniform band"
			if chi2 > bandTop {
				verdict = "outside uniform band — distinguishable at tested sample size"
			}
			run.Homogeneity = append(run.Homogeneity, nifHomogRow{
				Size:           size,
				Delta:          dspec.name,
				SampleN:        sampleN,
				Chi2Homog:      chi2,
				Chi2DF:         255,
				UniformBandTop: bandTop,
				Verdict:        verdict,
			})
			t.Logf("HOMOG size=%5d delta=%-10s N=%d chi2=%8.2f (band top %.0f) verdict=%s",
				size, dspec.name, sampleN, chi2, bandTop, verdict)
		}
	}

	// Cross-cell summary: max homogeneity chi² across the matrix,
	// max byte-equal-rate excess over floor per category.
	var maxHomog float64
	var maxHomogSize int
	var maxHomogDelta string
	for _, row := range run.Homogeneity {
		if row.Chi2Homog > maxHomog {
			maxHomog = row.Chi2Homog
			maxHomogSize = row.Size
			maxHomogDelta = row.Delta
		}
	}
	var maxFloorRatioNI float64
	var maxFloorRatioNISize int
	var maxFloorRatioNIDelta string
	var maxFloorRatioIndep float64
	for _, c := range run.Cells {
		if c.Category == "near_identical" && c.FloorRatio > maxFloorRatioNI {
			maxFloorRatioNI = c.FloorRatio
			maxFloorRatioNISize = c.Size
			maxFloorRatioNIDelta = c.Delta
		}
		if c.Category == "independent_control" && c.FloorRatio > maxFloorRatioIndep {
			maxFloorRatioIndep = c.FloorRatio
		}
	}
	t.Logf("SUMMARY max cross-category chi²=%.2f at size=%d delta=%s (band top 323)",
		maxHomog, maxHomogSize, maxHomogDelta)
	t.Logf("SUMMARY max near_identical byte-equal floor ratio=%.3fx at size=%d delta=%s",
		maxFloorRatioNI, maxFloorRatioNISize, maxFloorRatioNIDelta)
	t.Logf("SUMMARY max independent_control byte-equal floor ratio=%.3fx",
		maxFloorRatioIndep)

	// Baseline comparison against the pre-v0.3.0 archival nonce-reuse
	// Layer A number at 512 B on the near-identical pair shape. The
	// number is the published REDTEAM.md range top (`redteam_nonce_
	// reuse_test.go` Layer A histogram at 512 B, near-identical
	// shape) ≈ 0.063 byte-equal rate = 16.128× the 1/256 floor. This
	// probe measures the same shape under fresh nonces; the delta
	// between the two floors is the load-bearing "fresh nonce
	// suffices" number.
	run.Baseline.Kind = "nonce-reuse near-identical pair at 512 B (Layer A histogram)"
	run.Baseline.Source = "redteam_nonce_reuse_test.go TestRedTeamNonceReuseLayerAHistogram (reference archival number in REDTEAM.md § 'Nonce reuse (lab-only)')"
	run.Baseline.NonceReuseNearIdenticalBER = 0.063
	run.Baseline.NonceReuseFloorRatio = 16.128
	run.Baseline.NoteFreshVsReuse = "Under nonce reuse the near-identical pair produces C1 XOR C2 whose byte-equal rate at 512 B sits at ~16x the 1/256 floor — a traffic-analysis residue. Under fresh nonces the same pair shape should collapse to floor because each Encrypt call redraws every per-chunk mask + noise position + rotation + startPixel from the fresh nonce, so no per-position correlation between the two pair wires survives."

	// A compact fresh-nonce number at 512 B on the near-identical
	// cells, matching the archival baseline size, for a directly
	// comparable "fresh vs reuse" number in the aggregator.
	summary := map[string]any{
		"max_homogeneity_chi2":                          maxHomog,
		"max_homogeneity_size":                          maxHomogSize,
		"max_homogeneity_delta":                         maxHomogDelta,
		"df255_uniform_3sigma_top":                      bandTop,
		"max_near_identical_floor_ratio":                maxFloorRatioNI,
		"max_near_identical_floor_ratio_size":           maxFloorRatioNISize,
		"max_near_identical_floor_ratio_delta":          maxFloorRatioNIDelta,
		"max_independent_control_floor_ratio":           maxFloorRatioIndep,
		"nonce_reuse_baseline_near_identical_floor_512": run.Baseline.NonceReuseFloorRatio,
		"note": "Under fresh nonces the near-identical pair's cross-category homogeneity chi² is the load-bearing between-pair-shape distinguisher; in-band across the matrix implies the pre-v0.3.0 nonce-reuse near-identical-pair traffic-analysis residue collapses to the 1/256 floor.",
	}

	emitJSONNIF(t, "near_identical_fresh_matrix", map[string]any{
		"run":            run,
		"summary":        summary,
		"format_version": "1",
	})

	// Attach a compact 512-B near-identical-vs-reuse contrast line
	// visible in `-v` output so a reader without the aggregator sees
	// the load-bearing baseline delta at a glance.
	fmt.Fprintf(os.Stderr, "[nif-baseline] fresh-nonce near-identical floor ratio range across matrix: near_id max=%.3fx, indep_ctrl max=%.3fx (nonce-reuse archival baseline near-identical at 512 B = %.3fx floor)\n",
		maxFloorRatioNI, maxFloorRatioIndep, run.Baseline.NonceReuseFloorRatio)
}
