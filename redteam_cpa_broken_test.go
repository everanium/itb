//go:build redteam

package itb

// Fresh-nonce CPA re-verification against the shipped architecture
// (always-on 48-bit Interlocked Barrier + Triple Ouroboros + 8 mandatory
// seeds) under a below-spec primitive on every seed role. Companion to
// `redteam_related_seed_test.go` and `redteam_related_nonce_test.go`;
// extends the broken-primitive scaffolding from structural forced-Δ
// diffusion probes to the shipped-API chosen-plaintext attacker posture.
//
// Threat model. Attacker capability is fresh-nonce chosen-plaintext:
// the attacker holds an encryption oracle and can submit any plaintext
// they choose, and each call draws a fresh nonce from `crypto/rand` (the
// shipped `generateNonceCfg` path — `testNonceOverride` is NOT installed
// in this file). The primitive substitution — FNV-1a keyed onto every
// one of the 8 mandatory seed roles — is a lab hypothesis; the shipped
// registry never lets a caller reach this configuration for a
// PRF-grade session. The CPA capability itself is a real shipped-API
// attacker posture; the primitive substitution stresses whether the
// barrier's closure holds even when the underlying hash is invertible
// non-linear over Z/2^128 rather than PRF-grade.
//
// Measurement surface. For each (primitive arm, chosen plaintext kind)
// cell the probe:
//
//   1. Runs N adversarial encryptions of the chosen plaintext through
//      `Encrypt3x128Cfg` with the same 8-seed bundle. Each call draws a
//      fresh CSPRNG nonce internally.
//   2. Accumulates a pooled 256-bin byte histogram of the wire's
//      container body across the N ciphertexts.
//   3. Computes:
//         - the pooled body byte-histogram vs df=255 uniform (per cell,
//           per arm)
//         - a mean pairwise byte-equal rate across successive ciphertext
//           pairs (position-wise agreement fraction, expected 1/256
//           for independent uniform streams)
//         - a two-sample homogeneity chi-squared between the FNV-1a and
//           BLAKE3 arms at the same plaintext kind (df=255)
//
// Wall-clock. Default N = 2000 messages per cell → 2 arms × 6 kinds ×
// 2000 = 24000 encryptions at 512-byte plaintext. Encrypt3x128Cfg
// parallelises across `runtime.NumCPU()`; typical wall clock is a few
// minutes on an 8-core host. Override via `ITB_CPA_N`.
//
// Attacker-realism (attacker-realism discipline).
//   - The chi² and byte-equal statistics are inherently attacker-visible
//     — every ingested byte is a public wire byte.
//   - No seed / nonce / mask / rotation / noise-position value is read
//     in any decision path.
//   - The 8-seed bundle values are drawn from a deterministic PRNG so
//     the run is reproducible, but the values themselves are not
//     consulted after the seeds are constructed.
//
// Emission. `$HOME/scratch/redteam/cpa_broken/<name>.json` (per the
// working-tree layout) for downstream aggregation. Override the parent
// directory via `REDTEAM_CPA_BROKEN_OUTPUT_DIR`.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/zeebo/blake3"
)

// outCPADir is the shared scratch subdir all CPA probes below emit
// into. Resolved via redteamOutputDir; see that helper for the default
// + env-override contract.
var outCPADir = redteamOutputDir("cpa_broken")

// cpaKeyComponents keeps the 1024-bit key width the related-seed /
// related-nonce probes settled on so container geometry stays
// comparable across the broken-primitive track.
const cpaKeyComponents = 16

// cpaPlaintextBytes is the fixed chosen-plaintext size per kind. Sized
// so the container body is O(1 KiB) — enough for the pooled histogram
// over N encryptions to fill 256 bins at the tested sample size.
const cpaPlaintextBytes = 512

// cpaBaseSeed is the deterministic seed for the 8 seed-component
// vectors and the plaintext-generator PRNG streams. Distinct from the
// related-seed / related-nonce nonceSeed values so ledgers do not
// accidentally share fixture material.
const cpaBaseSeed uint64 = 0xC1A0F0F0C1A0F0F0

// cpaDefaultN is the sample size per (arm, kind) cell when the
// `ITB_CPA_N` env override is unset. Chosen to give a pooled histogram
// with ≥ 500 samples per bin on a 512-byte plaintext (body ≈ 1 KiB).
const cpaDefaultN = 2000

// emitJSONCPA writes a compact JSON record under `outCPADir/<name>.json`
// for downstream aggregation. Errors are logged, not fatal.
func emitJSONCPA(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(outCPADir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", outCPADir, err)
		return
	}
	path := filepath.Join(outCPADir, name+".json")
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

// makeBlake3Hash128CPA is the PRF-grade reference primitive: keyed
// BLAKE3 wrapped to the HashFunc128 interface (extracts the low 16
// bytes of the 32-byte digest as (lo, hi)). The wrapper key is derived
// deterministically from `tag` so runs are reproducible. Structurally
// parallel to `makeBlake3Hash256` in aliases_test.go, restricted to a
// 128-bit output width for a fair comparison against
// `fnv1a128BrokenLab` through the same `Encrypt3x128Cfg` cipher
// entrypoint.
func makeBlake3Hash128CPA(tag uint64) HashFunc128 {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[0:8], tag^0x9E3779B97F4A7C15)
	binary.LittleEndian.PutUint64(key[8:16], tag^0xBF58476D1CE4E5B9)
	binary.LittleEndian.PutUint64(key[16:24], tag^0x94D049BB133111EB)
	binary.LittleEndian.PutUint64(key[24:32], tag^0xDA942042E4DD58B5)
	template, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		h := template.Clone()
		const seedInjectBytes = 16
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		binary.LittleEndian.PutUint64(mixed[0:], binary.LittleEndian.Uint64(mixed[0:])^seed0)
		binary.LittleEndian.PutUint64(mixed[8:], binary.LittleEndian.Uint64(mixed[8:])^seed1)
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)
		var buf [32]byte
		h.Sum(buf[:0])
		lo := binary.LittleEndian.Uint64(buf[0:])
		hi := binary.LittleEndian.Uint64(buf[8:])
		return lo, hi
	}
}

// cpaDrawComponents pulls n uint64s from a deterministic PRNG stream
// keyed by (cpaBaseSeed, streamTag). Disjoint per-role streams so the
// 8 seed axes carry independent but reproducible values.
func cpaDrawComponents(streamTag uint64, n int) []uint64 {
	rng := rand.New(rand.NewSource(int64(cpaBaseSeed ^ streamTag)))
	out := make([]uint64, n)
	for i := range out {
		out[i] = rng.Uint64()
	}
	return out
}

// cpaStreamTags is the disjoint per-axis PRNG stream tag so baseline
// components for each of the 8 seeds are independent but reproducible.
// Tags are chosen distinct from `rsStreamTags` / `rnBaseComponents`'s
// tags so seed values do not overlap across ledgers.
var cpaStreamTags = map[string]uint64{
	"noiseSeed":  0xCC00000000000001,
	"lockSeed":   0xCC00000000000002,
	"dataSeed1":  0xCC00000000000003,
	"dataSeed2":  0xCC00000000000004,
	"dataSeed3":  0xCC00000000000005,
	"startSeed1": 0xCC00000000000006,
	"startSeed2": 0xCC00000000000007,
	"startSeed3": 0xCC00000000000008,
}

// cpaBuild8Seeds constructs the 8 mandatory Seed128 handles under
// primitive `hf` keyed by disjoint deterministic PRNG streams.
// Encrypt3x128Cfg rejects seed pointer collisions; each role receives a
// unique component vector.
func cpaBuild8Seeds(t *testing.T, hf HashFunc128) [8]*Seed128 {
	t.Helper()
	tags := []string{
		"noiseSeed", "lockSeed",
		"dataSeed1", "dataSeed2", "dataSeed3",
		"startSeed1", "startSeed2", "startSeed3",
	}
	var out [8]*Seed128
	for i, tag := range tags {
		comps := cpaDrawComponents(cpaStreamTags[tag], cpaKeyComponents)
		s, err := SeedFromComponents128(hf, comps...)
		if err != nil {
			t.Fatalf("SeedFromComponents128 %s: %v", tag, err)
		}
		out[i] = s
	}
	return out
}

// bodyOfCTCPA slices the ciphertext body out of a shipped wire. Layout:
// main_nonce (NonceSize) || interlock_nonce (NonceSize) || W(2 BE) || H(2 BE) || W*H*Channels body bytes.
func bodyOfCTCPA(ct []byte) []byte {
	header := 2*NonceSize + 4
	w := int(binary.BigEndian.Uint16(ct[2*NonceSize : 2*NonceSize+2]))
	h := int(binary.BigEndian.Uint16(ct[2*NonceSize+2 : 2*NonceSize+4]))
	total := w * h
	return ct[header : header+total*Channels]
}

// ---------------------------------------------------------------------------
// Plaintext-kind generators. Each returns a fixed-length byte slice of
// `cpaPlaintextBytes` bytes. All are DETERMINISTIC so a rerun of the
// probe encrypts the SAME chosen plaintext per (arm, kind), which is
// the chosen-plaintext-attacker premise: the attacker fixes the
// plaintext then queries the oracle N times.
// ---------------------------------------------------------------------------

// cpaKindZeros — the all-zeros plaintext. The trivial fixed-content
// probe; every attacker-known plaintext byte is 0.
func cpaKindZeros() []byte {
	return make([]byte, cpaPlaintextBytes)
}

// cpaKind7F — every plaintext byte set to 0x7F. High-Hamming-weight
// constant content; the byte value that maximally exercises the 7-bit
// channel packing (all data bits set, no spare bit position).
func cpaKind7F() []byte {
	b := make([]byte, cpaPlaintextBytes)
	for i := range b {
		b[i] = 0x7F
	}
	return b
}

// cpaKindSingleBitLow — an otherwise-zero plaintext with a single 1-bit
// at (byte 0, bit 0). Systematic sparse probe placed at the very start
// of the payload.
func cpaKindSingleBitLow() []byte {
	b := make([]byte, cpaPlaintextBytes)
	b[0] = 0x01
	return b
}

// cpaKindSingleBitMid — an otherwise-zero plaintext with a single 1-bit
// at (byte cpaPlaintextBytes/2, bit 3). Systematic sparse probe placed
// mid-payload so the barrier's per-chunk permutation is exercised on
// the bit at an interior chunk boundary.
func cpaKindSingleBitMid() []byte {
	b := make([]byte, cpaPlaintextBytes)
	b[cpaPlaintextBytes/2] = 1 << 3
	return b
}

// cpaKindStructuredJSON — a public-schema JSON prefix padded to
// `cpaPlaintextBytes`. Models a real attacker crib: the header token
// pattern is known a priori, so the plaintext is high-signal for a
// crib-anchored attack.
func cpaKindStructuredJSON() []byte {
	tpl := []byte(`{"type":"telemetry","v":1,"src":"itb-cpa-probe","ts":"2026-08-27T00:00:00Z","payload":{"metric":"cpa","value":0,"body":"`)
	suffix := []byte(`"}}`)
	b := make([]byte, cpaPlaintextBytes)
	if len(tpl)+len(suffix) > cpaPlaintextBytes {
		copy(b, tpl[:cpaPlaintextBytes])
		return b
	}
	copy(b, tpl)
	for i := len(tpl); i < cpaPlaintextBytes-len(suffix); i++ {
		b[i] = 'A'
	}
	copy(b[cpaPlaintextBytes-len(suffix):], suffix)
	return b
}

// cpaKindStructuredHTML — HTML boilerplate padded to
// `cpaPlaintextBytes`. Parallel to the JSON crib but with a different
// public-schema signature (`<!DOCTYPE ...>` and `</html>`).
func cpaKindStructuredHTML() []byte {
	tpl := []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>ITB CPA</title></head><body><p class="itb">`)
	suffix := []byte(`</p></body></html>`)
	b := make([]byte, cpaPlaintextBytes)
	if len(tpl)+len(suffix) > cpaPlaintextBytes {
		copy(b, tpl[:cpaPlaintextBytes])
		return b
	}
	copy(b, tpl)
	for i := len(tpl); i < cpaPlaintextBytes-len(suffix); i++ {
		b[i] = ' '
	}
	copy(b[cpaPlaintextBytes-len(suffix):], suffix)
	return b
}

// cpaKindRandomControl — a deterministic random 512-byte plaintext. The
// attacker-choice control: a plaintext that carries no structural
// signal the barrier could disproportionately amplify. Same PRNG seed
// across runs so the same 512 bytes are chosen every time.
func cpaKindRandomControl() []byte {
	// Runtime uint64 -> int64 cast: the compile-time overflow check
	// on a const XOR of two 64-bit values does not permit a direct
	// int64 literal cast when the top bit is set; a variable-typed
	// uint64 first converts freely at runtime.
	seedVar := uint64(cpaBaseSeed) ^ uint64(0x7A57A57A57A57A57)
	rng := rand.New(rand.NewSource(int64(seedVar)))
	b := make([]byte, cpaPlaintextBytes)
	if _, err := rng.Read(b); err != nil {
		panic(err)
	}
	return b
}

// cpaKindSpec bundles a plaintext kind's name with its generator. The
// name goes into the JSON emission and log lines; the generator is
// called once per (arm, kind) and its output is encrypted N times.
type cpaKindSpec struct {
	name string
	gen  func() []byte
}

var cpaKindSpecs = []cpaKindSpec{
	{"zeros", cpaKindZeros},
	{"fill_7f", cpaKind7F},
	{"single_bit_low", cpaKindSingleBitLow},
	{"single_bit_mid", cpaKindSingleBitMid},
	{"structured_json", cpaKindStructuredJSON},
	{"structured_html", cpaKindStructuredHTML},
	{"random_control", cpaKindRandomControl},
}

// ---------------------------------------------------------------------------
// Statistical helpers.
// ---------------------------------------------------------------------------

// addToHist adds `data`'s byte counts to `hist` (256 bins).
func addToHist(hist []int, data []byte) {
	for _, b := range data {
		hist[b]++
	}
}

// chi2UniformCPA computes Pearson chi-squared of `hist` (256 bins,
// total `total` observations) against a uniform expectation. df = 255.
// One-sided 3σ upper bound of χ²(df=255) ≈ 323.
func chi2UniformCPA(hist []int, total int) float64 {
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

// chi2Homogeneity computes the two-sample chi-squared homogeneity
// statistic between two 256-bin histograms with totals `totalA`,
// `totalB`. df = 255. Under H0 (both samples drawn from the same
// underlying distribution) the statistic follows χ²(df=255): mean 255,
// variance 510, one-sided 3σ upper bound ≈ 323. A value outside the
// uniform band signals distributional distinguishability at the tested
// sample size.
func chi2Homogeneity(a, b []int, totalA, totalB int) float64 {
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

// meanByteEqualRatePairs computes the mean position-wise byte-equal
// rate across successive ciphertext-body pairs (`bodies[2k]` vs
// `bodies[2k+1]`). For independent uniform streams the expected rate is
// 1/256 ≈ 0.00391. `bodies` must have at least 2 entries; only the
// leading len(bodies)/2 pairs are consumed.
func meanByteEqualRatePairs(bodies [][]byte) float64 {
	pairs := len(bodies) / 2
	if pairs == 0 {
		return 0
	}
	var sum float64
	for k := 0; k < pairs; k++ {
		a := bodies[2*k]
		b := bodies[2*k+1]
		n := len(a)
		if len(b) < n {
			n = len(b)
		}
		if n == 0 {
			continue
		}
		eq := 0
		for i := 0; i < n; i++ {
			if a[i] == b[i] {
				eq++
			}
		}
		sum += float64(eq) / float64(n)
	}
	return sum / float64(pairs)
}

// resolveCpaSampleSize honours the `ITB_CPA_N` env override.
func resolveCpaSampleSize() int {
	if v := os.Getenv("ITB_CPA_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return cpaDefaultN
}

// ---------------------------------------------------------------------------
// cpaCell / cpaRun JSON schemas.
// ---------------------------------------------------------------------------

type cpaCell struct {
	Primitive           string  `json:"primitive"`
	Kind                string  `json:"kind"`
	SampleN             int     `json:"sample_n"`
	PlaintextBytes      int     `json:"plaintext_bytes"`
	PooledBodyBytes     int     `json:"pooled_body_bytes"`
	BodyChi2Uniform     float64 `json:"body_chi2_uniform"`
	BodyChi2DF          int     `json:"body_chi2_df"`
	MeanPairByteEqRate  float64 `json:"mean_pair_byte_equal_rate"`
	IndepFloor          float64 `json:"indep_floor"`
	ExcessOverFloor     float64 `json:"excess_over_floor"`
	NoteHomogeneityPair string  `json:"note_homogeneity_pair"`
}

type cpaHomogRow struct {
	Kind         string  `json:"kind"`
	SampleN      int     `json:"sample_n"`
	Chi2Homog    float64 `json:"chi2_homogeneity_fnv1a_vs_blake3"`
	Chi2DF       int     `json:"chi2_df"`
	Uniform3σTop float64 `json:"uniform_band_3sigma_top"`
	Verdict      string  `json:"verdict"`
}

type cpaRun struct {
	Config struct {
		KeyBits         int      `json:"key_bits"`
		Primitives      []string `json:"primitives"`
		Kinds           []string `json:"kinds"`
		SampleN         int      `json:"sample_n"`
		PlaintextBytes  int      `json:"plaintext_bytes"`
		WirePath        string   `json:"wire_path"`
		CipherEntry     string   `json:"cipher_entry"`
		NoncePolicy     string   `json:"nonce_policy"`
		AttackerPosture string   `json:"attacker_posture"`
	} `json:"config"`
	Cells       []cpaCell     `json:"cells"`
	Homogeneity []cpaHomogRow `json:"homogeneity"`
}

// ---------------------------------------------------------------------------
// TestRedTeamCPABroken — the load-bearing chosen-plaintext probe.
//
// For each (primitive arm, plaintext kind) cell: encrypt the chosen
// plaintext `sampleN` times through `Encrypt3x128Cfg` (fresh CSPRNG
// nonce per call), accumulate the pooled container-body byte histogram,
// compute per-cell body chi² vs df=255 uniform + mean pairwise
// byte-equal rate vs 1/256 floor, and the two-sample homogeneity chi²
// between the FNV-1a arm and the BLAKE3 arm at the same plaintext
// kind. A homogeneity chi² inside the df=255 uniform band means the
// FNV-1a wire is indistinguishable from the BLAKE3 wire under CPA at
// the tested sample size — i.e. the primitive's algebraic weakness
// does not surface at the barrier's chosen-plaintext output.
// ---------------------------------------------------------------------------

func TestRedTeamCPABroken(t *testing.T) {
	if testing.Short() {
		t.Skip("CPA broken-primitive matrix: skipped under -short")
	}

	sampleN := resolveCpaSampleSize()

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"FNV-1a", fnv1a128BrokenLab},
		{"BLAKE3", makeBlake3Hash128CPA(cpaBaseSeed ^ 0xB1A3B1A3B1A3B1A3)},
	}

	run := cpaRun{}
	run.Config.KeyBits = cpaKeyComponents * 64
	for _, p := range primitives {
		run.Config.Primitives = append(run.Config.Primitives, p.name)
	}
	for _, k := range cpaKindSpecs {
		run.Config.Kinds = append(run.Config.Kinds, k.name)
	}
	run.Config.SampleN = sampleN
	run.Config.PlaintextBytes = cpaPlaintextBytes
	run.Config.WirePath = "container body (Encrypt3x128Cfg wire minus nonce + dimension header)"
	run.Config.CipherEntry = "Encrypt3x128Cfg"
	run.Config.NoncePolicy = "fresh CSPRNG per Encrypt call (generateNonceCfg, testNonceOverride NOT installed)"
	run.Config.AttackerPosture = "chosen-plaintext, fresh nonce; attacker fixes plaintext then queries oracle sample_n times"

	// arm-indexed pooled histogram per plaintext kind, plus per-arm
	// per-kind pooled body byte totals.
	type armState struct {
		hists   map[string][]int // kind -> 256-bin
		totals  map[string]int   // kind -> pooled body byte total
		perCell map[string]cpaCell
	}
	arms := map[string]*armState{}

	for _, prim := range primitives {
		state := &armState{
			hists:   map[string][]int{},
			totals:  map[string]int{},
			perCell: map[string]cpaCell{},
		}
		seeds := cpaBuild8Seeds(t, prim.hf)

		for _, kspec := range cpaKindSpecs {
			pt := kspec.gen()
			bodies := make([][]byte, 0, sampleN)
			hist := make([]int, 256)
			var pooled int

			for i := 0; i < sampleN; i++ {
				ct, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
				if err != nil {
					t.Fatalf("Encrypt3x128Cfg %s/%s iter=%d: %v", prim.name, kspec.name, i, err)
				}
				body := bodyOfCTCPA(ct)
				addToHist(hist, body)
				pooled += len(body)
				// Keep ciphertext bodies needed for the pairwise
				// byte-equal test. The body slice references ct, so
				// retaining it pins the whole ct; that is fine at the
				// sampleN scale here (2000 encryptions × ~1 KiB body =
				// ~2 MiB peak per cell).
				if i < 2*(sampleN/2) {
					bodies = append(bodies, body)
				}
			}

			bodyChi2 := chi2UniformCPA(hist, pooled)
			const indepFloor = 1.0 / 256.0
			pairRate := meanByteEqualRatePairs(bodies)
			excess := pairRate - indepFloor

			cell := cpaCell{
				Primitive:           prim.name,
				Kind:                kspec.name,
				SampleN:             sampleN,
				PlaintextBytes:      len(pt),
				PooledBodyBytes:     pooled,
				BodyChi2Uniform:     bodyChi2,
				BodyChi2DF:          255,
				MeanPairByteEqRate:  pairRate,
				IndepFloor:          indepFloor,
				ExcessOverFloor:     excess,
				NoteHomogeneityPair: fmt.Sprintf("paired with %s arm at kind=%s in the homogeneity table below", oppositeArmName(prim.name), kspec.name),
			}
			run.Cells = append(run.Cells, cell)
			state.hists[kspec.name] = hist
			state.totals[kspec.name] = pooled
			state.perCell[kspec.name] = cell

			t.Logf("%-6s kind=%-16s N=%d body_chi2=%9.1f pair_be=%.5f excess=%+9.2e",
				prim.name, kspec.name, sampleN, bodyChi2, pairRate, excess)
		}

		arms[prim.name] = state
	}

	// Two-sample homogeneity chi² between FNV-1a and BLAKE3 arms per
	// kind. df = 255; one-sided 3σ upper bound ≈ 323.
	armA := arms["FNV-1a"]
	armB := arms["BLAKE3"]
	if armA == nil || armB == nil {
		t.Fatalf("both primitive arms required for homogeneity: FNV-1a=%v BLAKE3=%v", armA != nil, armB != nil)
	}
	for _, kspec := range cpaKindSpecs {
		hA := armA.hists[kspec.name]
		hB := armB.hists[kspec.name]
		nA := armA.totals[kspec.name]
		nB := armB.totals[kspec.name]
		chi2 := chi2Homogeneity(hA, hB, nA, nB)
		const bandTop = 323.0
		verdict := "in df=255 uniform band"
		if chi2 > bandTop {
			verdict = "outside uniform band — distinguishable at tested sample size"
		}
		run.Homogeneity = append(run.Homogeneity, cpaHomogRow{
			Kind:         kspec.name,
			SampleN:      sampleN,
			Chi2Homog:    chi2,
			Chi2DF:       255,
			Uniform3σTop: bandTop,
			Verdict:      verdict,
		})
		t.Logf("HOMOG kind=%-16s N=%d chi2=%8.2f (band top %.0f) verdict=%s",
			kspec.name, sampleN, chi2, bandTop, verdict)
	}

	// Cross-cell summary: worst homogeneity chi² across kinds; per-arm
	// worst body chi².
	var maxHomog float64
	var maxHomogKind string
	for _, row := range run.Homogeneity {
		if row.Chi2Homog > maxHomog {
			maxHomog = row.Chi2Homog
			maxHomogKind = row.Kind
		}
	}
	worstBody := map[string]float64{}
	worstBodyKind := map[string]string{}
	for _, c := range run.Cells {
		if c.BodyChi2Uniform > worstBody[c.Primitive] {
			worstBody[c.Primitive] = c.BodyChi2Uniform
			worstBodyKind[c.Primitive] = c.Kind
		}
	}
	t.Logf("SUMMARY max homogeneity chi²=%.2f (kind=%s, band top 323)", maxHomog, maxHomogKind)
	for _, p := range primitives {
		t.Logf("SUMMARY %-6s worst body chi²=%9.1f (kind=%s, uniform band top 323 excluding dimension-header signature)",
			p.name, worstBody[p.name], worstBodyKind[p.name])
	}

	summary := map[string]any{
		"max_homogeneity_chi2":     maxHomog,
		"max_homogeneity_kind":     maxHomogKind,
		"df255_uniform_3sigma_top": 323.0,
		"per_primitive_worst_body_chi2":   worstBody,
		"per_primitive_worst_body_kind":   worstBodyKind,
		"note_body_chi2_upper_bound":      "body chi² per cell reflects the dimension-header residual + per-cell CPA response; the homogeneity chi² is the load-bearing between-arm distinguisher.",
	}

	emitJSONCPA(t, "cpa_broken_matrix", map[string]any{
		"run":     run,
		"summary": summary,
	})
}

// oppositeArmName is a helper for the note field in cpaCell so the
// per-cell JSON records point at the matching homogeneity row. Purely
// cosmetic — no decision path consumes it.
func oppositeArmName(name string) string {
	switch name {
	case "FNV-1a":
		return "BLAKE3"
	case "BLAKE3":
		return "FNV-1a"
	default:
		return "?"
	}
}
