package itb

// Related-nonce differential re-verification for the v0.3.0 architecture
// (always-on 48-bit Interlocked Barrier + Triple Ouroboros + 8 mandatory
// seeds). Companion to `redteam_related_seed_test.go`; extends the
// related-seed Δ probe to the nonce axis.
//
// Architectural finding (READ FIRST — code-trace of seed*.go /
// process_generic.go / interlock48.go):
//
//   The nonce is a shared input to FOUR distinct derivation paths, and
//   every one of the 8 mandatory seeds consumes it:
//
//     * noiseSeed  → per-pixel  noisePos       (via processChunk's
//                                              noiseBuf = pixIdx || nonce)
//     * dataSeed_i → per-pixel  dataRotation + channelXOR (per snake,
//                                              via processChunk's dataBuf
//                                              = pixIdx || nonce)
//     * startSeed_i→ per-snake  startPixel     (via deriveStartPixel's
//                                              buf = 0x02 || nonce)
//     * lockSeed   → per-chunk  Interlocked Barrier bit-permutation key
//                                              (via deriveInterLockSeed's
//                                              buf = 0x02 || nonce)
//
//   A 1-bit nonce Δ therefore perturbs ALL 8 seed-derived outputs
//   simultaneously — fundamentally different from Rank 2's single-seed
//   Δ. The lockSeed derivation slot is one of eight nonce consumers,
//   not a bottleneck; nonce Δ SUPERSETS lockSeed Δ by also perturbing
//   the other seven derivation slots.
//
// Threat model per probe (see docstrings): lab-forced 1-bit nonce Δ
// (installed via setBrokenTestNonce), same seeds forced across the
// compared pair, same plaintext, same hash-function instance. This is a
// **structural diffusion probe** — a production attacker cannot force a
// nonce delta because generateNonceCfg draws from crypto/rand per
// Encrypt call. The χ² measurement stresses the barrier's diffusion
// property against a hypothetical nonce Δ, not any shipped-API attack
// path.
//
// Attacker-realism (CLAUDE.md discipline):
//
//   - The χ² statistic is inherently attacker-visible — it consumes
//     ciphertext bytes only. No seed components are read in any
//     decision path.
//   - Ground-truth Δ hex is emitted only in terminal-stage JSON records
//     for later analysis; the χ² decision does not depend on knowing Δ.
//   - The lab-forced nonce Δ is a probe input, not an attacker
//     capability — the ARCHITECTURAL question is whether a 1-bit nonce
//     perturbation produces a measurable ciphertext-XOR bias against the
//     df=255 uniform band.
//
// Emission: each test writes a compact JSON line to
// `tmp/redteam/related_nonce/<name>.json` under the repo (gitignored)
// so downstream aggregation can consume the measurements without
// rerunning the tests.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// tmpRNDir is the shared scratch subdir all related-nonce probes emit
// into. Relative to the package directory.
const tmpRNDir = "tmp/redteam/related_nonce"

// rnKeyComponents matches the Rank 2 methodology — 1024-bit key across
// all 8 seed roles so per-cell wall-clock and container geometry stay
// comparable to the related-seed matrix.
const rnKeyComponents = 16

// rnPlaintextBytes matches Rank 2 at 512 KiB.
const rnPlaintextBytes = 512 * 1024

// rnBaseNonceSeed is the deterministic seed for the base nonce; every
// matrix cell uses (rnBaseNonce, rnBaseNonce XOR Δ) as its compared
// pair. Chosen distinct from Rank 2's nonceSeed so the two ledgers do
// not accidentally share a nonce value.
const rnBaseNonceSeed uint64 = 0xB1A2C3D4E5F6A7B8

// emitJSONRN writes a compact JSON record. Non-fatal on error.
func emitJSONRN(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpRNDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpRNDir, err)
		return
	}
	path := filepath.Join(tmpRNDir, name+".json")
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

// deriveFixedNonceRN is a deterministic non-zero nonce of NonceSize
// bytes, keyed by a uint64 seed via xorshift. Not cryptographic —
// reproducibility only.
func deriveFixedNonceRN(seed uint64) []byte {
	nonce := make([]byte, NonceSize)
	x := seed
	if x == 0 {
		x = 0xB1B1B1B1B1B1B1B1
	}
	for i := 0; i < NonceSize; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		nonce[i] = byte(x & 0xFF)
	}
	return nonce
}

// rnNonceDelta returns a 1-bit delta pattern applied to nonce[byteIdx]
// at bit position bitIdx. Returned buffer has NonceSize bytes, all zero
// except for the 1-bit mask at (byteIdx, bitIdx).
func rnNonceDelta(byteIdx int, bitIdx uint) []byte {
	d := make([]byte, NonceSize)
	d[byteIdx] = 1 << bitIdx
	return d
}

// rnDeltaPattern maps a symbolic Δ name to its (byteIdx, bitIdx)
// coordinates. Six diverse positions sample nonce byte-word structure:
// LSB of byte 0, MSB of byte 0 (byte-boundary), LSB of byte 7 (first
// 64-bit-word boundary), a middle byte, LSB of a higher-order byte, and
// the top bit (MSB of last byte).
var rnDeltaPatterns = []struct {
	name    string
	byteIdx int
	bitIdx  uint
}{
	{"bit_low", 0, 0},                   // nonce[0]  bit 0 — LSB of first byte
	{"byte_msb", 0, 7},                  // nonce[0]  bit 7 — MSB of first byte
	{"word_boundary", 7, 7},             // nonce[7]  bit 7 — high bit of first 64-bit word
	{"bit_mid", NonceSize / 2, 0},       // nonce[32] bit 0 — middle-byte LSB
	{"byte_high_lsb", NonceSize - 8, 0}, // nonce[56] bit 0 — LSB of last 64-bit word
	{"bit_high", NonceSize - 1, 7},      // nonce[63] bit 7 — top bit
}

// drawBaseComponentsRN pulls n uint64s from a deterministic PRNG stream.
// Disjoint per-role streams so the 8 seed axes are independent but
// reproducible across runs.
func drawBaseComponentsRN(nonceSeed, streamTag uint64, n int) []uint64 {
	rng := rand.New(rand.NewSource(int64(nonceSeed ^ streamTag)))
	out := make([]uint64, n)
	for i := range out {
		out[i] = rng.Uint64()
	}
	return out
}

// generatePlaintextRN — random or ASCII plaintext of the requested
// size, deterministic PRNG.
func generatePlaintextRN(rng *rand.Rand, size int, kind string) []byte {
	pt := make([]byte, size)
	switch kind {
	case "random":
		if _, err := rng.Read(pt); err != nil {
			panic(err)
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
		panic(fmt.Sprintf("rnGeneratePlaintext: bad kind %q", kind))
	}
	return pt
}

// bodyOfCTRN slices the ciphertext body out of a v0.3.0 wire.
func bodyOfCTRN(ct []byte) []byte {
	header := NonceSize + 4
	w := int(binary.BigEndian.Uint16(ct[NonceSize : NonceSize+2]))
	h := int(binary.BigEndian.Uint16(ct[NonceSize+2 : NonceSize+4]))
	total := w * h
	return ct[header : header+total*Channels]
}

// xorBytesRN returns a XOR b, truncated to min(len(a), len(b)).
func xorBytesRN(a, b []byte) []byte {
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

// mkSeed128RN wraps SeedFromComponents128, panic on error.
func mkSeed128RN(t *testing.T, hf HashFunc128, comps []uint64) *Seed128 {
	t.Helper()
	s, err := SeedFromComponents128(hf, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents128: %v", err)
	}
	return s
}

// rnBuild8Seeds constructs 8 Seed128 handles under primitive hf keyed
// by disjoint deterministic PRNG streams. Encrypt3x128Cfg rejects seed
// pointer collisions; components differ across roles.
func rnBuild8Seeds(t *testing.T, hf HashFunc128, base map[string][]uint64) [8]*Seed128 {
	return [8]*Seed128{
		mkSeed128RN(t, hf, base["noiseSeed"]),
		mkSeed128RN(t, hf, base["lockSeed"]),
		mkSeed128RN(t, hf, base["dataSeed1"]),
		mkSeed128RN(t, hf, base["dataSeed2"]),
		mkSeed128RN(t, hf, base["dataSeed3"]),
		mkSeed128RN(t, hf, base["startSeed1"]),
		mkSeed128RN(t, hf, base["startSeed2"]),
		mkSeed128RN(t, hf, base["startSeed3"]),
	}
}

// rnBaseComponents draws base components for the 8 seed roles from
// disjoint PRNG streams.
func rnBaseComponents(nonceSeed uint64) map[string][]uint64 {
	streamTags := map[string]uint64{
		"noiseSeed":  0xBB00000000000001,
		"lockSeed":   0xBB00000000000002,
		"dataSeed1":  0xBB00000000000003,
		"dataSeed2":  0xBB00000000000004,
		"dataSeed3":  0xBB00000000000005,
		"startSeed1": 0xBB00000000000006,
		"startSeed2": 0xBB00000000000007,
		"startSeed3": 0xBB00000000000008,
	}
	out := map[string][]uint64{}
	for k, tag := range streamTags {
		out[k] = drawBaseComponentsRN(nonceSeed, tag, rnKeyComponents)
	}
	return out
}

// rnCell is one row of the matrix.
type rnCell struct {
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

// rnRun is the top-level JSON emission.
type rnRun struct {
	Config struct {
		KeyBits        int      `json:"key_bits"`
		NonceBits      int      `json:"nonce_bits"`
		Primitives     []string `json:"primitives"`
		DeltaKinds     []string `json:"delta_kinds"`
		PlaintextKinds []string `json:"plaintext_kinds"`
		PlaintextBytes int      `json:"plaintext_bytes"`
		BaseNonceSeed  uint64   `json:"base_nonce_seed"`
	} `json:"config"`
	Cells []rnCell `json:"cells"`
}

// ---------------------------------------------------------------------------
// No-Δ architectural floor — reference against which every Δ cell is
// compared. Two Encrypt3x128Cfg calls with identical seeds and IDENTICAL
// forced nonce; produces the same architectural CSPRNG-noise-bit + fill
// artefact Rank 2 measured (CRC128 ~41.9M / FNV-1a ~56.3M).
// ---------------------------------------------------------------------------

// TestRedTeamRelatedNonceNoDeltaFloor establishes the χ² floor under
// v0.3.0 Encrypt3x128Cfg with identical seeds + IDENTICAL forced nonce
// + same plaintext. The Rank 2 methodology-check identifies this as the
// "CSPRNG-noise-bit + fill" architectural artefact of two independent
// encrypts. Values here should reproduce Rank 2's floor within
// primitive-conditional noise.
func TestRedTeamRelatedNonceNoDeltaFloor(t *testing.T) {
	if testing.Short() {
		t.Skip("related-nonce no-Δ floor: skipped under -short")
	}

	baseNonce := deriveFixedNonceRN(rnBaseNonceSeed)
	setBrokenTestNonce(t, baseNonce)

	base := rnBaseComponents(rnBaseNonceSeed)
	seedVar := uint64(rnBaseNonceSeed)
	pt := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x1919191919191919))), rnPlaintextBytes, "random")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}

	floors := []map[string]any{}

	for _, prim := range primitives {
		seeds := rnBuild8Seeds(t, prim.hf, base)

		ct0, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
		if err != nil {
			t.Fatalf("baseline Encrypt3x128Cfg %s: %v", prim.name, err)
		}
		ct1, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
		if err != nil {
			t.Fatalf("re-encrypt Encrypt3x128Cfg %s: %v", prim.name, err)
		}
		body0 := bodyOfCTRN(ct0)
		body1 := bodyOfCTRN(ct1)
		diff := xorBytesRN(body0, body1)
		chi2 := byteChi2RS(diff)
		meanAbs, maxAbs := bitBalanceRS(diff)
		t.Logf("FLOOR %-6s NO_Δ chi2=%12.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d",
			prim.name, chi2, meanAbs, maxAbs, len(diff))
		floors = append(floors, map[string]any{
			"primitive":        prim.name,
			"chi2":             chi2,
			"chi2_df":          255,
			"bit_bal_mean_abs": meanAbs,
			"bit_bal_max_abs":  maxAbs,
			"body_bytes":       len(diff),
			"note":             "two encrypts, identical seeds, IDENTICAL forced nonce; matches Rank 2 no-Δ floor within primitive noise",
		})
	}

	emitJSONRN(t, "related_nonce_floor", map[string]any{
		"description": "no-Δ χ² floor under v0.3.0 shipped Encrypt3x128Cfg, identical nonce",
		"floors":      floors,
	})
}

// ---------------------------------------------------------------------------
// v0.3.0 matrix — 6 Δ patterns × 2 plaintext kinds × 2 primitives = 24
// cells. Each cell computes ct_baseline_nonce ⊕ ct_delta_nonce body χ²
// against df=255 uniform expectation via Encrypt3x128Cfg + always-on
// interlock.
// ---------------------------------------------------------------------------

// TestRedTeamRelatedNonceMatrix runs the 24-cell matrix under the
// shipped Encrypt3x128Cfg. Two encrypts per cell: baseline with the
// deterministic base nonce; variant with (base nonce XOR 1-bit Δ).
// Every seed component fixed identically. Plaintext held fixed per
// cell so the ciphertext-body XOR isolates nonce-Δ propagation through
// the barrier + 8-seed derivation graph.
//
// Runtime: ~2-3 minutes wall clock at 512 KiB plaintext × 48 encrypts
// (24 cells × 2 encrypts) × two below-spec primitives. Encrypt3x128Cfg
// uses runtime.NumCPU() workers, so wall time scales with cores.
func TestRedTeamRelatedNonceMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("related-nonce matrix: skipped under -short (48 512-KiB encrypts)")
	}

	baseNonce := deriveFixedNonceRN(rnBaseNonceSeed)
	base := rnBaseComponents(rnBaseNonceSeed)

	// Runtime uint64 → int64 cast: the compile-time overflow check on a
	// const XOR of two 64-bit values does not permit a direct int64
	// literal cast when the top bit is set; a variable-typed uint64 first
	// converts freely at runtime.
	seedVar := uint64(rnBaseNonceSeed)
	ptRandom := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x2A2A555555550000))), rnPlaintextBytes, "random")
	ptAscii := generatePlaintextRN(rand.New(rand.NewSource(int64(seedVar^0x15552A2A2A2A0000))), rnPlaintextBytes, "ascii")

	primitives := []struct {
		name string
		hf   HashFunc128
	}{
		{"CRC128", crc128BrokenLab},
		{"FNV-1a", fnv1a128BrokenLab},
	}
	plaintextKinds := []string{"random", "ascii"}

	run := rnRun{}
	run.Config.KeyBits = rnKeyComponents * 64
	run.Config.NonceBits = NonceSize * 8
	for _, p := range primitives {
		run.Config.Primitives = append(run.Config.Primitives, p.name)
	}
	for _, d := range rnDeltaPatterns {
		run.Config.DeltaKinds = append(run.Config.DeltaKinds, d.name)
	}
	run.Config.PlaintextKinds = append([]string{}, plaintextKinds...)
	run.Config.PlaintextBytes = rnPlaintextBytes
	run.Config.BaseNonceSeed = rnBaseNonceSeed

	for _, prim := range primitives {
		seeds := rnBuild8Seeds(t, prim.hf, base)

		for _, dp := range rnDeltaPatterns {
			// Build variant nonce = baseNonce XOR (1-bit Δ mask).
			deltaMask := rnNonceDelta(dp.byteIdx, dp.bitIdx)
			variantNonce := make([]byte, NonceSize)
			for i := 0; i < NonceSize; i++ {
				variantNonce[i] = baseNonce[i] ^ deltaMask[i]
			}

			for _, ptk := range plaintextKinds {
				var pt []byte
				if ptk == "random" {
					pt = ptRandom
				} else {
					pt = ptAscii
				}

				// Baseline encrypt: force base nonce.
				setBrokenTestNonce(t, baseNonce)
				ct0, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
				if err != nil {
					t.Fatalf("baseline Encrypt3x128Cfg %s/%s/%s: %v", prim.name, dp.name, ptk, err)
				}

				// Variant encrypt: force variant nonce.
				setBrokenTestNonce(t, variantNonce)
				ct1, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
				if err != nil {
					t.Fatalf("variant Encrypt3x128Cfg %s/%s/%s: %v", prim.name, dp.name, ptk, err)
				}

				body0 := bodyOfCTRN(ct0)
				body1 := bodyOfCTRN(ct1)
				matched := len(body0) == len(body1)
				diff := xorBytesRN(body0, body1)
				chi2 := byteChi2RS(diff)
				meanAbs, maxAbs := bitBalanceRS(diff)

				cell := rnCell{
					Primitive:        prim.name,
					DeltaKind:        dp.name,
					DeltaByteIdx:     dp.byteIdx,
					DeltaBitIdx:      int(dp.bitIdx),
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

				t.Logf("%-6s Δ=%-14s (byte=%2d bit=%d) pt=%-6s chi2=%10.1f bit_bal(mean|abs|,max|abs|)=(%.5f,%.5f) body=%d match=%v",
					prim.name, dp.name, dp.byteIdx, dp.bitIdx, ptk, chi2, meanAbs, maxAbs, len(diff), matched)
			}
		}
	}

	// Sanity: per-primitive max χ² across all Δ patterns.
	summary := map[string]map[string]any{}
	for _, prim := range primitives {
		var maxChi float64
		var maxCell rnCell
		var minChi float64 = 1e300
		var minCell rnCell
		var sum float64
		var n int
		for _, c := range run.Cells {
			if c.Primitive != prim.name {
				continue
			}
			if c.Chi2 > maxChi {
				maxChi = c.Chi2
				maxCell = c
			}
			if c.Chi2 < minChi {
				minChi = c.Chi2
				minCell = c
			}
			sum += c.Chi2
			n++
		}
		mean := 0.0
		if n > 0 {
			mean = sum / float64(n)
		}
		t.Logf("SUMMARY %-6s: min=%9.1f (Δ=%s pt=%s) mean=%9.1f max=%9.1f (Δ=%s pt=%s)",
			prim.name, minChi, minCell.DeltaKind, minCell.PlaintextKind,
			mean, maxChi, maxCell.DeltaKind, maxCell.PlaintextKind)
		summary[prim.name] = map[string]any{
			"max_chi2":             maxChi,
			"max_chi2_cell":        maxCell,
			"min_chi2":             minChi,
			"min_chi2_cell":        minCell,
			"mean_chi2":            mean,
			"rank2_lockseed_band":  map[string]float64{"CRC128": 635, "FNV-1a": 550}[prim.name],
			"rank2_nonlock_floor":  map[string]float64{"CRC128": 41894696, "FNV-1a": 56328564}[prim.name],
			"df255_uniform_one_3s": 323.0,
		}
	}

	emitJSONRN(t, "related_nonce_matrix", map[string]any{
		"run":     run,
		"summary": summary,
	})
}
