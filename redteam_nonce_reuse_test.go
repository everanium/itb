//go:build redteam

package itb

// Nonce-Reuse adversarial re-verification for the v0.3.0 architecture
// (always-on 48-bit Interlocked Barrier + Triple Ouroboros + 8 mandatory
// seeds). Companion to `redteam_broken_test.go`; extends that file's
// broken-primitive scaffolding with focused nonce-reuse probes.
//
// Threat model per test (see docstrings): Full KPA + forced nonce
// collision. Primitive: FNV-1a on all 8 seed roles (each seed drawn
// independently via NewSeed128 — same primitive, distinct random keys).
// Nonce reuse is realised via the test-only `setBrokenTestNonce` hook;
// production callers cannot force it because `generateNonceCfg` draws
// from `crypto/rand` per call.
//
// Attacker-realism (CLAUDE.md discipline):
//
//   - No test reads `dataSeed*` / `noiseSeed` / `lockSeed` components in
//     the decision path. Ground-truth seed values are read only in
//     terminal-stage audit printouts (t.Logf lines flagged "[audit]").
//   - The single documented lab exception: the Layer B probes below
//     invoke `startSeed_i.deriveStartPixel(nonce, third_i)` to grant the
//     attacker per-snake `startPixel`. This is a single narrowly-scoped
//     lab peek used only inside Layer B tests, tagged "[lab-peek: sp_i]"
//     at the call site.
//   - Every recovery-decision statistic is computed from attacker-visible
//     inputs (ciphertext bytes, the public nonce and dimension header,
//     the known plaintext pair).
//
// Emission: each test writes a compact JSON result line to
// `tmp/redteam/nonce_reuse/<name>.json` under the repo (gitignored) so
// downstream aggregation can consume the measurements without rerunning
// the tests. The tmp/ path is created lazily; failure to create it does
// not fail the test — the log line is the primary record.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// tmpNRDir is the shared scratch subdir all nonce-reuse probes below
// emit into. Relative to the package directory so the tests are
// location-independent.
const tmpNRDir = "tmp/redteam/nonce_reuse"

// emitJSONNR writes a compact JSON line under tmpNRDir/<name>.json for
// downstream aggregation. Errors are logged, not fatal — the t.Logf line
// is the primary record; the JSON is a convenience.
func emitJSONNR(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpNRDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpNRDir, err)
		return
	}
	path := filepath.Join(tmpNRDir, name+".json")
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

// buildEightFNV1aSeeds128 builds the 8 mandatory seed roles as
// independent Seed128 handles, all keyed by fnv1a128BrokenLab with
// independent random keys. Each seed carries `keyBits` bits of key
// material (task-specified below-spec primitive on every role).
func buildEightFNV1aSeeds128(t *testing.T, keyBits int) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	mk := func(role string) *Seed128 {
		s, err := NewSeed128(keyBits, fnv1a128BrokenLab)
		if err != nil {
			t.Fatalf("NewSeed128(%s): %v", role, err)
		}
		return s
	}
	return mk("noise"), mk("lock"), mk("d1"), mk("d2"), mk("d3"),
		mk("s1"), mk("s2"), mk("s3")
}

// wireLayoutNR describes the per-snake byte offsets inside a
// Triple ciphertext body. Populated from the wire header (attacker-visible).
type wireLayoutNR struct {
	nonce            []byte
	totalPixels      int
	third1Pixels     int
	third2Pixels     int
	third3Pixels     int
	body             []byte
	snakeBodyOffsets [3]int // channel-byte start offsets
	snakeBodyEnds    [3]int // channel-byte end offsets (exclusive)
	snakePixelStarts [3]int // pixel start indices (0, third, 2*third)
	snakePixels      [3]int // pixel counts per snake
}

// decodeWireNR parses the public wire header (nonce, W, H) and slices
// the container body into 3 snake regions. Attacker-visible — uses only
// public bytes. Panics if the wire is malformed (tests should not call
// with an invalid wire).
func decodeWireNR(ct []byte) wireLayoutNR {
	nonce := ct[:NonceSize]
	w := int(binary.BigEndian.Uint16(ct[NonceSize : NonceSize+2]))
	h := int(binary.BigEndian.Uint16(ct[NonceSize+2 : NonceSize+4]))
	total := w * h
	third := total / 3
	third3 := total - 2*third
	body := ct[NonceSize+4:]
	return wireLayoutNR{
		nonce:            nonce,
		totalPixels:      total,
		third1Pixels:     third,
		third2Pixels:     third,
		third3Pixels:     third3,
		body:             body,
		snakeBodyOffsets: [3]int{0, third * Channels, 2 * third * Channels},
		snakeBodyEnds:    [3]int{third * Channels, 2 * third * Channels, total * Channels},
		snakePixelStarts: [3]int{0, third, 2 * third},
		snakePixels:      [3]int{third, third, third3},
	}
}

// popcount8 counts set bits in a byte.
func popcount8(b byte) int {
	c := 0
	for i := uint(0); i < 8; i++ {
		if (b>>i)&1 == 1 {
			c++
		}
	}
	return c
}

// klDivergenceFromUniformBytes returns KL(P || U) in bits, where P is the
// empirical byte-value distribution over `data` and U is uniform over 256
// values. Terms with p_i == 0 are treated as 0 log 0 = 0.
func klDivergenceFromUniformBytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var hist [256]int
	for _, b := range data {
		hist[b]++
	}
	n := float64(len(data))
	log2u := math.Log2(1.0 / 256.0)
	var kl float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		kl += p * (math.Log2(p) - log2u)
	}
	return kl
}

// chiSquareUniformBytes returns the chi-square statistic of `data`'s
// byte-value distribution against a uniform 256-bin expectation (df=255,
// uniform band at large N is approximately [220, 292] for p ∈ [0.01,
// 0.99] and grows sublinearly).
func chiSquareUniformBytes(data []byte) float64 {
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

// xorBytes returns a XOR b, len == min(len(a), len(b)).
func xorBytes(a, b []byte) []byte {
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

// ---------------------------------------------------------------------------
// Layer A — Naive statistical distinguisher on C1 XOR C2 under nonce reuse.
//
// Under the pre-v0.3.0 (Single Ouroboros, barrier-off) construction, C1
// XOR C2 concentrated recoverable structure into a narrow ~5.4x-floor
// byte-histogram tilt that the demasker could exploit. Under v0.3.0's
// always-on 48-bit interlock, per-chunk mask triples permute plaintext
// bits into 3 lane-scrambled snake payloads BEFORE cobs + pixel encode,
// so the C1 XOR C2 pixel bytes should carry no residual histogram tilt
// against a uniform 256-bin expectation.
//
// This probe measures three statistics on C1 XOR C2's snake regions:
//   - byte-value chi-square against uniform (df = 255)
//   - KL divergence from uniform, in bits
//   - byte-equal rate against the ideal 1/256 floor
//
// Uses ONLY attacker-visible bytes (both ciphertexts + public wire header).
// No knowledge of P1 or P2 is consumed by the statistics.
// ---------------------------------------------------------------------------

func TestRedTeamNonceReuseLayerAHistogram(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	// Fixed session seeds; N nonce-reuse pairs per plaintext-shape cell.
	// Small N + several plaintext shapes stresses whether structured
	// XORs surface any signal above the CSPRNG tail-fill floor.
	const N = 40
	sizes := []int{128, 256, 512}
	shapes := []string{"random", "structured", "near_identical"}
	rng := rand.New(rand.NewSource(0xA17))

	type cell struct {
		Size       int     `json:"plaintext_size"`
		Shape      string  `json:"shape"`
		N          int     `json:"pairs"`
		Bytes      int     `json:"xor_bytes"`
		Chi2Uni    float64 `json:"chi2_uniform_df255"`
		KLbits     float64 `json:"kl_from_uniform_bits"`
		ZeroRate   float64 `json:"byte_equal_rate"`
		FloorRatio float64 `json:"vs_1_over_256_floor"`
	}
	cells := []cell{}

	makePlain := func(size int, shape string, rng *rand.Rand, i int) []byte {
		p := make([]byte, size)
		switch shape {
		case "random":
			rng.Read(p)
		case "structured":
			// JSON-flavoured public schema — deterministic key, varying
			// value regions. Attacker holds the full plaintext (Full KPA);
			// this shape just picks a realistic payload.
			for j := 0; j < size; j++ {
				p[j] = byte(0x20 + ((i*31 + j*7) % 64))
			}
			// Salt a few positions so P1 != P2 non-trivially.
			for j := 0; j < 8 && j*11 < size; j++ {
				p[j*11] = byte((i * 137) & 0xFF)
			}
		case "near_identical":
			// Base plaintext (from rng seed 0) with a single byte flipped
			// per iteration. Under nonce reuse this drives a very
			// narrow-XOR probe — the most favourable Layer 1 signal
			// available.
			baseRng := rand.New(rand.NewSource(0xB40))
			baseRng.Read(p)
			if size > 0 {
				p[size/2] ^= byte(0x01 << (uint(i) % 8))
			}
		}
		return p
	}

	for _, size := range sizes {
		for _, shape := range shapes {
			// Collect the concatenated C1 XOR C2 body across pairs, then
			// evaluate on the concat.
			var xorAll []byte
			zeroCount := 0
			totalCount := 0
			for i := 0; i < N; i++ {
				p1 := makePlain(size, shape, rng, i*2)
				p2 := makePlain(size, shape, rng, i*2+1)
				// Same 8 seeds, same forced nonce on both encryptions —
				// the nonce-reuse lab assumption realised.
				c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
				if err != nil {
					t.Fatalf("Encrypt p1: %v", err)
				}
				c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
				if err != nil {
					t.Fatalf("Encrypt p2: %v", err)
				}
				// Sanity: nonces collide (lab assumption in effect).
				if string(c1[:NonceSize]) != string(c2[:NonceSize]) {
					t.Fatalf("nonce did not collide — setBrokenTestNonce override lost")
				}
				layout := decodeWireNR(c1)
				// Only the container body enters the statistic — nonce +
				// dim-header bytes carry no XOR signal (identical bytes
				// XOR to zero and would over-count the "zero rate").
				bodyXor := xorBytes(c1[NonceSize+4:NonceSize+4+layout.totalPixels*Channels],
					c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])
				xorAll = append(xorAll, bodyXor...)
				for _, b := range bodyXor {
					if b == 0 {
						zeroCount++
					}
					totalCount++
				}
			}
			chi2 := chiSquareUniformBytes(xorAll)
			kl := klDivergenceFromUniformBytes(xorAll)
			zeroRate := float64(zeroCount) / float64(totalCount)
			cells = append(cells, cell{
				Size:       size,
				Shape:      shape,
				N:          N,
				Bytes:      len(xorAll),
				Chi2Uni:    chi2,
				KLbits:     kl,
				ZeroRate:   zeroRate,
				FloorRatio: zeroRate / (1.0 / 256.0),
			})
			t.Logf("Layer A: size=%4d shape=%-14s N=%d bytes=%d chi2=%.1f KL(bits)=%.5f zeroRate=%.5f (%.2fx 1/256 floor)",
				size, shape, N, len(xorAll), chi2, kl, zeroRate, zeroRate/(1.0/256.0))
		}
	}
	emitJSONNR(t, "layer_a_histogram", map[string]any{
		"threat_model": "nonce_reuse+full_kpa",
		"primitive":    "fnv1a128BrokenLab",
		"key_bits":     keyBits,
		"cells":        cells,
	})
}

// ---------------------------------------------------------------------------
// Layer A' — Naive Crib-KPA XOR-constraint match on the wire.
//
// The pre-v0.3.0 Single-Ouroboros nonce-reuse demasker enumerated 56
// (noisePos, rotation) candidates per pixel; the correct pair extracts 7
// data bits per channel matching the KNOWN plaintext XOR at (pixel,
// channel). Under v0.3.0's 3-snake interlock split, the "known plaintext
// XOR at (pixel, channel)" is NOT the raw plaintext-XOR byte — the
// intervening 48-bit interlock permutation redistributes plaintext bits
// across 3 lane-payloads under a per-chunk mask the attacker cannot
// enumerate.
//
// This probe runs the naive Crib-KPA anyway (assuming — incorrectly —
// that plaintext byte b appears at snake-payload-byte b, i.e. as if no
// barrier were present). For each ciphertext pair, for each snake, for
// each candidate startPixel in [0, snake_pixel_count) and each pixel of a
// short probe, count how many pixels yield ANY consistent (noisePos,
// rotation) pair against the assumed plaintext XOR bits. A working
// demasker would produce a distinct startPixel plateau; a broken one
// leaves the constraint unanchored.
//
// This is a null-probe: it measures whether the interlock alone (without
// the attacker peeking at masks or startPixels) neutralises the
// pre-v0.3.0 attack chain.
// ---------------------------------------------------------------------------

// naiveKPAAnchorRate counts, per candidate startPixel, the number of
// probe pixels that admit AT LEAST ONE (np, r) pair matching the
// attacker's assumed plaintext-XOR at (pixel, channel). The assumption
// is deliberately naive — attacker treats snake payload byte b as
// plaintext byte b (i.e., ignores the interlock split). Returns the max
// pixel-match count achieved by any startPixel and the anchoring rate.
func naiveKPAAnchorRate(bodyXor []byte, snakePixels int, snakeBodyOffset int, plainXor []byte, probePixels int) (bestMatches int, distinct int) {
	if probePixels > snakePixels {
		probePixels = snakePixels
	}
	best := 0
	distinctFullyAnchoring := 0
	for sp := 0; sp < snakePixels; sp++ {
		matches := 0
		for pp := 0; pp < probePixels; pp++ {
			ci := (sp + pp) % snakePixels
			pixelOff := snakeBodyOffset + ci*Channels
			// Assume plaintext byte b at (pp*7 + ch) — naive attacker
			// treats snake payload byte b as plaintext byte b.
			anyCandidate := false
			for np := uint(0); np < 8; np++ {
				for r := uint(0); r < 7; r++ {
					ok := true
					for ch := 0; ch < Channels; ch++ {
						cbXor := bodyXor[pixelOff+ch]
						extXor := extract7Broken(cbXor, np)
						unrotXor := rotateBits7(extXor, 7-r)
						// Assumed plaintext XOR bits for (pp, ch): 7 bits
						// packed from plainXor at bit offset pp*56 + ch*7.
						assumed := getBits7Broken(plainXor, pp, ch)
						if unrotXor != assumed {
							ok = false
							break
						}
					}
					if ok {
						anyCandidate = true
						break
					}
				}
				if anyCandidate {
					break
				}
			}
			if anyCandidate {
				matches++
			}
		}
		if matches > best {
			best = matches
		}
		if matches == probePixels {
			distinctFullyAnchoring++
		}
	}
	return best, distinctFullyAnchoring
}

func TestRedTeamNonceReuseLayerANaiveKPA(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x77 ^ i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	// Small plaintexts so the wire is compact and the naive-KPA scan
	// finishes in seconds. Random plaintexts stress the constraint —
	// their XOR is a random 8*len-bit vector and the extract-consistency
	// test has zero prior bias.
	rng := rand.New(rand.NewSource(0xBEEF))
	type cell struct {
		Size          int     `json:"plaintext_size"`
		Shape         string  `json:"shape"`
		Pairs         int     `json:"pairs"`
		ProbePixels   int     `json:"probe_pixels"`
		Snake         int     `json:"snake"`
		BestMatchesMx int     `json:"max_matches_across_startPixels"`
		AvgFullAnchor float64 `json:"avg_startPixels_fully_anchoring"`
	}
	cells := []cell{}

	sizes := []int{128, 256}
	shapes := []string{"random", "near_identical"}
	const pairs = 5
	const probePixels = 8

	for _, size := range sizes {
		for _, shape := range shapes {
			var maxAcrossPairs [3]int
			var sumFullAnchor [3]int
			for pi := 0; pi < pairs; pi++ {
				var p1, p2 []byte
				switch shape {
				case "random":
					p1 = make([]byte, size)
					p2 = make([]byte, size)
					rng.Read(p1)
					rng.Read(p2)
				case "near_identical":
					p1 = make([]byte, size)
					rng.Read(p1)
					p2 = append([]byte(nil), p1...)
					// flip one nibble at the middle
					p2[size/2] ^= 0x0F
				}
				c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
				if err != nil {
					t.Fatalf("Encrypt p1: %v", err)
				}
				c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
				if err != nil {
					t.Fatalf("Encrypt p2: %v", err)
				}
				layout := decodeWireNR(c1)
				bodyXor := xorBytes(layout.body[:layout.totalPixels*Channels],
					c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])
				plainXor := xorBytes(p1, p2)

				for si := 0; si < 3; si++ {
					// bestMatches: max pixel-match count over all startPixels
					// for this snake. distinct: number of startPixels achieving
					// full match on the probe.
					bm, distinct := naiveKPAAnchorRate(
						bodyXor,
						layout.snakePixels[si],
						layout.snakeBodyOffsets[si],
						plainXor,
						probePixels,
					)
					if bm > maxAcrossPairs[si] {
						maxAcrossPairs[si] = bm
					}
					sumFullAnchor[si] += distinct
				}
			}
			for si := 0; si < 3; si++ {
				cells = append(cells, cell{
					Size:          size,
					Shape:         shape,
					Pairs:         pairs,
					ProbePixels:   probePixels,
					Snake:         si,
					BestMatchesMx: maxAcrossPairs[si],
					AvgFullAnchor: float64(sumFullAnchor[si]) / float64(pairs),
				})
				t.Logf("Layer A-KPA: size=%4d shape=%-14s snake=%d pairs=%d probe=%d max_matches=%d full_anchor_avg=%.2f",
					size, shape, si, pairs, probePixels, maxAcrossPairs[si],
					float64(sumFullAnchor[si])/float64(pairs))
			}
		}
	}
	emitJSONNR(t, "layer_a_naive_kpa", map[string]any{
		"threat_model":    "nonce_reuse+full_kpa (attacker knows P1, P2)",
		"primitive":       "fnv1a128BrokenLab",
		"key_bits":        keyBits,
		"probe_pixels":    probePixels,
		"pairs_per_shape": pairs,
		"note":            "Attacker uses NAIVE assumption: snake_payload_byte[b] == plaintext_byte[b]. Under Triple + Interlocked Barrier this is wrong.",
		"cells":           cells,
	})
}

// ---------------------------------------------------------------------------
// Layer B — Startpixel-known constraint match (documented lab peek).
//
// Layer B grants the attacker the single documented lab exception: the
// three snake startPixels. The peek at `startSeed_i.deriveStartPixel(
// nonce, third_i)` is tagged "[lab-peek: sp_i]" at the call site, in
// keeping with the "primary attack result must run under standard
// attacker-visible inputs" scoping. The point of Layer B is not to
// declare a primary break — it is to quantify how much extra reach the
// documented lab peek buys the attacker.
//
// Two variants:
//
//  B.i — Random plaintext pair. The attacker still lacks the per-chunk
//        mask triples, so per snake pixel the "expected snake payload
//        XOR bits" are unknown; the (noisePos, rotation) constraint
//        cannot be anchored via the classical XOR-of-known-XOR match.
//        Measure: max pixel-match count over startPixels (should trend
//        near the false-positive floor of ~56/(2^56) ≈ 0 per pixel).
//
//  B.ii — Quiet-chunk plaintext pair. P1 == P2 except in one 6-byte
//         chunk near the end. All plaintext chunks that are IDENTICAL
//         produce all-zero snake-payload XOR regardless of the per-chunk
//         mask triple. For the corresponding "quiet" pixels the attacker
//         can constrain (np, r): the extracted 7 bits per channel MUST
//         equal zero. Measure: fraction of quiet pixels where a unique
//         (np, r) survives, and how many bits of (np, r) are pinned.
//         This is the sharpest constraint an attacker can extract under
//         Layer B; anything below "unique (np, r)" means the barrier
//         forces a broader ambiguity than the pre-v0.3.0 demasker faced.
// ---------------------------------------------------------------------------

// grantStartPixelsLabPeek is the documented single lab peek used by
// Layer B probes below. It reads `startSeed_i.deriveStartPixel(nonce,
// snakePixels[i])` for i in [0..3) and returns the three offsets.
// EVERY caller is tagged as an attacker-realism lab exception in its
// docstring; the peek is not consumed by Layer A / C / D probes.
func grantStartPixelsLabPeek(nonce []byte, snakePixels [3]int, ss1, ss2, ss3 *Seed128) [3]int {
	return [3]int{
		ss1.deriveStartPixel(nonce, snakePixels[0]),
		ss2.deriveStartPixel(nonce, snakePixels[1]),
		ss3.deriveStartPixel(nonce, snakePixels[2]),
	}
}

// pixelExtractIsAllZero checks: for the given ciphertext-XOR pixel and a
// (np, r) guess, does un-rotating extract7(byte, np) yield all-zero
// 7-bit values across all 8 channels? Returns true iff the constraint
// holds — which means "consistent with dataXOR = 0 at every channel of
// this pixel", i.e., consistent with a quiet chunk under the guessed
// (np, r).
func pixelExtractIsAllZero(bodyXor []byte, pixelOff int, np, r uint) bool {
	for ch := 0; ch < Channels; ch++ {
		ext := extract7Broken(bodyXor[pixelOff+ch], np)
		unrot := rotateBits7(ext, 7-r)
		if unrot != 0 {
			return false
		}
	}
	return true
}

// countAllZeroCandidates enumerates the 56 (np, r) pairs and returns the
// count consistent with all-zero extract at the given pixel. If the
// pixel is truly "quiet" (all snake payload bits are 0), then this
// count equals the number of (np, r) pairs consistent with a random
// noise bit at each channel — which is ALL 56 pairs (since np pinpoints
// the random bit, and r doesn't affect a zero rotation). If the pixel
// is not quiet, the count drops sharply.
func countAllZeroCandidates(bodyXor []byte, pixelOff int) int {
	c := 0
	for np := uint(0); np < 8; np++ {
		for r := uint(0); r < 7; r++ {
			if pixelExtractIsAllZero(bodyXor, pixelOff, np, r) {
				c++
			}
		}
	}
	return c
}

func TestRedTeamNonceReuseLayerBQuietChunk(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x11 * (i + 1))
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	// Build P1, P2 identical except for the middle 6-byte chunk. Every
	// OTHER 48-bit plaintext chunk is "quiet" (P1_chunk == P2_chunk),
	// yielding all-zero snake payload XOR at those chunks regardless of
	// the interlock mask.
	const size = 384 // 64 chunks of 6 bytes each after len prefix
	rng := rand.New(rand.NewSource(0xC0DE))
	p1 := make([]byte, size)
	rng.Read(p1)
	p2 := append([]byte(nil), p1...)
	// Flip the middle chunk (6 bytes) so exactly ONE plaintext chunk is
	// noisy — the rest are guaranteed quiet.
	midChunkOff := (size / 2 / 6) * 6
	for i := 0; i < 6; i++ {
		p2[midChunkOff+i] ^= byte(0x5A + i)
	}

	c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
	if err != nil {
		t.Fatalf("Encrypt p1: %v", err)
	}
	c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
	if err != nil {
		t.Fatalf("Encrypt p2: %v", err)
	}
	layout := decodeWireNR(c1)
	bodyXor := xorBytes(layout.body[:layout.totalPixels*Channels],
		c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])

	// [lab-peek: sp_i] — documented single lab exception for Layer B.
	sp := grantStartPixelsLabPeek(layout.nonce, layout.snakePixels, s1, s2, s3)
	t.Logf("[lab-peek] snake startPixels: sp1=%d sp2=%d sp3=%d (each of %d/%d/%d snake pixels)",
		sp[0], sp[1], sp[2], layout.snakePixels[0], layout.snakePixels[1], layout.snakePixels[2])

	// For each snake, walk pixels in payload order (starting at sp_i)
	// and count how many are "candidate quiet" — i.e. bodyXor's 8
	// channel bytes admit at least one (np, r) making the extract
	// all-zero. Compare against a uniform-random-XOR baseline expectation.
	//
	// Attacker-realism note: this loop consumes bodyXor + sp_i only. No
	// mask peek, no dataSeed peek, no plaintext-byte peek (P1 XOR P2 is
	// used only in the terminal-stage validation printout at the end,
	// tagged [audit]).
	type snakeResult struct {
		Snake              int     `json:"snake"`
		Pixels             int     `json:"snake_pixels"`
		StartPixel         int     `json:"start_pixel"`
		QuietCandidateNumr int     `json:"quiet_candidate_pixels"`
		FullyQuietPixels   int     `json:"fully_quiet_pixels_all56_np_r_admit"`
		AmbiguityBits      float64 `json:"avg_log2_np_r_candidates_on_quiet_pixels"`
	}
	results := []snakeResult{}
	for si := 0; si < 3; si++ {
		quietCandidates := 0
		fullyQuiet := 0
		sumLog2 := 0.0
		quietCount := 0
		for pp := 0; pp < layout.snakePixels[si]; pp++ {
			ci := (sp[si] + pp) % layout.snakePixels[si]
			pixelOff := layout.snakeBodyOffsets[si] + ci*Channels
			cnt := countAllZeroCandidates(bodyXor, pixelOff)
			if cnt >= 1 {
				quietCandidates++
			}
			if cnt == 56 {
				fullyQuiet++
			}
			if cnt >= 1 {
				sumLog2 += math.Log2(float64(cnt))
				quietCount++
			}
		}
		avgLog2 := 0.0
		if quietCount > 0 {
			avgLog2 = sumLog2 / float64(quietCount)
		}
		results = append(results, snakeResult{
			Snake:              si,
			Pixels:             layout.snakePixels[si],
			StartPixel:         sp[si],
			QuietCandidateNumr: quietCandidates,
			FullyQuietPixels:   fullyQuiet,
			AmbiguityBits:      avgLog2,
		})
		t.Logf("Layer B (quiet-chunk): snake=%d pixels=%d sp=%d quiet-candidates=%d fully-quiet=%d avg log2 candidates=%.2f",
			si, layout.snakePixels[si], sp[si], quietCandidates, fullyQuiet, avgLog2)
	}

	// [audit] terminal-stage ground-truth compare: what fraction of the
	// pixels should be "quiet" if the attacker could see the mask?
	// Under a P1/P2 differing in one 48-bit chunk, every other chunk is
	// quiet (all snake_i_XOR bits at that chunk are 0). The snake pixel
	// count carrying quiet chunks is (chunks_quiet * 16 bits) / 56 bits
	// per pixel, so audit expectation ≈ (num_chunks - 1) * 16 / 56
	// approximated by fraction of quiet snake payload bytes per snake.
	plainXor := xorBytes(p1, p2)
	xorHW := 0
	for _, b := range plainXor {
		xorHW += popcount8(b)
	}
	t.Logf("[audit] plaintext XOR Hamming weight = %d bits (in %d bytes = %d bits total)", xorHW, len(plainXor), len(plainXor)*8)

	emitJSONNR(t, "layer_b_quiet_chunk", map[string]any{
		"threat_model":        "nonce_reuse+full_kpa+startPixel_labpeek",
		"primitive":           "fnv1a128BrokenLab",
		"key_bits":            keyBits,
		"plaintext_size":      size,
		"differing_chunk":     midChunkOff,
		"plain_xor_HW_bits":   xorHW,
		"per_snake":           results,
		"quiet_expectation":   "if all pixels were quiet, per pixel np is pinned (8 candidates) since noise bit at np is random and always the only nonzero bit; r is unconstrained → per pixel candidates = 8 (log2 = 3)",
		"barrier_expectation": "under the interlock, 'quiet snake XOR' at a chunk is guaranteed for chunks where P1_chunk==P2_chunk regardless of masks — but the plaintext-chunk-to-snake-payload-byte alignment is byte-boundary-aware. A snake pixel spans ~7 snake payload bytes ≈ 3.5 plaintext chunks worth of split bits, so 'fully quiet' pixel count is fewer than 'candidate quiet' pixel count.",
	})
}

// TestRedTeamNonceReuseLayerBRandomPair measures the false-positive
// floor of the quiet-chunk probe under a fully-random plaintext pair.
// Since random P1 XOR P2 has HW ~ 4 bits per byte, no chunk is quiet and
// no pixel should register any (np, r) yielding all-zero extract on all
// 8 channels — the "quiet candidate" rate should hug the 8*7/2^56
// per-pixel false-positive floor.
func TestRedTeamNonceReuseLayerBRandomPair(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x33 * (i + 1))
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	const size = 384
	rng := rand.New(rand.NewSource(0xD00D))
	p1 := make([]byte, size)
	p2 := make([]byte, size)
	rng.Read(p1)
	rng.Read(p2)

	c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
	if err != nil {
		t.Fatalf("Encrypt p1: %v", err)
	}
	c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
	if err != nil {
		t.Fatalf("Encrypt p2: %v", err)
	}
	layout := decodeWireNR(c1)
	bodyXor := xorBytes(layout.body[:layout.totalPixels*Channels],
		c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])

	// [lab-peek: sp_i] — documented single lab exception, matches the
	// Quiet-Chunk probe's peek.
	sp := grantStartPixelsLabPeek(layout.nonce, layout.snakePixels, s1, s2, s3)
	_ = sp

	// Random-pair floor: count of (np, r) admitting all-zero extract per
	// pixel across the whole snake region (payload-order irrelevant here
	// because we are measuring the floor, not the recovery rate).
	type snakeResult struct {
		Snake              int     `json:"snake"`
		Pixels             int     `json:"snake_pixels"`
		AnyCandidatePixels int     `json:"pixels_with_at_least_1_np_r_admitting_allzero"`
		AllCandidatePixels int     `json:"pixels_with_all_56_admitting_allzero"`
		MeanCandidates     float64 `json:"mean_np_r_candidates_per_pixel"`
	}
	results := []snakeResult{}
	for si := 0; si < 3; si++ {
		anyC := 0
		allC := 0
		sumC := 0
		for pp := 0; pp < layout.snakePixels[si]; pp++ {
			pixelOff := layout.snakeBodyOffsets[si] + pp*Channels
			cnt := countAllZeroCandidates(bodyXor, pixelOff)
			if cnt >= 1 {
				anyC++
			}
			if cnt == 56 {
				allC++
			}
			sumC += cnt
		}
		results = append(results, snakeResult{
			Snake:              si,
			Pixels:             layout.snakePixels[si],
			AnyCandidatePixels: anyC,
			AllCandidatePixels: allC,
			MeanCandidates:     float64(sumC) / float64(layout.snakePixels[si]),
		})
		t.Logf("Layer B (random floor): snake=%d pixels=%d any=%d all=%d mean_candidates_per_pixel=%.4f",
			si, layout.snakePixels[si], anyC, allC, float64(sumC)/float64(layout.snakePixels[si]))
	}

	emitJSONNR(t, "layer_b_random_floor", map[string]any{
		"threat_model": "nonce_reuse+full_kpa+startPixel_labpeek",
		"primitive":    "fnv1a128BrokenLab",
		"key_bits":     keyBits,
		"per_snake":    results,
	})
}

// ---------------------------------------------------------------------------
// Layer B' — Constrained (np, r) recovery via ALL-KNOWN chunk oracle
// (upper-bound probe).
//
// This probe is deliberately GENEROUS to the attacker: it grants the
// attacker not only the startPixels but ALSO the per-chunk mask triples
// (i.e., the interlock lockSeed is treated as revealed). Under this
// upper-bound gift, the pre-v0.3.0 Layer 1 constraint match applies
// unchanged: per pixel, (np, r) is uniquely recovered from any two
// nonzero-diff pixels of a nonce-reuse pair.
//
// The point of Layer B' is not attacker-realistic — no attacker gets the
// masks. It quantifies the upper-bound recovery rate the barrier
// permits IF a hypothetical primitive break gave the attacker the mask
// stream: with masks known, the pre-v0.3.0 demasker's Layer 1 succeeds
// at 99.14-99.30% per-pixel (see REDTEAM-v0.2.md Phase 2d demasker
// validation table). This probe verifies that the barrier does not
// separately break the constraint match — the mask is the sole
// architectural closure.
//
// Every step of this probe is a documented lab peek; the results are
// UPPER BOUNDS, not attacker-realistic capabilities.
// ---------------------------------------------------------------------------

func TestRedTeamNonceReuseLayerBMaskOraclePeek(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x55 ^ (i * 3))
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	const size = 384
	rng := rand.New(rand.NewSource(0xF00D))
	p1 := make([]byte, size)
	p2 := make([]byte, size)
	rng.Read(p1)
	rng.Read(p2)

	c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
	if err != nil {
		t.Fatalf("Encrypt p1: %v", err)
	}
	c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
	if err != nil {
		t.Fatalf("Encrypt p2: %v", err)
	}
	layout := decodeWireNR(c1)
	bodyXor := xorBytes(layout.body[:layout.totalPixels*Channels],
		c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])

	// [lab-peek: sp_i] and [lab-peek: masks] — this is the mask-oracle
	// upper-bound probe. The revelation is documented in the test
	// docstring and is NOT attacker-realistic. Results here are upper
	// bounds, not achievable capability.
	sp := grantStartPixelsLabPeek(layout.nonce, layout.snakePixels, s1, s2, s3)

	// Compute snake payload XORs exactly as the encoder does — this uses
	// the true lockSeed (lab peek). The "expected snake payload XOR"
	// stream per snake is:
	//   snake_i_payload_XOR = cobs(splitlane_i(P1)) XOR cobs(splitlane_i(P2))
	// However Under the shipped snake payload layout, the payload byte
	// stream INSIDE each snake is:
	//   payload_i = cobs(lane_i) || 0x00 || CSPRNG_tail_fill
	// The CSPRNG tail-fill differs per encryption, so the XOR beyond the
	// COBS terminator is uncorrelated between messages. Restrict the
	// recovery pass to the payload prefix where both encryptions
	// share deterministic bytes.
	//
	// [lab-peek: masks]
	p1Framed := prependTripleLen(p1)
	p2Framed := prependTripleLen(p2)
	bp := buildLockBatchPRF48_128Cfg(nil, ls, layout.nonce)
	l0a, l1a, l2a := splitTriple48LockedBatch(p1Framed, bp)
	l0b, l1b, l2b := splitTriple48LockedBatch(p2Framed, bp)
	// COBS-encode per snake lane to get the deterministic byte prefix.
	snakeCobs1 := [3][]byte{cobsEncode(l0a), cobsEncode(l1a), cobsEncode(l2a)}
	snakeCobs2 := [3][]byte{cobsEncode(l0b), cobsEncode(l1b), cobsEncode(l2b)}
	// The deterministic prefix per snake is min(len(cobs1), len(cobs2))
	// (the terminator sits at position max(...) actually but the safer
	// bound is min). Beyond that byte, snake payload includes the 0x00
	// terminator or CSPRNG fill; recovery there is undefined.
	// Prefix bit length constrains how many pixel channels we probe.
	prefixBits := [3]int{
		min3(len(snakeCobs1[0]), len(snakeCobs2[0])) * 8,
		min3(len(snakeCobs1[1]), len(snakeCobs2[1])) * 8,
		min3(len(snakeCobs1[2]), len(snakeCobs2[2])) * 8,
	}
	// snake payload XOR at bit offset b within the prefix range:
	//   xorPayload_i[b] = cobs1_i[b/8] XOR cobs2_i[b/8], extracted at (b%8)
	snakePayloadXor := [3][]byte{
		xorBytes(snakeCobs1[0][:min3(len(snakeCobs1[0]), len(snakeCobs2[0]))], snakeCobs2[0]),
		xorBytes(snakeCobs1[1][:min3(len(snakeCobs1[1]), len(snakeCobs2[1]))], snakeCobs2[1]),
		xorBytes(snakeCobs1[2][:min3(len(snakeCobs1[2]), len(snakeCobs2[2]))], snakeCobs2[2]),
	}

	type snakeResult struct {
		Snake              int `json:"snake"`
		Pixels             int `json:"snake_pixels"`
		StartPixel         int `json:"start_pixel"`
		ProbedPixels       int `json:"pixels_probed_within_deterministic_prefix"`
		UniqueNpR          int `json:"pixels_with_unique_np_r"`
		MultipleCandidates int `json:"pixels_with_multiple_np_r_candidates"`
		ZeroCandidates     int `json:"pixels_with_zero_np_r_candidates"`
	}
	results := []snakeResult{}
	for si := 0; si < 3; si++ {
		unique, multi, zero := 0, 0, 0
		probed := 0
		for pp := 0; pp < layout.snakePixels[si]; pp++ {
			// The pixel's payload bits sit at snake bit-offset [pp*56, (pp+1)*56).
			bitStart := pp * DataBitsPerPixel
			if bitStart+DataBitsPerPixel > prefixBits[si] {
				break
			}
			ci := (sp[si] + pp) % layout.snakePixels[si]
			pixelOff := layout.snakeBodyOffsets[si] + ci*Channels

			candidates := 0
			for np := uint(0); np < 8; np++ {
				for r := uint(0); r < 7; r++ {
					ok := true
					for ch := 0; ch < Channels; ch++ {
						ext := extract7Broken(bodyXor[pixelOff+ch], np)
						unrot := rotateBits7(ext, 7-r)
						// Expected snake-payload XOR 7 bits at (pp, ch).
						expected := getBits7Broken(snakePayloadXor[si], pp, ch)
						if unrot != expected {
							ok = false
							break
						}
					}
					if ok {
						candidates++
					}
				}
			}
			switch {
			case candidates == 1:
				unique++
			case candidates > 1:
				multi++
			default:
				zero++
			}
			probed++
		}
		results = append(results, snakeResult{
			Snake:              si,
			Pixels:             layout.snakePixels[si],
			StartPixel:         sp[si],
			ProbedPixels:       probed,
			UniqueNpR:          unique,
			MultipleCandidates: multi,
			ZeroCandidates:     zero,
		})
		t.Logf("Layer B' (mask oracle upper bound): snake=%d probed=%d unique(np,r)=%d multi=%d zero=%d",
			si, probed, unique, multi, zero)
	}
	emitJSONNR(t, "layer_b_mask_oracle_peek", map[string]any{
		"threat_model": "nonce_reuse+full_kpa+startPixel_peek+MASK_ORACLE_PEEK (upper bound, NOT attacker-realistic)",
		"primitive":    "fnv1a128BrokenLab",
		"key_bits":     keyBits,
		"per_snake":    results,
		"note":         "This probe reveals BOTH the startPixels and the interlock mask triples to the attacker. Results are the upper bound of what the pre-v0.3.0 demasker Layer 1 can recover IF a hypothetical primitive break gave the attacker the lockSeed. Under attacker-realistic inputs (no mask peek), the recovery rate drops to the Layer B random floor.",
	})
}

// min3 is a local min for readability; go stdlib min() exists but this
// keeps the site self-contained.
func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Layer D — Multi-pair cross-message statistics.
//
// If the attacker collects N > 2 nonce-reuse ciphertexts under the same
// seeds, do statistics across pairs reveal any deterministic per-pixel
// residue the barrier fails to whiten? Measure: per-pixel byte-value
// histogram, chi-square, per-pixel entropy pooled across pairs. If some
// pixel positions have a "sticky" pattern across pairs, that leaks
// per-pixel PRF structure (channelXOR + noisePos + rotation are
// deterministic per pixel under nonce reuse, so this probe tests
// whether the CSPRNG noise bit + CSPRNG tail-fill effectively neutralise
// the deterministic pipeline).
// ---------------------------------------------------------------------------

func TestRedTeamNonceReuseLayerDMultiPair(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0xC1 ^ i*2)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	const size = 256
	const N = 30 // 30 different plaintexts, all under the same forced nonce
	rng := rand.New(rand.NewSource(0xFA57))

	// Collect N ciphertexts.
	cts := make([][]byte, N)
	for i := 0; i < N; i++ {
		p := make([]byte, size)
		rng.Read(p)
		ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		cts[i] = ct
	}
	layout := decodeWireNR(cts[0])

	// For each container-body byte position, pool all N byte values and
	// measure the chi-square vs uniform (expected each of 256 values
	// appears N/256 times — with N=30 the expected is 30/256 ≈ 0.117
	// so cell chi-square is very high by definition unless we aggregate
	// across many positions). Aggregate all bytes across the snake
	// body — statistics of the "always deterministic PRF pipeline" is
	// what we test for leakage.

	// Alternative more meaningful measure at N=30: per byte position,
	// count distinct byte values observed. If per-position pipeline is
	// deterministic and CSPRNG-whitened, distinct count should be
	// binomially distributed around 1 - (1 - 1/256)^N ≈ 0.111 * 256 ≈
	// 28.5 per position for N=30 (near-perfectly random). If pipeline
	// leaks a fixed bit, distinct count drops sharply on the leaked bit.

	type posStat struct {
		Snake        int `json:"snake"`
		PosInSnake   int `json:"pos_in_snake"`
		DistinctVals int `json:"distinct_byte_values"`
	}
	// Aggregate distinct-values across the whole snake body.
	type snakeStat struct {
		Snake              int     `json:"snake"`
		SnakeBytes         int     `json:"snake_body_bytes"`
		Ns                 int     `json:"pairs_N"`
		MeanDistinctPerPos float64 `json:"mean_distinct_byte_values_per_position"`
		MinDistinctPerPos  int     `json:"min_distinct_byte_values_per_position"`
		MaxDistinctPerPos  int     `json:"max_distinct_byte_values_per_position"`
		BucketLE2          int     `json:"positions_distinct_le_2"`
		BucketLE4          int     `json:"positions_distinct_le_4"`
		BucketLE8          int     `json:"positions_distinct_le_8"`
		BucketLE16         int     `json:"positions_distinct_le_16"`
		BucketGE17         int     `json:"positions_distinct_ge_17"`
	}
	sstats := []snakeStat{}

	// posStat is retained (currently unused as summary output) — future
	// per-position emission would use it. Reference to prevent unused-decl.
	_ = posStat{}

	// Break out the distinct-count distribution by threshold buckets so
	// a "constant except noise-bit" residue (distinct=2, from the fixed
	// public 4-byte length prefix + any other structurally-constant
	// channel bits) is separable from the uniform floor.
	for si := 0; si < 3; si++ {
		off, end := layout.snakeBodyOffsets[si], layout.snakeBodyEnds[si]
		npos := end - off
		distinctCounts := make([]int, npos)
		for pos := 0; pos < npos; pos++ {
			seen := make(map[byte]struct{}, N)
			for i := 0; i < N; i++ {
				body := cts[i][NonceSize+4:]
				seen[body[off+pos]] = struct{}{}
			}
			distinctCounts[pos] = len(seen)
		}
		sort.Ints(distinctCounts)
		mean := 0.0
		buckets := [5]int{} // <=2, 3-4, 5-8, 9-16, >=17
		for _, d := range distinctCounts {
			mean += float64(d)
			switch {
			case d <= 2:
				buckets[0]++
			case d <= 4:
				buckets[1]++
			case d <= 8:
				buckets[2]++
			case d <= 16:
				buckets[3]++
			default:
				buckets[4]++
			}
		}
		mean /= float64(len(distinctCounts))
		sstats = append(sstats, snakeStat{
			Snake:              si,
			SnakeBytes:         npos,
			Ns:                 N,
			MeanDistinctPerPos: mean,
			MinDistinctPerPos:  distinctCounts[0],
			MaxDistinctPerPos:  distinctCounts[len(distinctCounts)-1],
			BucketLE2:          buckets[0],
			BucketLE4:          buckets[1],
			BucketLE8:          buckets[2],
			BucketLE16:         buckets[3],
			BucketGE17:         buckets[4],
		})
		expectedMean := 256.0 * (1.0 - math.Pow(255.0/256.0, float64(N)))
		t.Logf("Layer D (multi-pair): snake=%d pos=%d N=%d mean_distinct=%.2f (expected %.2f under uniform) min=%d max=%d buckets(<=2/<=4/<=8/<=16/>=17)=%d/%d/%d/%d/%d",
			si, npos, N, mean, expectedMean, distinctCounts[0], distinctCounts[len(distinctCounts)-1],
			buckets[0], buckets[1], buckets[2], buckets[3], buckets[4])
	}
	emitJSONNR(t, "layer_d_multi_pair", map[string]any{
		"threat_model":  "nonce_reuse (N pairs) + Full KPA (P1..PN known)",
		"primitive":     "fnv1a128BrokenLab",
		"key_bits":      keyBits,
		"pairs_N":       N,
		"per_snake":     sstats,
		"floor_formula": "under uniform per-position bytes, expected distinct at N draws = 256*(1 - (255/256)^N)",
	})
}

// ---------------------------------------------------------------------------
// Layer C — FNV-1a algebraic recovery, threat-model dependency.
//
// The pre-v0.3.0 nonce-reuse chain (Single Ouroboros, barrier-off)
// terminated at "reconstructed pure ChainHash stream", which under
// FNV-1a exposed enough structure for NIST STS to flag spectral,
// block-frequency, cumulative-sums, and runs tests (6/188 fails,
// REDTEAM-v0.2.md Phase 2d). Under v0.3.0's 48-bit interlock, Layer 1
// cannot be run without the mask (Layer B random floor is essentially
// zero on random plaintexts and constrained-only on all-quiet chunks).
// Layer C is therefore architecturally foreclosed by Layer B failure —
// there is no ChainHash stream to reconstruct.
//
// This probe formalises the closure: it attempts the Layer 1
// reconstruction under the (attacker-realistic) NO-mask-peek scenario
// and verifies that no per-pixel channelXOR value can be recovered.
// Returns the count of pixels where a unique channelXOR was determined —
// which should be zero on random-plaintext pairs.
// ---------------------------------------------------------------------------

func TestRedTeamNonceReuseLayerCFNVAlgebraic(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x88 ^ i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	const size = 512
	rng := rand.New(rand.NewSource(0x1234))
	p1 := make([]byte, size)
	p2 := make([]byte, size)
	rng.Read(p1)
	rng.Read(p2)

	c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
	if err != nil {
		t.Fatalf("Encrypt p1: %v", err)
	}
	c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
	if err != nil {
		t.Fatalf("Encrypt p2: %v", err)
	}
	layout := decodeWireNR(c1)
	bodyXor := xorBytes(layout.body[:layout.totalPixels*Channels],
		c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])

	// [lab-peek: sp_i] — same documented Layer B lab exception. Even with
	// this peek granted, Layer C's precondition (recovered channelXOR
	// stream) requires Layer 1 succeeding under NO mask peek, which
	// itself requires knowing the expected snake payload XOR bits —
	// which requires the mask. This attempt therefore uses the naive
	// (mask == identity) assumption and measures how many pixels admit
	// a unique (np, r) under that wrong assumption.
	sp := grantStartPixelsLabPeek(layout.nonce, layout.snakePixels, s1, s2, s3)

	// For each snake, try to recover a unique (np, r) per pixel using
	// the NAIVE mask assumption (attacker treats snake_payload_byte[b]
	// == plaintext_XOR_byte[b]). No lockSeed peek.
	plainXor := xorBytes(p1, p2)
	type snakeResult struct {
		Snake             int     `json:"snake"`
		Pixels            int     `json:"snake_pixels"`
		StartPixel        int     `json:"start_pixel"`
		UniqueRecovered   int     `json:"pixels_with_unique_np_r"`
		AnyRecovered      int     `json:"pixels_with_at_least_1_np_r"`
		AvgCandidateCount float64 `json:"avg_np_r_candidates_over_admitted_pixels"`
	}
	results := []snakeResult{}
	for si := 0; si < 3; si++ {
		unique, any, sumC, admC := 0, 0, 0, 0
		for pp := 0; pp < layout.snakePixels[si]; pp++ {
			ci := (sp[si] + pp) % layout.snakePixels[si]
			pixelOff := layout.snakeBodyOffsets[si] + ci*Channels
			candidates := 0
			for np := uint(0); np < 8; np++ {
				for r := uint(0); r < 7; r++ {
					ok := true
					for ch := 0; ch < Channels; ch++ {
						ext := extract7Broken(bodyXor[pixelOff+ch], np)
						unrot := rotateBits7(ext, 7-r)
						assumed := getBits7Broken(plainXor, pp, ch)
						if unrot != assumed {
							ok = false
							break
						}
					}
					if ok {
						candidates++
					}
				}
			}
			if candidates >= 1 {
				any++
				sumC += candidates
				admC++
				if candidates == 1 {
					unique++
				}
			}
		}
		avgC := 0.0
		if admC > 0 {
			avgC = float64(sumC) / float64(admC)
		}
		results = append(results, snakeResult{
			Snake:             si,
			Pixels:            layout.snakePixels[si],
			StartPixel:        sp[si],
			UniqueRecovered:   unique,
			AnyRecovered:      any,
			AvgCandidateCount: avgC,
		})
		t.Logf("Layer C (FNV algebraic precondition): snake=%d pixels=%d sp=%d unique=%d any=%d avg_candidates=%.3f",
			si, layout.snakePixels[si], sp[si], unique, any, avgC)
	}
	emitJSONNR(t, "layer_c_fnv_algebraic_precondition", map[string]any{
		"threat_model": "nonce_reuse+full_kpa+startPixel_labpeek+NAIVE_mask_assumption (no mask peek)",
		"primitive":    "fnv1a128BrokenLab",
		"key_bits":     keyBits,
		"per_snake":    results,
		"conclusion":   "Layer C (FNV-1a algebraic seed recovery from reconstructed ChainHash stream) is architecturally foreclosed by Layer 1 failure under the attacker-realistic no-mask-peek assumption. Under the mask-oracle upper-bound peek (Layer B'), Layer C is not further neutralised by the barrier — the closure lives in the mask, not in the pixel layer.",
	})
	_ = fmt.Sprintf // keep import if pruning
}

// ---------------------------------------------------------------------------
// Cross-message decrypt — the sharpest headline: given N nonce-reuse
// ciphertexts with Full KPA on N-1 of them, can the attacker decrypt
// the Nth message?
//
// Pre-v0.3.0 (Single Ouroboros, barrier-off): the demasker recovers
// per-pixel (np, r, chanXOR) from any nonce-reuse pair with Full KPA,
// then applies the same demasker to the third ciphertext — at ~99.17%
// raw byte match. This is REDTEAM-v0.2.md Phase 2d's "classical
// keystream-reuse decrypt".
//
// v0.3.0 (Triple + always-on 48-bit interlock): the demasker's Layer 1
// requires the per-chunk mask triples the attacker cannot enumerate.
// Under attacker-realistic no-lab-peek inputs, the demasker returns
// zero anchors from any nonce-reuse pair; the third-message decrypt
// therefore has nothing to apply.
//
// This probe runs the pre-v0.3.0 classical keystream-reuse decrypt end
// to end against v0.3.0 ciphertexts and measures the recovered byte
// match on the third message. Three regimes reported: (A) no lab peek,
// (B) startPixel peek, (B') mask-oracle peek. Only regime B' should
// achieve high recovery — that quantifies the mask-oracle upper bound
// while confirming the attacker-realistic (A) verdict.
// ---------------------------------------------------------------------------

// recoverPerPixelNpRUnderMaskOracle demasks one snake's pixel stream
// using the known snake payload XOR bits (lab peek — mask oracle) and
// returns the recovered per-pixel (noisePos, rotation, chanXOR56)
// triple. Attacker-realistic reference implementation of the
// pre-v0.3.0 Phase 2d Layer 1 constraint match, ported to a v0.3.0
// snake region. Returns per-pixel (np, r, chanXOR56) only for pixels
// where the constraint uniquely anchors; unresolved pixels report
// np=r=chanXOR56=0 with a false ok.
type demaskedPixel struct {
	Np, R     uint
	ChanXOR56 uint64
	Ok        bool
}

func recoverPerPixelNpRUnderMaskOracle(bodyXor []byte, snakePixels int, snakeBodyOffset int, startPixel int, snakePayloadXor []byte, maxPixels int) []demaskedPixel {
	if maxPixels > snakePixels {
		maxPixels = snakePixels
	}
	out := make([]demaskedPixel, maxPixels)
	for pp := 0; pp < maxPixels; pp++ {
		bitStart := pp * DataBitsPerPixel
		// Give up if snake payload XOR prefix does not cover this pixel.
		if (bitStart+DataBitsPerPixel+7)/8 > len(snakePayloadXor) {
			break
		}
		ci := (startPixel + pp) % snakePixels
		pixelOff := snakeBodyOffset + ci*Channels
		var found demaskedPixel
		count := 0
		for np := uint(0); np < 8; np++ {
			for r := uint(0); r < 7; r++ {
				ok := true
				for ch := 0; ch < Channels; ch++ {
					ext := extract7Broken(bodyXor[pixelOff+ch], np)
					unrot := rotateBits7(ext, 7-r)
					expected := getBits7Broken(snakePayloadXor, pp, ch)
					if unrot != expected {
						ok = false
						break
					}
				}
				if ok {
					count++
					found = demaskedPixel{Np: np, R: r, Ok: true}
				}
			}
		}
		if count == 1 {
			out[pp] = found
		}
	}
	return out
}

// applyDemaskerToThirdMsg uses recovered per-pixel (np, r) to strip the
// per-pixel PRF pipeline from C3's snake region, yielding the pure
// snake-payload byte stream for that snake. Because the barrier's
// interlock mask is REVEALED under Layer B', the attacker also inverts
// the split-lane XOR to reconstruct the plaintext byte stream. Returns
// the recovered snake payload byte stream for pixel index range
// [startPixel .. startPixel + maxPixels).
func applyDemaskerToThirdMsg(c3Body []byte, snakePixels, snakeBodyOffset, startPixel int, demask []demaskedPixel, snakePayloadC1 []byte) []byte {
	// c3Body is the full container body; snakePayloadC1 is the *known*
	// snake payload of C1 (from the mask-oracle peek's forward
	// splitTriple+cobsEncode step). Given demask[p] = (np, r, chanXOR56),
	// derived from C1 XOR C2 and the C1/C2 snake payload XORs, we can
	// convert C3's per-pixel channel bytes → C3's snake payload bytes:
	//   extract7(C3[c], np) → 7-bit rotated + chanXOR value
	//   unrotate(..., r) → 7 bits of dataBits XOR chanXOR
	//   XOR with chanXOR → 7 bits of dataBits (== C3 snake payload bits)
	// This is the "classical keystream-reuse" recovery — the (np, r,
	// chanXOR56) triple IS the per-pixel keystream, and it applies to
	// any message encrypted under the same (all seeds, same nonce).
	//
	// Note: chanXOR56 is derived within this function from a known-XOR
	// crib on C1: chanXOR56[ch] = unrotate(extract7(C1[c], np), r) XOR
	// snake_payload_C1_bits(pp, ch). We use snakePayloadC1 for the
	// canonical crib.
	_ = snakePayloadC1 // computed from mask peek at caller; retained for
	// contract clarity — the per-pixel chanXOR reveal happens on the
	// C1↔C1_payload side of the peek, not on C3.
	out := make([]byte, 0, len(demask)*7)
	for pp, dp := range demask {
		if !dp.Ok {
			// unrecovered pixel — emit garbage bytes so byte offsets
			// remain aligned with the ground-truth snake payload.
			for k := 0; k < 7; k++ {
				out = append(out, 0)
			}
			continue
		}
		ci := (startPixel + pp) % snakePixels
		pixelOff := snakeBodyOffset + ci*Channels
		// Recover per-pixel chanXOR from C1 and snakePayloadC1 crib.
		var packed uint64
		for ch := 0; ch < Channels; ch++ {
			ext := extract7Broken(c3Body[pixelOff+ch], dp.Np)
			unrot := rotateBits7(ext, 7-dp.R)
			// unrot = dataBits_C3[ch] XOR chanXOR[ch]
			// chanXOR[ch] = unrotate(extract7(C1[c], np), r) XOR C1_snakePayload_bits(pp, ch)
			// (we ARE the caller's lab-peek pipeline so we can plumb this
			// via snakePayloadC1). Instead of recomputing here, we
			// require the caller to hand `chanXORPerPixel` in — but since
			// the caller has both C1 body and C1 payload, the simplest
			// wire is to compute chanXOR inline.
			// For clarity: chanXOR_bits = extract7(C1[c], dp.Np) after
			// un-rotate, XOR with snakePayloadC1's 7 bits at (pp, ch).
			// Access to the C1 body is via c3Body arg — but c3Body IS C3;
			// the caller passes C3 here. So we need a separate
			// chanXORPerPixel slice from the caller. For simplicity we
			// swap the interface: the caller computes chanXOR56[pp] from
			// C1 + snakePayloadC1 and passes it in the demask slice.
			// See dp.ChanXOR56 field.
			raw7 := unrot ^ byte((dp.ChanXOR56>>uint(ch*DataBitsPerChannel))&0x7F)
			packed |= uint64(raw7) << uint(ch*DataBitsPerChannel)
		}
		// Pack 56 bits into 7 bytes little-endian.
		for k := 0; k < 7; k++ {
			out = append(out, byte(packed>>uint(k*8)))
		}
	}
	return out
}

func TestRedTeamNonceReuseCrossMessageDecrypt(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x66 ^ (i * 5))
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128(t, keyBits)

	const size = 320
	rng := rand.New(rand.NewSource(0xACE1))
	p1 := make([]byte, size)
	p2 := make([]byte, size)
	p3 := make([]byte, size)
	rng.Read(p1)
	rng.Read(p2)
	rng.Read(p3)

	c1, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p1)
	if err != nil {
		t.Fatalf("Encrypt p1: %v", err)
	}
	c2, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p2)
	if err != nil {
		t.Fatalf("Encrypt p2: %v", err)
	}
	c3, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, p3)
	if err != nil {
		t.Fatalf("Encrypt p3: %v", err)
	}
	layout := decodeWireNR(c1)
	bodyXor12 := xorBytes(layout.body[:layout.totalPixels*Channels],
		c2[NonceSize+4:NonceSize+4+layout.totalPixels*Channels])
	c3Body := c3[NonceSize+4 : NonceSize+4+layout.totalPixels*Channels]

	// Regime A — attacker-realistic (no lab peek). Attacker has C1, C2,
	// C3, P1, P2 and tries to decrypt P3 by first recovering the
	// per-pixel (np, r) from (C1, C2, P1, P2). The naive assumption
	// (snake payload byte == plaintext byte) is required — no mask,
	// no startPixel. Report: recovered bytes of P3 that match ground
	// truth (should be at chance ~1/256 across snake data pixels).
	plainXor := xorBytes(p1, p2)
	regimeA := func() (matchBytes, totalBytes int) {
		// For each snake, walk pixels in body order (no startPixel peek —
		// attacker must guess ordering; naive assumes body position ==
		// snake pixel position). Attempt to recover unique (np, r) per
		// pixel via the naive constraint. Under Triple + Interlocked, no
		// startPixel gives unique anchoring across probe pixels; no
		// unique (np, r) is produced.
		for si := 0; si < 3; si++ {
			for pp := 0; pp < layout.snakePixels[si]; pp++ {
				pixelOff := layout.snakeBodyOffsets[si] + pp*Channels
				var recoveredNp, recoveredR uint
				count := 0
				for np := uint(0); np < 8; np++ {
					for r := uint(0); r < 7; r++ {
						ok := true
						for ch := 0; ch < Channels; ch++ {
							ext := extract7Broken(bodyXor12[pixelOff+ch], np)
							unrot := rotateBits7(ext, 7-r)
							assumed := getBits7Broken(plainXor, pp, ch)
							if unrot != assumed {
								ok = false
								break
							}
						}
						if ok {
							count++
							recoveredNp, recoveredR = np, r
						}
					}
				}
				if count != 1 {
					// unresolved — cannot decrypt this pixel of P3.
					continue
				}
				// Recover chanXOR56 from C1 + P1 (naive: snake payload ==
				// plaintext), then apply to C3 to yield "P3 bytes".
				var chanXOR56 uint64
				for ch := 0; ch < Channels; ch++ {
					c1b := layout.body[pixelOff+ch]
					ext := extract7Broken(c1b, recoveredNp)
					unrot := rotateBits7(ext, 7-recoveredR)
					plainBits := getBits7Broken(p1, pp, ch)
					chanXOR56 |= uint64(unrot^plainBits) << uint(ch*DataBitsPerChannel)
				}
				// Decrypt C3 pixel:
				var packed uint64
				for ch := 0; ch < Channels; ch++ {
					ext := extract7Broken(c3Body[pixelOff+ch], recoveredNp)
					unrot := rotateBits7(ext, 7-recoveredR)
					raw7 := unrot ^ byte((chanXOR56>>uint(ch*DataBitsPerChannel))&0x7F)
					packed |= uint64(raw7) << uint(ch*DataBitsPerChannel)
				}
				// Match against ground-truth P3 bytes at (pp * 7 .. (pp+1) * 7)
				// [audit] — this is the terminal-stage validation.
				for k := 0; k < 7; k++ {
					pByte := getBits7Broken(p3, pp, k) // packed as 7-bit
					packedByte := byte((packed >> uint(k*7)) & 0x7F)
					_ = pByte
					_ = packedByte
					// Approximate: compare 7-bit values position-by-position
					// via reconstructed byte stream against p3.
				}
				// Simpler bytewise comparison:
				byteStart := pp * 7
				for k := 0; k < 7 && byteStart+k < len(p3); k++ {
					recoveredByte := byte(packed >> uint(k*8))
					if recoveredByte == p3[byteStart+k] {
						matchBytes++
					}
					totalBytes++
				}
			}
		}
		return
	}

	// Regime B — startPixel peek only (no mask peek). Uses the naive
	// mask assumption but with the correct startPixel per snake. Under
	// the barrier this still cannot uniquely anchor (np, r) because the
	// naive "snake payload byte == plaintext byte" is wrong.
	regimeB := func() (matchBytes, totalBytes int) {
		// [lab-peek: sp_i]
		sp := grantStartPixelsLabPeek(layout.nonce, layout.snakePixels, s1, s2, s3)
		for si := 0; si < 3; si++ {
			for pp := 0; pp < layout.snakePixels[si]; pp++ {
				ci := (sp[si] + pp) % layout.snakePixels[si]
				pixelOff := layout.snakeBodyOffsets[si] + ci*Channels
				var recoveredNp, recoveredR uint
				count := 0
				for np := uint(0); np < 8; np++ {
					for r := uint(0); r < 7; r++ {
						ok := true
						for ch := 0; ch < Channels; ch++ {
							ext := extract7Broken(bodyXor12[pixelOff+ch], np)
							unrot := rotateBits7(ext, 7-r)
							assumed := getBits7Broken(plainXor, pp, ch)
							if unrot != assumed {
								ok = false
								break
							}
						}
						if ok {
							count++
							recoveredNp, recoveredR = np, r
						}
					}
				}
				if count != 1 {
					continue
				}
				var chanXOR56 uint64
				for ch := 0; ch < Channels; ch++ {
					c1b := layout.body[pixelOff+ch]
					ext := extract7Broken(c1b, recoveredNp)
					unrot := rotateBits7(ext, 7-recoveredR)
					plainBits := getBits7Broken(p1, pp, ch)
					chanXOR56 |= uint64(unrot^plainBits) << uint(ch*DataBitsPerChannel)
				}
				var packed uint64
				for ch := 0; ch < Channels; ch++ {
					ext := extract7Broken(c3Body[pixelOff+ch], recoveredNp)
					unrot := rotateBits7(ext, 7-recoveredR)
					raw7 := unrot ^ byte((chanXOR56>>uint(ch*DataBitsPerChannel))&0x7F)
					packed |= uint64(raw7) << uint(ch*DataBitsPerChannel)
				}
				byteStart := pp * 7
				for k := 0; k < 7 && byteStart+k < len(p3); k++ {
					recoveredByte := byte(packed >> uint(k*8))
					if recoveredByte == p3[byteStart+k] {
						matchBytes++
					}
					totalBytes++
				}
			}
		}
		return
	}

	// Regime B' — startPixel peek + mask-oracle peek (upper bound). The
	// attacker gets the true snake payload XOR bits per snake and can
	// uniquely anchor (np, r) per pixel; the recovered chanXOR56 is
	// derived from C1 + true snake_payload_C1 (via mask peek); the
	// pipeline applies to C3 and decrypts snake payload → interleaves
	// the 3 recovered snake payloads through the mask-oracle inverse to
	// yield P3.
	regimeBPrime := func() (matchBytes, totalBytes int) {
		// [lab-peek: sp_i] + [lab-peek: masks]
		sp := grantStartPixelsLabPeek(layout.nonce, layout.snakePixels, s1, s2, s3)
		bp := buildLockBatchPRF48_128Cfg(nil, ls, layout.nonce)

		// Snake payload XOR bits (for anchoring) come from cobs of the
		// splitTriple lanes of P1 and P2.
		p1Framed := prependTripleLen(p1)
		p2Framed := prependTripleLen(p2)
		p1Lanes := [3][]byte{}
		p2Lanes := [3][]byte{}
		p1Lanes[0], p1Lanes[1], p1Lanes[2] = splitTriple48LockedBatch(p1Framed, bp)
		p2Lanes[0], p2Lanes[1], p2Lanes[2] = splitTriple48LockedBatch(p2Framed, bp)
		snakeCobs1 := [3][]byte{cobsEncode(p1Lanes[0]), cobsEncode(p1Lanes[1]), cobsEncode(p1Lanes[2])}
		snakeCobs2 := [3][]byte{cobsEncode(p2Lanes[0]), cobsEncode(p2Lanes[1]), cobsEncode(p2Lanes[2])}
		snakePayloadXor := [3][]byte{}
		for i := 0; i < 3; i++ {
			n := min3(len(snakeCobs1[i]), len(snakeCobs2[i]))
			snakePayloadXor[i] = xorBytes(snakeCobs1[i][:n], snakeCobs2[i][:n])
		}

		// Recover per-pixel (np, r, chanXOR56) per snake by anchoring
		// against snake payload XOR.
		recoveredSnakeBytes := [3][]byte{}
		for si := 0; si < 3; si++ {
			pxls := recoverPerPixelNpRUnderMaskOracle(bodyXor12, layout.snakePixels[si], layout.snakeBodyOffsets[si], sp[si], snakePayloadXor[si], layout.snakePixels[si])
			// Add chanXOR56 from C1 + true snake payload C1 crib.
			for pp := range pxls {
				if !pxls[pp].Ok {
					continue
				}
				ci := (sp[si] + pp) % layout.snakePixels[si]
				pixelOff := layout.snakeBodyOffsets[si] + ci*Channels
				var chanXOR56 uint64
				for ch := 0; ch < Channels; ch++ {
					c1b := layout.body[pixelOff+ch]
					ext := extract7Broken(c1b, pxls[pp].Np)
					unrot := rotateBits7(ext, 7-pxls[pp].R)
					// Snake_payload_C1_bits(pp, ch) from mask peek.
					plainBits := getBits7Broken(snakeCobs1[si], pp, ch)
					chanXOR56 |= uint64(unrot^plainBits) << uint(ch*DataBitsPerChannel)
				}
				pxls[pp].ChanXOR56 = chanXOR56
			}
			// Apply the demasker to C3's snake region.
			recoveredSnakeBytes[si] = applyDemaskerToThirdMsg(c3Body, layout.snakePixels[si], layout.snakeBodyOffsets[si], sp[si], pxls, snakeCobs1[si])
		}

		// Interleave the recovered snake payload bytes through the mask
		// oracle to yield the framed plaintext. First need to peel COBS,
		// then interleaveForTriple48LockedCfg. Because tail-fill differs
		// per encryption and our recovered bytes past the COBS terminator
		// are garbage, restrict interleave to the C3 lane bytes' known
		// deterministic prefix range.
		//
		// Compute the true C3 snake payload lengths (via forward encode
		// under mask peek) so we know where COBS terminates.
		p3Framed := prependTripleLen(p3)
		p3Lanes := [3][]byte{}
		p3Lanes[0], p3Lanes[1], p3Lanes[2] = splitTriple48LockedBatch(p3Framed, bp)
		p3Cobs := [3][]byte{cobsEncode(p3Lanes[0]), cobsEncode(p3Lanes[1]), cobsEncode(p3Lanes[2])}

		// Attacker uses lab peek to sizeknow, but doesn't know exact
		// content — that IS the decrypt problem. Compare the recovered
		// snake payload bytes to the true snake payload bytes (cobs,
		// pre-terminator) — the length is known via the lab peek here.
		for si := 0; si < 3; si++ {
			trueLen := len(p3Cobs[si])
			for k := 0; k < trueLen && k < len(recoveredSnakeBytes[si]); k++ {
				if recoveredSnakeBytes[si][k] == p3Cobs[si][k] {
					matchBytes++
				}
				totalBytes++
			}
		}
		return
	}

	amb, atot := regimeA()
	bmb, btot := regimeB()
	bpmb, bptot := regimeBPrime()
	rate := func(m, t int) float64 {
		if t == 0 {
			return 0
		}
		return float64(m) / float64(t)
	}
	t.Logf("Cross-message decrypt: regime A (no peek)      matched %d/%d bytes (%.4f)", amb, atot, rate(amb, atot))
	t.Logf("Cross-message decrypt: regime B (sp peek)      matched %d/%d bytes (%.4f)", bmb, btot, rate(bmb, btot))
	t.Logf("Cross-message decrypt: regime B' (sp+mask peek) matched %d/%d bytes (%.4f)", bpmb, bptot, rate(bpmb, bptot))
	emitJSONNR(t, "cross_message_decrypt", map[string]any{
		"threat_model":   "nonce_reuse+full_kpa(P1,P2 known); attacker attempts to decrypt bytes of P3 encrypted under same seeds+same forced nonce",
		"primitive":      "fnv1a128BrokenLab",
		"key_bits":       keyBits,
		"plaintext_size": size,
		"regime_A_no_peek": map[string]any{
			"match_bytes": amb,
			"total_bytes": atot,
			"match_rate":  rate(amb, atot),
		},
		"regime_B_startpixel_peek": map[string]any{
			"match_bytes": bmb,
			"total_bytes": btot,
			"match_rate":  rate(bmb, btot),
		},
		"regime_B_prime_mask_oracle_peek": map[string]any{
			"match_bytes": bpmb,
			"total_bytes": bptot,
			"match_rate":  rate(bpmb, bptot),
			"note":        "Upper bound only — attacker does NOT hold the mask oracle. Included to quantify what the barrier's mask secrecy is worth.",
		},
	})
}

// ---------------------------------------------------------------------------
// Cross-track summary — Layer A / A' / B / B' / C / D at a glance.
//
// The individual probes above produce JSON records in tmp/redteam/
// nonce_reuse/*.json; this test aggregates the key headline numbers into
// a single record for the REDTEAM.md rewrite. Runs after all individual
// probes and echoes the summary to the test log.
// ---------------------------------------------------------------------------

func TestRedTeamNonceReuseSummaryDigest(t *testing.T) {
	// Re-read the per-probe JSON files (attacker-visible; this is just
	// aggregation). If any is missing, the digest reports partial —
	// running `go test -run TestRedTeamNonceReuse -v` in one invocation
	// produces all inputs.
	entries := []string{
		"layer_a_histogram",
		"layer_a_naive_kpa",
		"layer_b_quiet_chunk",
		"layer_b_random_floor",
		"layer_b_mask_oracle_peek",
		"layer_c_fnv_algebraic_precondition",
		"layer_d_multi_pair",
	}
	digest := map[string]any{
		"threat_model":     "Full KPA + forced nonce reuse; primitive = FNV-1a on all 8 seeds",
		"attacker_realism": "startPixel_labpeek permitted for Layer B / C only (documented single exception); mask_oracle_peek granted only for Layer B' (upper-bound reference, NOT attacker-realistic)",
		"probe_files":      entries,
	}
	present := 0
	for _, name := range entries {
		p := filepath.Join(tmpNRDir, name+".json")
		if _, err := os.Stat(p); err == nil {
			present++
		}
	}
	digest["probe_files_present"] = present
	emitJSONNR(t, "summary_digest", digest)
	t.Logf("Summary digest: %d/%d probe outputs present", present, len(entries))
}
