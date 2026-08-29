//go:build redteam

package itb

// FNV-1a lo-lane SAT re-verification for the v0.3.0 architecture
// (always-on 48-bit Interlocked Barrier + Triple Ouroboros + 8 mandatory
// seeds). Companion to `redteam_broken_test.go` — this file extends the
// broken-primitive track with FNV-1a-specific SAT-anchoring probes.
//
// Claim under test (REDTEAM.md § "FNV-1a lo-lane SAT — architecturally
// foreclosed"): the pre-v0.3.0 SAT harness that recovered a functional
// FNV-1a lo-lane compound key in ≈ 8 h on Single Ouroboros with the
// barrier disengaged cannot be formulated under v0.3.0 because the
// 48-bit interlock destroys the fixed bit-to-lane anchor the SAT
// depends on. This file quantifies that closure at the anchoring layer.
//
// The pre-v0.3.0 SAT anchored on the mapping
//
//	plaintext byte K → pixel (startPixel + K/7) mod totalPixels
//	                   channel K % 7
//	                   → dataHash(pixel).lo >> 3
//
// which held under Single Ouroboros. Under v0.3.0 the plaintext is
// first prepended with a 4-byte length, then split into three snake
// streams by the 48-bit interlock (a per-chunk PRF-keyed 16-of-48
// balanced partition, ≈ 2^70.20 mask space). Lane i's bytes are then
// COBS-wrapped and encoded into snake i's own container, at a
// snake-i-owned `startPixel_i`. The naive attacker guessing "byte K
// lives at snake K%3, snake pixel (sp_i + (K/3)/7)" is wrong at
// essentially every position once the barrier has permuted the chunk
// bits.
//
// The probes below quantify that failure across two attacker regimes:
//
//   - Attacker-realistic (F1, F4): only public wire bytes + the
//     public-schema crib. Reports the achievable per-pixel candidate
//     set structure and the per-snake displacement fraction.
//   - Lab-peek diagnostic (F2, F3, F5): consumes true seed material
//     in the decision path to establish the upper bound the SAT would
//     have to reach. Ground-truth values are used as the DIRECT
//     discriminator, not as validation prints — the results establish
//     that even the oracle-attacker's naive-crib anchoring fails.
//
// Every probe emits a JSON record under `tmp/redteam/fnv1a_sat/` for
// downstream aggregation. The gitignored `tmp/` path is created
// lazily; failure to write is logged but non-fatal.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// tmpFNVDir is the shared scratch subdir for FNV-1a SAT probes below.
const tmpFNVDir = "tmp/redteam/fnv1a_sat"

// emitJSONFNV writes a compact JSON line under tmpFNVDir/<name>.json.
func emitJSONFNV(t *testing.T, name string, v any) {
	t.Helper()
	if err := os.MkdirAll(tmpFNVDir, 0o755); err != nil {
		t.Logf("[emit] mkdir %s: %v", tmpFNVDir, err)
		return
	}
	path := filepath.Join(tmpFNVDir, name+".json")
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

// buildEightFNV1aSeeds128FNV constructs the 8 mandatory seed roles as
// independent Seed128 handles keyed by fnv1a128BrokenLab. Mirrors
// buildEightFNV1aSeeds128 in redteam_nonce_reuse_test.go, namespaced to
// avoid symbol collision (CLAUDE.md frozen-code rule).
func buildEightFNV1aSeeds128FNV(t *testing.T, keyBits int) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
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

// snakeGeometryFNV describes the wire slicing of a Triple ciphertext.
// Populated from the public wire header (attacker-visible bytes only).
type snakeGeometryFNV struct {
	nonce         []byte
	totalPixels   int
	snakePixels   [3]int
	snakeBodies   [3][]byte
	snakePixStart [3]int
}

func decodeWireFNV(ct []byte) snakeGeometryFNV {
	nonce := ct[:NonceSize]
	w := int(binary.BigEndian.Uint16(ct[2*NonceSize : 2*NonceSize+2]))
	h := int(binary.BigEndian.Uint16(ct[2*NonceSize+2 : 2*NonceSize+4]))
	total := w * h
	third := total / 3
	third3 := total - 2*third
	body := ct[2*NonceSize+4:]
	return snakeGeometryFNV{
		nonce:       nonce,
		totalPixels: total,
		snakePixels: [3]int{third, third, third3},
		snakeBodies: [3][]byte{
			body[0 : third*Channels],
			body[third*Channels : 2*third*Channels],
			body[2*third*Channels : total*Channels],
		},
		snakePixStart: [3]int{0, third, 2 * third},
	}
}

// recoverXorMask56FNV inverts the encode formula for one candidate
// (noisePos, rotation) pair to recover the 56-bit compound
// `dataHash.lo >> 3` value under the assumed crib alignment. Identical
// math to the pre-v0.3.0 achievable-key routine in
// scripts/redteam/itb/theory/fnv1a/itb_channel_mirror.py
// (decode_channel_to_plaintext_bits), specialised to yield the full
// 56-bit compound directly. Used by both anchor probes.
func recoverXorMask56FNV(pixelBytes [Channels]byte, np uint, r uint, cribBits [Channels]byte) uint64 {
	var xorMask56 uint64
	for ch := 0; ch < Channels; ch++ {
		ext := extract7Broken(pixelBytes[ch], np) // strip noise bit
		unrot := rotateBits7(ext, 7-r)            // undo rotate
		cx := unrot ^ cribBits[ch]                // recover channel_xor
		xorMask56 |= uint64(cx) << uint(ch*DataBitsPerChannel)
	}
	return xorMask56
}

// naiveSnakeCribBits returns the assumed 7-bit-per-channel crib payload
// for snake i at snake-pixel p under the pre-v0.3.0 anchoring
// assumption "plaintext byte K lives at snake K%3, snake-pixel (K/3)/7,
// channel (K/3)%7". Returns false when the assumed byte range falls
// outside the raw plaintext (short crib).
func naiveSnakeCribBits(plain []byte, snakeIdx, snakePixel int) (bits [Channels]byte, ok bool) {
	for ch := 0; ch < Channels; ch++ {
		bitIdx := snakePixel*DataBitsPerPixel + ch*DataBitsPerChannel
		byteIdx := bitIdx / 8
		bitOff := uint(bitIdx % 8)
		absIdx0 := snakeIdx + 3*byteIdx
		absIdx1 := snakeIdx + 3*(byteIdx+1)
		if absIdx0 >= len(plain) {
			return bits, false
		}
		var raw uint16 = uint16(plain[absIdx0])
		if absIdx1 < len(plain) {
			raw |= uint16(plain[absIdx1]) << 8
		}
		bits[ch] = byte((raw >> bitOff) & 0x7F)
	}
	return bits, true
}

// pixelBytesAt returns a [Channels]byte snapshot of snake i's container
// at snake-pixel p — attacker-visible bytes only.
func pixelBytesAt(geom snakeGeometryFNV, snakeIdx, snakePixel int) [Channels]byte {
	var out [Channels]byte
	body := geom.snakeBodies[snakeIdx]
	base := snakePixel * Channels
	if base+Channels > len(body) {
		return out
	}
	for ch := 0; ch < Channels; ch++ {
		out[ch] = body[base+ch]
	}
	return out
}

// trueXorMask56FNV returns the ground-truth `dataHash(streamIdx).lo >> 3`
// under the true dataSeed. LAB PEEK — consumed by diagnostic probes.
//
// Important convention: the encoder in processChunk128 computes
// dataHash and noiseHash at the STREAM INDEX (the counter p walked
// from startP), NOT at the absolute container position
// linearIdx = (startPixel + p) mod totalPixels. Callers must pass the
// stream index the naive-crib-alignment attacker assumes for the
// corresponding crib byte — for the SAT-anchoring premise "crib byte K
// lives at snake K%3 stream position (K/3)/7", that stream index is
// (K/3)/7 counted from 0 at the crib prefix.
func trueXorMask56FNV(dataSeed *Seed128, nonce []byte, streamIdx int) uint64 {
	buf := make([]byte, 4+len(nonce))
	copy(buf[4:], nonce)
	lo, _ := dataSeed.blockHash128(buf, streamIdx)
	return (lo >> DataRotationBits) & mask56Broken
}

// trueRotationFNV returns the ground-truth rotation r = dataHash.lo % 7
// under the true dataSeed at the given stream index. LAB PEEK.
func trueRotationFNV(dataSeed *Seed128, nonce []byte, streamIdx int) uint {
	buf := make([]byte, 4+len(nonce))
	copy(buf[4:], nonce)
	lo, _ := dataSeed.blockHash128(buf, streamIdx)
	return uint(lo % 7)
}

// trueNoisePosFNV returns the ground-truth noise_pos = noiseHash.lo & 7
// under the true noiseSeed at the given stream index. LAB PEEK.
func trueNoisePosFNV(noiseSeed *Seed128, nonce []byte, streamIdx int) uint {
	buf := make([]byte, 4+len(nonce))
	copy(buf[4:], nonce)
	lo, _ := noiseSeed.blockHash128(buf, streamIdx)
	return uint(lo & 7)
}

// jsonCribPlaintext is the shared structured-JSON plaintext used by
// every probe below. Attacker-visible: the prefix through byte ~120
// follows a public schema (JSON identifier field, ISO timestamp), so
// every byte in that prefix is a legitimate crib byte the attacker
// predicts without any defender-private input.
var jsonCribPlaintext = []byte(`[{"identifier_of_record_in_system":"0000000000","event_timestamp_iso":"2026-08-24T00:00:00Z","payload":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]`)

// ---------------------------------------------------------------------------
// Probe F1 — attacker-realistic pre-anchor structure.
//
// Reports the achievable per-pixel candidate xor_mask56 set size under
// every (sp_i, np, r) tuple, using only attacker-visible bytes plus the
// naive-crib alignment. Under CRC128 the pre-v0.3.0 pre-anchor filter
// intersected these sets across crib pixels to collapse candidate
// startPixels to the true one (pixel-independent K + linear ChainHash).
// Under FNV-1a the ChainHash is not affine, so no pixel-independent K
// exists — the per-pixel achievable sets are functionally independent
// 56-value slices of Z/2^56 with no cross-pixel intersection signal.
//
// The probe reports:
//
//   - per snake: min, max, mean |achievable xor_mask56 set| per pixel
//     across all candidate startPixels (expected ≤ 56 — the number of
//     (np, r) tuples per pixel);
//   - per snake: the intersection size of the achievable sets across
//     6 crib pixels, taken as the max over all startPixel candidates
//     (expected ≈ 0 because the sets are functionally independent).
//
// Under Single Ouroboros without barrier the CRC128 intersection is
// exactly 1 at the true shift. Under any FNV-1a construction (with or
// without barrier) the intersection is 0 at every shift because the
// per-pixel achievable sets are independent 56-element slices of
// Z/2^56, and P(intersection non-empty across P pixels) ≈ (56/2^56)^P.
// This probe therefore does NOT discriminate barrier from no-barrier
// for FNV-1a — the discrimination lives at the SAT layer (Layer 2).
// The measurement is reported to document the pre-anchor filter's
// invalidity for FNV-1a and to justify the SAT-only decision path.
// ---------------------------------------------------------------------------

func TestRedTeamBrokenFNV1aCribKPA(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x50 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	plain := jsonCribPlaintext
	const cribPixelsPerSnake = 6

	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128FNV(t, keyBits)

	ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plain)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	back, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil || string(back) != string(plain) {
		t.Fatalf("v0.3.0 ciphertext did not round-trip: %v", err)
	}
	t.Logf("[audit] v0.3.0 Triple/barrier round-trip OK (%d B plain → %d B wire)", len(plain), len(ct))

	geom := decodeWireFNV(ct)

	type snakeReport struct {
		Snake                  int     `json:"snake"`
		SnakePixels            int     `json:"snake_pixels"`
		PerPixelSetSizeMean    float64 `json:"per_pixel_set_size_mean"`
		PerPixelSetSizeMin     int     `json:"per_pixel_set_size_min"`
		PerPixelSetSizeMax     int     `json:"per_pixel_set_size_max"`
		MaxIntersectionOverSPs int     `json:"max_intersection_over_startpixel"`
	}
	reports := make([]snakeReport, 3)
	for si := 0; si < 3; si++ {
		snakePixels := geom.snakePixels[si]
		perPixelSizes := []int{}
		maxInter := 0
		for sp := 0; sp < snakePixels; sp++ {
			var chainInter map[uint64]struct{}
			ok := true
			for p := 0; p < cribPixelsPerSnake; p++ {
				snakePix := (sp + p) % snakePixels
				cribBits, cribOk := naiveSnakeCribBits(plain, si, p)
				if !cribOk {
					ok = false
					break
				}
				pix := pixelBytesAt(geom, si, snakePix)
				set := make(map[uint64]struct{}, 56)
				for np := uint(0); np < 8; np++ {
					for r := uint(0); r < 7; r++ {
						xor56 := recoverXorMask56FNV(pix, np, r, cribBits)
						set[xor56] = struct{}{}
					}
				}
				perPixelSizes = append(perPixelSizes, len(set))
				if p == 0 {
					chainInter = set
				} else {
					next := make(map[uint64]struct{}, len(chainInter))
					for k := range chainInter {
						if _, hit := set[k]; hit {
							next[k] = struct{}{}
						}
					}
					chainInter = next
					if len(chainInter) == 0 {
						break
					}
				}
			}
			if ok && chainInter != nil && len(chainInter) > maxInter {
				maxInter = len(chainInter)
			}
		}
		var sum int
		minS, maxS := 1<<30, 0
		for _, v := range perPixelSizes {
			sum += v
			if v < minS {
				minS = v
			}
			if v > maxS {
				maxS = v
			}
		}
		mean := 0.0
		if len(perPixelSizes) > 0 {
			mean = float64(sum) / float64(len(perPixelSizes))
		}
		reports[si] = snakeReport{
			Snake:                  si,
			SnakePixels:            snakePixels,
			PerPixelSetSizeMean:    mean,
			PerPixelSetSizeMin:     minS,
			PerPixelSetSizeMax:     maxS,
			MaxIntersectionOverSPs: maxInter,
		}
		t.Logf("Snake %d: snake_pixels=%d per_pixel_set_size mean=%.2f min=%d max=%d max_intersection_over_sp=%d",
			si, snakePixels, mean, minS, maxS, maxInter)
	}
	if reports[0].MaxIntersectionOverSPs > 8 || reports[1].MaxIntersectionOverSPs > 8 ||
		reports[2].MaxIntersectionOverSPs > 8 {
		t.Fatalf("FNV-1a pre-anchor intersection unexpectedly high — investigate")
	}
	emitJSONFNV(t, "f1_pre_anchor_structure", map[string]any{
		"probe":                 "F1_pre_anchor_structure",
		"plaintext_len":         len(plain),
		"crib_pixels_per_snake": cribPixelsPerSnake,
		"note":                  "attacker-realistic — per-pixel achievable-set sizes are ≤56 with essentially zero cross-pixel intersection under any FNV-1a shift (pixel-independent K does not exist for non-affine ChainHash); discriminator moves to SAT Layer 2",
		"per_snake":             reports,
	})
}

// ---------------------------------------------------------------------------
// Probe F2 — LAB-PEEK true-anchor upper bound. For each candidate
// startPixel per snake, count how many crib channel bytes match the
// TRUE recovered xor_mask56 (using true noiseSeed for np and true
// dataSeed for r + xor_mask56) under the naive-crib alignment.
//
// Under Single Ouroboros without barrier: at the true startPixel, all
// cribPixels * Channels bytes match — this is the SAT anchor. Under
// v0.3.0 barrier: the crib bytes are wrong at nearly every position,
// so the recovered xor_mask56 does NOT equal the true dataHash even
// under true (np, r). Match count drops to the same-symbol coincidence
// floor per shift.
//
// This is the definitive negative-result probe: even the oracle
// attacker (given true seeds) cannot anchor the naive-crib SAT on the
// barrier ciphertext.
// ---------------------------------------------------------------------------

func TestRedTeamBrokenFNV1aCribKPATrueAnchor(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x50 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	plain := jsonCribPlaintext
	const cribPixelsPerSnake = 6

	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128FNV(t, keyBits)
	dataSeeds := [3]*Seed128{d1, d2, d3}

	ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plain)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	geom := decodeWireFNV(ct)

	type snakeReport struct {
		Snake                    int     `json:"snake"`
		SnakePixels              int     `json:"snake_pixels"`
		ChannelBudget            int     `json:"crib_channels_budget"`
		FullChainAnchoringShifts int     `json:"full_true_anchor_shifts"`
		MaxChannelMatches        int     `json:"max_channel_matches"`
		AvgChannelMatches        float64 `json:"avg_channel_matches"`
		ChanceFloor              float64 `json:"chance_floor_per_channel"`
	}
	// Chance floor: two random 7-bit values match with p = 1/128.
	// Over budget = 6*8 = 48 channels the expected chance matches is
	// 48/128 = 0.375.
	const chanceFloor = 1.0 / 128.0

	reports := make([]snakeReport, 3)
	for si := 0; si < 3; si++ {
		snakePixels := geom.snakePixels[si]
		fullAnchoring := 0
		var sum int
		maxM := 0
		for sp := 0; sp < snakePixels; sp++ {
			matches := 0
			for p := 0; p < cribPixelsPerSnake; p++ {
				snakePix := (sp + p) % snakePixels
				cribBits, ok := naiveSnakeCribBits(plain, si, p)
				if !ok {
					break
				}
				pix := pixelBytesAt(geom, si, snakePix)
				// SAT-anchoring premise assumes crib byte K sits at
				// snake stream index p (naive every-3rd-byte guess);
				// per encoder convention, dataHash and noiseHash are
				// keyed by stream index p, not the absolute container
				// position (sp + p) mod snakePixels.
				trueNP := trueNoisePosFNV(ns, geom.nonce, p)
				trueR := trueRotationFNV(dataSeeds[si], geom.nonce, p)
				trueXor := trueXorMask56FNV(dataSeeds[si], geom.nonce, p)
				recovered := recoverXorMask56FNV(pix, trueNP, trueR, cribBits)
				for ch := 0; ch < Channels; ch++ {
					recCh := byte((recovered >> uint(ch*DataBitsPerChannel)) & 0x7F)
					trueCh := byte((trueXor >> uint(ch*DataBitsPerChannel)) & 0x7F)
					if recCh == trueCh {
						matches++
					}
				}
			}
			sum += matches
			if matches > maxM {
				maxM = matches
			}
			if matches == cribPixelsPerSnake*Channels {
				fullAnchoring++
			}
		}
		avg := float64(sum) / float64(snakePixels)
		reports[si] = snakeReport{
			Snake:                    si,
			SnakePixels:              snakePixels,
			ChannelBudget:            cribPixelsPerSnake * Channels,
			FullChainAnchoringShifts: fullAnchoring,
			MaxChannelMatches:        maxM,
			AvgChannelMatches:        avg,
			ChanceFloor:              chanceFloor,
		}
		t.Logf("Snake %d (true-seed peek): sp∈[0,%d) full_true_anchor=%d/%d max_ch_matches=%d/%d avg=%.3f floor≈%.3f",
			si, snakePixels, fullAnchoring, snakePixels, maxM, cribPixelsPerSnake*Channels, avg, float64(cribPixelsPerSnake*Channels)*chanceFloor)
	}
	// Under barrier, no shift should achieve the full-channel anchor.
	for _, r := range reports {
		if r.FullChainAnchoringShifts > 0 {
			t.Fatalf("Snake %d has %d full-anchor shifts under barrier — regression",
				r.Snake, r.FullChainAnchoringShifts)
		}
	}
	emitJSONFNV(t, "f2_true_anchor", map[string]any{
		"probe":                 "F2_true_anchor_lab_peek",
		"plaintext_len":         len(plain),
		"crib_pixels_per_snake": cribPixelsPerSnake,
		"note":                  "[lab-peek: true_seeds] definitive negative — recovered xor_mask56 from naive-crib alignment does not equal true dataHash even under true (np, r); match rate at chance floor",
		"per_snake":             reports,
	})
}

// ---------------------------------------------------------------------------
// Probe F3 — control encode (Single Ouroboros, barrier off) via
// process128Cfg. Confirms the anchor logic is correct: under the
// retired Single/barrier-off construction, the true (sp, np, r) at
// every crib pixel produces recovered xor_mask56 EQUAL to the true
// dataHash prefix. Positive control that the negative barrier result
// is contrasted against.
// ---------------------------------------------------------------------------

func TestRedTeamBrokenFNV1aCribKPAControl(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x50 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	plain := jsonCribPlaintext
	const cribPixelsControl = 6

	dataSeed, err := NewSeed128(keyBits, fnv1a128BrokenLab)
	if err != nil {
		t.Fatalf("NewSeed128 data: %v", err)
	}
	noiseSeed, err := NewSeed128(keyBits, fnv1a128BrokenLab)
	if err != nil {
		t.Fatalf("NewSeed128 noise: %v", err)
	}
	startSeed, err := NewSeed128(keyBits, fnv1a128BrokenLab)
	if err != nil {
		t.Fatalf("NewSeed128 start: %v", err)
	}

	totalPixels := (len(plain)*8+DataBitsPerPixel-1)/DataBitsPerPixel + 8
	ctrl := make([]byte, totalPixels*Channels)
	process128Cfg(nil, noiseSeed, dataSeed, startSeed, nonce, ctrl, totalPixels, 1, plain, true, 1)

	// [lab-peek: sp*] disclosed via deriveStartPixel — matches
	// Concession 1 of the pre-v0.3.0 SAT harness.
	sp := startSeed.deriveStartPixel(nonce, totalPixels)
	t.Logf("[audit] control startPixel = %d (derived from startSeed.deriveStartPixel)", sp)

	fullMatches := 0
	for p := 0; p < cribPixelsControl; p++ {
		// Encoder writes crib pixel p (stream index p) into container at
		// (sp + p) mod totalPixels, using dataHash / noiseHash at stream
		// index p. Attacker recovers by reading the container position
		// and hashing at the stream index.
		pix := (sp + p) % totalPixels
		var pixBytes [Channels]byte
		for ch := 0; ch < Channels; ch++ {
			pixBytes[ch] = ctrl[pix*Channels+ch]
		}
		var cribBits [Channels]byte
		for ch := 0; ch < Channels; ch++ {
			cribBits[ch] = getBits7Broken(plain, p, ch)
		}
		trueNP := trueNoisePosFNV(noiseSeed, nonce, p)
		trueR := trueRotationFNV(dataSeed, nonce, p)
		trueXor := trueXorMask56FNV(dataSeed, nonce, p)
		recovered := recoverXorMask56FNV(pixBytes, trueNP, trueR, cribBits)
		if recovered == trueXor {
			fullMatches++
		}
	}
	t.Logf("CONTROL (Single, overlay-off): full-anchor pixels %d/%d — recovered xor_mask56 == true dataHash >> 3 at true (np, r)",
		fullMatches, cribPixelsControl)
	if fullMatches != cribPixelsControl {
		t.Fatalf("CONTROL failed at true (sp, np, r): anchor logic is broken; barrier null cannot be trusted")
	}
	emitJSONFNV(t, "f3_control_positive", map[string]any{
		"probe":                     "F3_control_single_overlay_off",
		"crib_pixels":               cribPixelsControl,
		"full_anchor_pixels":        fullMatches,
		"true_startpixel_disclosed": sp,
		"note":                      "positive control — SAT anchor is recoverable under Single Ouroboros without barrier at true (sp, np, r)",
	})
}

// ---------------------------------------------------------------------------
// Probe F4 — startPixel-peek (Layer 3 scoped bonus). Under the barrier,
// even disclosing the three snake startPixels does not restore the
// naive-crib SAT anchor: the crib bytes are still moved off the
// sp-anchored positions by the per-chunk interlock.
//
// Reports the true-anchor channel match count AT the disclosed sp_i
// versus averaged across all snake shifts. If disclosing sp_i restored
// the anchor, the count at sp_i would be significantly above the
// shift-averaged floor. Under barrier: count at sp_i is at the same
// floor as every other shift, refuting the "would knowing startPixel
// help?" question.
// ---------------------------------------------------------------------------

func TestRedTeamBrokenFNV1aCribKPAStartPixelPeek(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x50 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	plain := jsonCribPlaintext
	const cribPixelsPerSnake = 6

	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128FNV(t, keyBits)
	startSeeds := [3]*Seed128{s1, s2, s3}
	dataSeeds := [3]*Seed128{d1, d2, d3}

	ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plain)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	geom := decodeWireFNV(ct)

	type snakeReport struct {
		Snake                int     `json:"snake"`
		SnakePixels          int     `json:"snake_pixels"`
		StartPixelDisclosed  int     `json:"startpixel_disclosed"`
		ChannelMatchesAtSP   int     `json:"channel_matches_at_sp"`
		AvgChannelMatchesAll float64 `json:"avg_channel_matches_all_shifts"`
		ChannelsBudget       int     `json:"crib_channels_budget"`
	}
	reports := make([]snakeReport, 3)
	for si := 0; si < 3; si++ {
		snakePixels := geom.snakePixels[si]
		sp := startSeeds[si].deriveStartPixel(geom.nonce, snakePixels)
		var atSP int
		var allSum int
		for shift := 0; shift < snakePixels; shift++ {
			var matches int
			for p := 0; p < cribPixelsPerSnake; p++ {
				snakePix := (shift + p) % snakePixels
				cribBits, ok := naiveSnakeCribBits(plain, si, p)
				if !ok {
					break
				}
				pix := pixelBytesAt(geom, si, snakePix)
				// SAT-anchoring premise assumes stream index p for
				// crib pixel p (see F2 docstring for the encoder
				// stream-vs-container distinction).
				trueNP := trueNoisePosFNV(ns, geom.nonce, p)
				trueR := trueRotationFNV(dataSeeds[si], geom.nonce, p)
				trueXor := trueXorMask56FNV(dataSeeds[si], geom.nonce, p)
				rec := recoverXorMask56FNV(pix, trueNP, trueR, cribBits)
				for ch := 0; ch < Channels; ch++ {
					recCh := byte((rec >> uint(ch*DataBitsPerChannel)) & 0x7F)
					trCh := byte((trueXor >> uint(ch*DataBitsPerChannel)) & 0x7F)
					if recCh == trCh {
						matches++
					}
				}
			}
			if shift == sp {
				atSP = matches
			}
			allSum += matches
		}
		avg := float64(allSum) / float64(snakePixels)
		reports[si] = snakeReport{
			Snake:                si,
			SnakePixels:          snakePixels,
			StartPixelDisclosed:  sp,
			ChannelMatchesAtSP:   atSP,
			AvgChannelMatchesAll: avg,
			ChannelsBudget:       cribPixelsPerSnake * Channels,
		}
		t.Logf("Snake %d [lab-peek: sp_i]: sp=%d ch_matches_at_sp=%d/%d avg_ch_matches_all=%.3f",
			si, sp, atSP, cribPixelsPerSnake*Channels, avg)
	}
	// Under barrier the true-sp count is not statistically above the
	// shift-averaged floor. Fail if any snake shows a > 4x elevation
	// (indicative that disclosing sp DID restore the anchor).
	for _, r := range reports {
		if float64(r.ChannelMatchesAtSP) > 4.0*r.AvgChannelMatchesAll+8 {
			t.Fatalf("Snake %d shows %d matches at sp vs %.3f avg — sp peek unexpectedly powerful",
				r.Snake, r.ChannelMatchesAtSP, r.AvgChannelMatchesAll)
		}
	}
	emitJSONFNV(t, "f4_startpixel_peek", map[string]any{
		"probe":                 "F4_startpixel_peek",
		"plaintext_len":         len(plain),
		"crib_pixels_per_snake": cribPixelsPerSnake,
		"note":                  "[lab-peek: sp_i] — disclosing per-snake startPixel does not restore the naive-crib SAT anchor; sp-column match count is at the same floor as any other shift",
		"per_snake":             reports,
	})
}

// ---------------------------------------------------------------------------
// Probe F5 — displacement fraction on the JSON crib. Repeats the
// TestRedTeamBrokenBarrierDisplacement measurement (redteam_broken_test.go
// L390) on the exact JSON plaintext used by every other FNV-1a probe
// so the reported anchoring null and the reported byte-position
// displacement come from the same input.
// ---------------------------------------------------------------------------

func TestRedTeamBrokenFNV1aCribKPADisplacement(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x50 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	plain := jsonCribPlaintext
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128FNV(t, keyBits)

	ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plain)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	back, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil || string(back) != string(plain) {
		t.Fatalf("v0.3.0 ciphertext did not round-trip: %v", err)
	}
	// [lab-peek: barrier_split] — splitForTriple48LockedCfg with the
	// true lockSeed reveals the per-snake lane bytes. Used for the
	// displacement measurement only.
	p0, p1, p2 := splitForTriple48LockedCfg(nil, plain, buildLockBatchPRF48_128Cfg(nil, ls, ct[:NonceSize]))
	snakes := [3][]byte{p0, p1, p2}

	type snakeDisp struct {
		Snake            int     `json:"snake"`
		Compared         int     `json:"compared"`
		Matched          int     `json:"matched"`
		Fraction         float64 `json:"fraction"`
		ChanceForSymbols float64 `json:"chance_at_alphabet"`
	}
	const chanceAlphabet = 1.0 / 40.0
	reps := make([]snakeDisp, 3)
	for si, sn := range snakes {
		checked, matched := 0, 0
		for j := 0; j < len(sn) && j < 60; j++ {
			assumedIdx := si + j*3
			if assumedIdx >= len(plain) {
				break
			}
			checked++
			if sn[j] == plain[assumedIdx] {
				matched++
			}
		}
		frac := 0.0
		if checked > 0 {
			frac = float64(matched) / float64(checked)
		}
		reps[si] = snakeDisp{
			Snake:            si,
			Compared:         checked,
			Matched:          matched,
			Fraction:         frac,
			ChanceForSymbols: chanceAlphabet,
		}
		t.Logf("Snake %d displacement: %d/%d (%.4f) crib bytes remain at attacker-predicted post-split position (chance ≈ %.4f for 40-symbol JSON)",
			si, matched, checked, frac, chanceAlphabet)
	}
	emitJSONFNV(t, "f5_displacement", map[string]any{
		"probe":              "F5_displacement_json_crib",
		"plaintext_len":      len(plain),
		"chance_at_alphabet": chanceAlphabet,
		"per_snake":          reps,
	})
}

// ---------------------------------------------------------------------------
// Probe F6 — emit corpus for the Python SAT harness. Writes a ciphertext
// + true seeds + true plaintext bundle under `tmp/redteam/fnv1a_sat/
// corpus/` for the companion Python SAT probe to consume. Runs the Go
// side of the two-language experiment: the emitted `bundle.json` is the
// only interface between Go (which owns the encoder + seed generation)
// and Python (which owns the SAT harness).
//
// The Python SAT probe consumes:
//   - ciphertext_hex — the full wire bytes (attacker-visible)
//   - nonce_hex — extracted from the wire header (attacker-visible)
//   - plaintext — the assumed public schema (attacker-visible crib)
//   - seed_components — GROUND TRUTH, consumed only by the Python
//     probe's audit / validation printouts (never in the SAT decision).
// ---------------------------------------------------------------------------

func TestRedTeamBrokenFNV1aCribKPAEmitCorpus(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x50 + i)
	}
	setBrokenTestNonce(t, nonce)

	const keyBits = 512
	plain := jsonCribPlaintext
	ns, ls, d1, d2, d3, s1, s2, s3 := buildEightFNV1aSeeds128FNV(t, keyBits)

	ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plain)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	// Also emit a control ciphertext for the Python SAT probe's
	// positive-control assertion: same seeds routed through the
	// single-snake process128Cfg (no barrier, no interleave). Bitwuzla
	// on this control instance must return SAT (recovering the seed);
	// on the barrier ciphertext it must return UNSAT.
	totalCtrlPixels := (len(plain)*8+DataBitsPerPixel-1)/DataBitsPerPixel + 8
	ctrl := make([]byte, totalCtrlPixels*Channels)
	process128Cfg(nil, ns, d1, s1, nonce, ctrl, totalCtrlPixels, 1, plain, true, 1)

	// hexEncode local helper: keep the emitted JSON string-serialisable.
	hexOf := func(b []byte) string {
		const hex = "0123456789abcdef"
		out := make([]byte, len(b)*2)
		for i, v := range b {
			out[i*2] = hex[v>>4]
			out[i*2+1] = hex[v&0x0F]
		}
		return string(out)
	}
	compOf := func(s *Seed128) []string {
		out := make([]string, len(s.Components))
		for i, c := range s.Components {
			out[i] = fmt.Sprintf("%016x", c)
		}
		return out
	}

	bundle := map[string]any{
		"description":     "FNV-1a on all 8 seeds; v0.3.0 Triple/barrier + single-snake control",
		"key_bits":        keyBits,
		"nonce_hex":       hexOf(nonce),
		"plaintext_utf8":  string(plain),
		"plaintext_hex":   hexOf(plain),
		"ciphertext_hex":  hexOf(ct),
		"control_bytes":   hexOf(ctrl),
		"control_pixels":  totalCtrlPixels,
		"seed_components": map[string][]string{
			"noise":  compOf(ns),
			"lock":   compOf(ls),
			"data1":  compOf(d1),
			"data2":  compOf(d2),
			"data3":  compOf(d3),
			"start1": compOf(s1),
			"start2": compOf(s2),
			"start3": compOf(s3),
		},
	}
	emitJSONFNV(t, "f6_corpus_bundle", bundle)
}
