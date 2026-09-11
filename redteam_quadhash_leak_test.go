//go:build redteam

package itb

// quadHash 7-of-8 unmask leak measurement (Step 1 MVP, fixed geometry).
//
// Correct pipeline understanding (from itb128.go:133 Encrypt3x128Cfg):
//   1. buildTripleWire3 → payloads[0..3] via splitForTriple48LockedInto.
//   2. tripleThirdCaps(totalPixels) → third, thirdPixels2 (per-snake widths).
//   3. 3× process128Cfg per snake:
//        process128Cfg(cfg, noiseSeed, dataSeed_i, startSeed_i, nonce,
//                      container[offset..], WIDTH_i, height=1, payloads[i], true, ...)
//   4. Inside process128Cfg (itb128.go:24-27):
//        totalPixels := width * height  = WIDTH_i (region width)
//        startPixel  := startSeed.deriveStartPixel(nonce, totalPixels=WIDTH_i)
//
// So startPixel_i lives in [0, WIDTH_i), NOT [0, full totalPixels).

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// quadHash — 8-bit-per-lane squaring fold. Non-bijective per iteration
// (x² mod 256 collides on ±x mod 256; output space collapses to ~44
// unique values from 256 domain), with fixed-point attractor at l=0
// and l=1. Weaker diffusion than trainHash (which is bijective through
// odd-multiplier multiply-add) yet still per-pixel varying, so the
// nullHash XOR^4=identity collapse is absent.
func thLeak_quadHash(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	l := seed0 & 0xFF
	h := seed1 & 0xFF
	for _, b := range data {
		l = ((l + uint64(b)) * (l + uint64(b))) & 0xFF
		h = (((h + uint64(b)) * (h + uint64(b))) + 1) & 0xFF
	}
	return l, h
}

func qhLeakDir() string {
	return redteamOutputDir("quadhash_leak")
}

func writeQuadHashLeakVictim(t *testing.T, outDir string, keyBits, ptSize, barrierFill int) {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", outDir, err)
	}
	cfg := &Config{NonceBits: 128, BarrierFill: barrierFill}
	plaintext := make([]byte, ptSize)
	for i := range plaintext {
		plaintext[i] = byte('A' + (i % 26))
	}
	mk := func() *Seed128 {
		s, err := NewSeed128(keyBits, thLeak_quadHash)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ns, ls := mk(), mk()
	d1, d2, d3 := mk(), mk(), mk()
	s1, s2, s3 := mk(), mk(), mk()
	ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatal("roundtrip mismatch")
	}
	nonceLen := currentNonceSizeCfg(cfg)
	mainNonce := ct[:nonceLen]
	ilNonce := ct[nonceLen : 2*nonceLen]
	width := int(binary.BigEndian.Uint16(ct[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(ct[2*nonceLen+2:]))
	totalPixels := width * height
	headerSize := 2*nonceLen + 4
	third, thirdPixels2, _ := tripleThirdCaps(totalPixels)

	// CORRECT startPixel derivation: per-snake width (not full totalPixels).
	sp1 := s1.deriveStartPixel(mainNonce, third)
	sp2 := s2.deriveStartPixel(mainNonce, third)
	sp3 := s3.deriveStartPixel(mainNonce, thirdPixels2)

	dumpComps := func(s *Seed128) []uint64 {
		out := make([]uint64, len(s.Components))
		copy(out, s.Components)
		return out
	}
	meta := map[string]any{
		"main_nonce_hex":      hex.EncodeToString(mainNonce),
		"interlock_nonce_hex": hex.EncodeToString(ilNonce),
		"width":               width,
		"height":              height,
		"total_pixels":        totalPixels,
		"header_size":         headerSize,
		"third":               third,
		"third_pixels2":       thirdPixels2,
		"start_pixels":        map[string]int{"s1": sp1, "s2": sp2, "s3": sp3},
		"debug_seeds": map[string][]uint64{
			"noise": dumpComps(ns), "lock": dumpComps(ls),
			"data1": dumpComps(d1), "data2": dumpComps(d2), "data3": dumpComps(d3),
			"start1": dumpComps(s1), "start2": dumpComps(s2), "start3": dumpComps(s3),
		},
	}
	if err := os.WriteFile(filepath.Join(outDir, "ct.bin"), ct, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "kpa.bin"), plaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	mj, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "cell.meta.json"), mj, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("victim written: totalPixels=%d third=%d thirdPixels2=%d startPixels=[%d %d %d]", totalPixels, third, thirdPixels2, sp1, sp2, sp3)
}

func TestRedTeamQuadHashLeak7of8(t *testing.T) {
	dir := qhLeakDir()
	writeQuadHashLeakVictim(t, dir, 512, 512, 1)

	ct, _ := os.ReadFile(filepath.Join(dir, "ct.bin"))
	kpa, _ := os.ReadFile(filepath.Join(dir, "kpa.bin"))
	metaRaw, _ := os.ReadFile(filepath.Join(dir, "cell.meta.json"))
	var meta struct {
		MainNonceHex   string `json:"main_nonce_hex"`
		InterlockNonce string `json:"interlock_nonce_hex"`
		TotalPixels    int    `json:"total_pixels"`
		HeaderSize     int    `json:"header_size"`
		Third          int    `json:"third"`
		ThirdPixels2   int    `json:"third_pixels2"`
		StartPixels    struct {
			S1 int `json:"s1"`
			S2 int `json:"s2"`
			S3 int `json:"s3"`
		} `json:"start_pixels"`
		Debug struct {
			Lock []uint64 `json:"lock"`
		} `json:"debug_seeds"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	ilNonce, _ := hex.DecodeString(meta.InterlockNonce)

	container := ct[meta.HeaderSize:]
	third := meta.Third
	thirdPixels2 := meta.ThirdPixels2
	off1 := third * Channels
	off2 := 2 * third * Channels
	regions := [3][]byte{
		container[0:off1],
		container[off1:off2],
		container[off2 : meta.TotalPixels*Channels],
	}
	widths := [3]int{third, third, thirdPixels2}
	startPixels := [3]int{meta.StartPixels.S1, meta.StartPixels.S2, meta.StartPixels.S3}

	// Debug hint: compute expected lane bytes via real lockSeed (Step 2
	// chunk-mask-brute stand-in). Attacker-realistically he'd brute
	// 2^16 rank per chunk × verify — same result at ~10^7 ops per chunk.
	lockSeed, _ := SeedFromComponents128(thLeak_quadHash, meta.Debug.Lock...)
	bp := buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce)
	laneLen := tripleLaneLen(len(kpa))
	lane0 := make([]byte, laneLen)
	lane1 := make([]byte, laneLen)
	lane2 := make([]byte, laneLen)
	splitForTriple48LockedInto(cfg, kpa, bp, lane0, lane1, lane2)
	// process128Cfg reads COBS-encoded lane bytes + 0x00 terminator,
	// then DRBG tail. Apply COBS encode to match what encoder writes.
	rawLanes := [3][]byte{lane0, lane1, lane2}
	var lanes [3][]byte
	for i := 0; i < 3; i++ {
		enc := cobsEncode(rawLanes[i])
		lanes[i] = append(enc, 0x00)
	}
	t.Logf("lane lengths: raw=%d cobs+term=[%d %d %d]", laneLen, len(lanes[0]), len(lanes[1]), len(lanes[2]))

	// Per-pixel 7-of-8 leak measurement per snake.
	stats := [3]struct{ unique, ambiguous, miss int }{}
	for i := 0; i < 3; i++ {
		region := regions[i]
		width := widths[i]
		lane := lanes[i]
		spI := startPixels[i]
		totalBits := len(lane) * 8
		bitIndex := 0
		for pp := 0; pp < width && bitIndex < totalBits; pp++ {
			linearIdx := (spI + pp) % width
			pixelOffset := linearIdx * Channels
			type cand struct{ rot, np uint }
			var candidates []cand
			for np := uint(0); np < 8; np++ {
				noiseMask := byte(1 << np)
				for rot := uint(0); rot < 7; rot++ {
					allMatch := true
					bi := bitIndex
					for ch := 0; ch < Channels; ch++ {
						if bi+7 > totalBits {
							break
						}
						pixByte := region[pixelOffset+ch]
						low := pixByte & (noiseMask - 1)
						high := pixByte >> (np + 1)
						recovered := low | (high << np)
						if ch != 0 {
							dataBits := rotateBits7(recovered, 7-rot)
							byteIdx := bi / 8
							bitOff := uint(bi % 8)
							var raw uint16
							raw = uint16(lane[byteIdx])
							if byteIdx+1 < len(lane) {
								raw |= uint16(lane[byteIdx+1]) << 8
							}
							expected := byte((raw >> bitOff) & 0x7F)
							if dataBits != expected {
								allMatch = false
								break
							}
						}
						bi += 7
					}
					if allMatch {
						candidates = append(candidates, cand{rot, np})
					}
				}
			}
			switch len(candidates) {
			case 0:
				stats[i].miss++
			case 1:
				stats[i].unique++
			default:
				stats[i].ambiguous++
			}
			bitIndex += 56
		}
	}
	t.Logf("=== quadHash 7-of-8 leak measurement (fixed geometry) ===")
	total := 0
	unique := 0
	for i := 0; i < 3; i++ {
		tot := stats[i].unique + stats[i].ambiguous + stats[i].miss
		if tot == 0 {
			continue
		}
		t.Logf("snake %d: total=%d unique=%d (%.1f%%) ambiguous=%d miss=%d",
			i+1, tot, stats[i].unique, 100.0*float64(stats[i].unique)/float64(tot),
			stats[i].ambiguous, stats[i].miss)
		total += tot
		unique += stats[i].unique
	}
	if total > 0 {
		pct := 100.0 * float64(unique) / float64(total)
		t.Logf("overall: %d/%d pixels unique-recovery (%.2f%%)", unique, total, pct)
		if pct < 50 {
			t.Errorf("leak degraded: only %.2f%%", pct)
		}
	}

	// ================================================================
	// Step 2 — attacker-realistic 2^16 lockSeed enumeration.
	//
	// Attacker does NOT peek lockSeed. He enumerates 2^16 candidate
	// (lo, hi) byte pairs via quadHashSeedConst(lo, hi) — Components
	// [0]=lo, [1]=hi, [2..7]=0. Per candidate: compute expected lane
	// bytes via splitForTriple48LockedInto + cobsEncode + 0x00. Run
	// the same 7-of-8 leak measurement per pixel. Record match count.
	//
	// Hypothesis under cascade defence: real lockSeed's cascade path
	// depends on Components[2..7] non-trivially (quadHash's non-
	// cancelling multiply-add). Attacker's synthetic space
	// (Components[2..7]=0) fundamentally does not reach real cascade
	// output — no candidate matches, even at correct (lo, hi).
	// If cascade defence holds: top candidate's score at attacker-
	// realistic conditions ≈ random floor (~50% × pixels).
	// If cascade defence breaks: top candidate = real (lo, hi),
	// score = 100%.
	t.Logf("=== Step 2 — 2^16 lockSeed enumeration (no lockSeed peek) ===")
	type lcScore struct {
		lo, hi byte
		match  int
	}
	best := lcScore{}
	// Real lockSeed's rawLo/rawHi (from Debug — used only for the
	// terminal-stage validation printout, NOT for candidate ranking).
	realLo := byte(meta.Debug.Lock[0])
	realHi := byte(meta.Debug.Lock[1])
	realMatch := 0
	step2Start := len(container) // avoid unused var noise
	_ = step2Start
	for lo := 0; lo < 256; lo++ {
		for hi := 0; hi < 256; hi++ {
			candLock, _ := SeedFromComponents128(thLeak_quadHash,
				uint64(lo), uint64(hi), 0, 0, 0, 0, 0, 0)
			candBp := buildLockBatchPRF48_128Cfg(cfg, candLock, ilNonce)
			cLane0 := make([]byte, laneLen)
			cLane1 := make([]byte, laneLen)
			cLane2 := make([]byte, laneLen)
			splitForTriple48LockedInto(cfg, kpa, candBp, cLane0, cLane1, cLane2)
			cLanes := [3][]byte{cLane0, cLane1, cLane2}
			var cobs [3][]byte
			for i := 0; i < 3; i++ {
				cobs[i] = append(cobsEncode(cLanes[i]), 0x00)
			}
			totalMatch := 0
			for i := 0; i < 3; i++ {
				region := regions[i]
				width := widths[i]
				lane := cobs[i]
				spI := startPixels[i]
				totalBits := len(lane) * 8
				bitIndex := 0
				for pp := 0; pp < width && bitIndex < totalBits; pp++ {
					linearIdx := (spI + pp) % width
					pixelOffset := linearIdx * Channels
					uniqueFound := false
					for np := uint(0); np < 8 && !uniqueFound; np++ {
						noiseMask := byte(1 << np)
						for rot := uint(0); rot < 7 && !uniqueFound; rot++ {
							allMatch := true
							bi := bitIndex
							for ch := 0; ch < Channels; ch++ {
								if bi+7 > totalBits {
									break
								}
								pixByte := region[pixelOffset+ch]
								low := pixByte & (noiseMask - 1)
								high := pixByte >> (np + 1)
								recovered := low | (high << np)
								if ch != 0 {
									dataBits := rotateBits7(recovered, 7-rot)
									byteIdx := bi / 8
									bitOff := uint(bi % 8)
									var raw uint16
									raw = uint16(lane[byteIdx])
									if byteIdx+1 < len(lane) {
										raw |= uint16(lane[byteIdx+1]) << 8
									}
									expected := byte((raw >> bitOff) & 0x7F)
									if dataBits != expected {
										allMatch = false
										break
									}
								}
								bi += 7
							}
							if allMatch {
								uniqueFound = true
							}
						}
					}
					if uniqueFound {
						totalMatch++
					}
					bitIndex += 56
				}
			}
			if totalMatch > best.match {
				best = lcScore{byte(lo), byte(hi), totalMatch}
			}
			if byte(lo) == realLo && byte(hi) == realHi {
				realMatch = totalMatch
			}
		}
	}
	t.Logf("best candidate: lo=0x%02x hi=0x%02x match=%d/75", best.lo, best.hi, best.match)
	t.Logf("real (labonly): lo=0x%02x hi=0x%02x match=%d/75", realLo, realHi, realMatch)
	if best.match > 60 {
		t.Logf("Step 2 CONVERGED: cascade defence broken (top candidate matches ≥ 60/75)")
	} else {
		t.Logf("Step 2 BLOCKED: top candidate at %d/75 (~random floor); cascade defence holds", best.match)
	}
}

// byteMatchCount returns the count of positions where a[i] == b[i] over
// min(len(a), len(b)). Used as the Full KPA byte-match feedback signal
// for the greedy Components[0] brute in TestRedTeamQuadHashFullAttack.
func byteMatchCount(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	m := 0
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			m++
		}
	}
	return m
}

// TestRedTeamQuadHashFullAttack — full plaintext recovery under quadHash
// via sequential Components[0] brute across 8 seed roles.
//
// Attacker-realistic conditions: 0/8 seeds granted, only ct.bin + Full KPA
// (as byte-match feedback signal). Since quadHash's non-bijective iteration
// `l = (l + b)² & 0xFF` loses entropy through the attractor set — 13-byte
// Interlock chunk buffer (5 rounds cascade at keyBits=512) fully attractor-
// collapses, while 4-byte external-Barrier per-pixel buffer preserves
// residual Components[0] dependence — the attack proceeds in two stages:
//
//   1. All 8 seeds' Components[1..7] set to 0 (attractor collapse absorbs
//      those dimensions).
//   2. Sequential brute of Components[0] per seed slot ∈ 0..255: pick the
//      value maximising Full KPA byte-match under shipped Decrypt3x128Cfg.
//      Repeat greedy passes until convergence.
//
// Under the shipped 8-seed isolation invariant (checkEightSeeds128 rejects
// Components-identical pairs), Components[0] values must remain distinct
// across the 8 slots. When two slots collide during the brute, the trial
// is skipped.
func TestRedTeamQuadHashFullAttack(t *testing.T) {
	dir := qhLeakDir()
	writeQuadHashLeakVictim(t, dir, 512, 512, 1)
	ct, _ := os.ReadFile(filepath.Join(dir, "ct.bin"))
	kpa, _ := os.ReadFile(filepath.Join(dir, "kpa.bin"))

	cfg := &Config{NonceBits: 128, BarrierFill: 1}

	buildSeeds := func(comps0 [8]byte) ([8]*Seed128, error) {
		var out [8]*Seed128
		for i := 0; i < 8; i++ {
			s, err := SeedFromComponents128(thLeak_quadHash,
				uint64(comps0[i]), 0, 0, 0, 0, 0, 0, 0)
			if err != nil {
				return out, err
			}
			out[i] = s
		}
		return out, nil
	}

	tryDecrypt := func(comps0 [8]byte) (int, error) {
		seeds, err := buildSeeds(comps0)
		if err != nil {
			return -1, err
		}
		got, err := Decrypt3x128Cfg(cfg,
			seeds[0], seeds[1], seeds[2], seeds[3], seeds[4],
			seeds[5], seeds[6], seeds[7], ct)
		if err != nil {
			return -1, err
		}
		return byteMatchCount(got, kpa), nil
	}

	// Initial state — Components[0] = 1..8 (distinct, satisfies 8-seed
	// isolation). Baseline byte-match under all-zero-plus-slot-index.
	best := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	baseMatch, err := tryDecrypt(best)
	if err != nil {
		t.Fatalf("baseline Decrypt: %v", err)
	}
	t.Logf("=== quadHash Full Attack (Full KPA byte-match feedback, 0/8 seeds granted) ===")
	t.Logf("baseline Components[0]=[1..8], Components[1..7]=0: %d/%d bytes match (%.2f%%)",
		baseMatch, len(kpa), 100.0*float64(baseMatch)/float64(len(kpa)))

	// Greedy sequential Components[0] brute across all 8 slots.
	start := time.Now()
	bestMatch := baseMatch
	passes := 0
	tries := 0
	for pass := 0; pass < 4; pass++ {
		improved := false
		passes++
		for slot := 0; slot < 8; slot++ {
			for x := 0; x < 256; x++ {
				trial := best
				trial[slot] = byte(x)
				// Skip if this collides with any other slot's Components[0]
				// (8-seed isolation rejection).
				collide := false
				for j := 0; j < 8; j++ {
					if j != slot && trial[j] == trial[slot] {
						collide = true
						break
					}
				}
				if collide {
					continue
				}
				tries++
				m, err := tryDecrypt(trial)
				if err != nil {
					continue
				}
				if m > bestMatch {
					bestMatch = m
					best = trial
					improved = true
				}
			}
		}
		t.Logf("pass %d: best match=%d/%d (%.2f%%) Components[0]=%v",
			pass+1, bestMatch, len(kpa), 100.0*float64(bestMatch)/float64(len(kpa)), best)
		if bestMatch == len(kpa) {
			break
		}
		if !improved {
			break
		}
	}
	elapsed := time.Since(start)

	t.Logf("greedy brute complete: %d passes, %d Decrypt trials, elapsed %v", passes, tries, elapsed)
	t.Logf("final Components[0]=%v", best)
	t.Logf("final byte-match: %d/%d (%.2f%%)", bestMatch, len(kpa), 100.0*float64(bestMatch)/float64(len(kpa)))

	if bestMatch == len(kpa) {
		t.Logf("*** BROKEN *** quadHash fully recovered via sequential Components[0] brute")
		t.Logf("    shipped Decrypt with recovered synthetic seeds reproduces plaintext bit-exact")
	} else if bestMatch > len(kpa)*90/100 {
		t.Logf("*** PARTIAL *** quadHash recovered to %.2f%% byte match — brute Components[0] insufficient",
			100.0*float64(bestMatch)/float64(len(kpa)))
		t.Logf("    Components[1..7] residual effect on external Barrier's 4-byte-buffer cascade")
	} else {
		t.Logf("*** BLOCKED *** attack stalled at %.2f%% byte match",
			100.0*float64(bestMatch)/float64(len(kpa)))
	}
}
