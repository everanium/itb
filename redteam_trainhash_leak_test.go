//go:build redteam

package itb

// trainHash 7-of-8 unmask leak measurement (Step 1 MVP, fixed geometry).
//
// Correct pipeline understanding (from itb128.go:133 Encrypt3x128Cfg):
//   1. buildTripleWire3 → payloads[0..3] via splitForTriple48LockedInto.
//   2. tripleThirdCaps(totalPixels) → third, thirdPixels2 (per-region widths).
//   3. 3× process128Cfg per region:
//        process128Cfg(cfg, noiseSeed, dataSeed_i, startSeed_i, nonce,
//                      container[offset..], WIDTH_i, height=1, payloads[i], true, ...)
//   4. Inside process128Cfg (itb128.go:24-27):
//        totalPixels := width * height  = WIDTH_i (region width)
//        startPixel  := startSeed.deriveStartPixel(nonce, totalPixels=WIDTH_i)
//
// So startPixel_i lives in [0, WIDTH_i), NOT [0, full totalPixels).

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func thLeak_trainHash(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	l := seed0 & 0xFF
	h := seed1 & 0xFF
	for _, b := range data {
		l = ((l + uint64(b)) * 3 + 1) & 0xFF
		h = ((h + uint64(b)) * 5 + 7) & 0xFF
	}
	return l, h
}

func thLeakDir() string {
	return redteamOutputDir("trainhash_leak")
}

func writeTrainHashLeakVictim(t *testing.T, outDir string, keyBits, ptSize, barrierFill int) {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", outDir, err)
	}
	cfg := &Config{NonceBits: 128, BarrierFill: barrierFill}
	plaintext := make([]byte, ptSize)
	// Random ASCII fill — more honest test victim than uniform byte
	// garbage (matches realistic KPA: text, JSON, protocol messages).
	// Fresh sample per run via crypto/rand → wire body varies across
	// runs while remaining a realistic printable-ASCII plaintext shape.
	const asciiAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ,.:;-!?"
	tmp := make([]byte, ptSize)
	if _, err := rand.Read(tmp); err != nil {
		t.Fatalf("crypto/rand.Read plaintext seed: %v", err)
	}
	for i := range plaintext {
		plaintext[i] = asciiAlphabet[int(tmp[i])%len(asciiAlphabet)]
	}
	mk := func() *Seed128 {
		s, err := NewSeed128(keyBits, thLeak_trainHash)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ns, ls := mk(), mk()
	d1, d2, d3 := mk(), mk(), mk()
	s1, s2, s3 := mk(), mk(), mk()
	// The interlock nonce is not a wire field — it travels split across
	// the interlocked lanes — so the lab fixture installs a
	// CSPRNG-fresh value and records the one the encrypt consumed.
	ilNonce := make([]byte, currentNonceSizeCfg(cfg))
	if _, rerr := rand.Read(ilNonce); rerr != nil {
		t.Fatalf("crypto/rand interlock nonce: %v", rerr)
	}
	setBrokenTestInterlockNonceOnly(t, ilNonce)
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
	width := int(binary.BigEndian.Uint16(ct[nonceLen:]))
	height := int(binary.BigEndian.Uint16(ct[nonceLen+2:]))
	totalPixels := width * height
	headerSize := nonceLen + 4
	third, thirdPixels2, _ := tripleThirdCaps(totalPixels)

	// CORRECT startPixel derivation: per-region width (not full totalPixels).
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

func TestRedTeamTrainHashLeak7of8(t *testing.T) {
	dir := thLeakDir()
	writeTrainHashLeakVictim(t, dir, 512, 512, 1)

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
	// The interlock nonce is not a wire field and is not granted here. It
	// travels split across the three interlocked lanes, and the three
	// steps below establish how much of it the observation channel hands
	// back: Step 0 enumerates the 16-bit key the nonce derives to (the
	// whole of its influence on the Rank Barrier at this hash width),
	// Step 0b reads the literal fragment bytes off the lane fronts, and
	// Step 1 then measures the leak against lanes built from what was
	// recovered rather than from what the fixture recorded.
	lens, offs := nonceSplit(currentNonceSizeCfg(cfg))

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

	// The lockSeed is the lab reference this whole measurement is stated
	// against: Step 1 characterises the observation channel, so ground
	// truth is the reference for a statistic and not an input to an
	// attack decision. The interlock nonce is NOT part of that reference.
	lockSeed, _ := SeedFromComponents128(thLeak_trainHash, meta.Debug.Lock...)
	laneLen := tripleLaneLen(len(kpa))

	// ================================================================
	// Step 0 — recover the derived interlock key.
	//
	// The interlock nonce reaches the Rank Barrier through exactly one
	// value: the pair deriveInterLockSeed returns under the 0x04 domain
	// tag, which the cascade fill prepends to the lockSeed components.
	// Under trainHash a ChainHash128 lane is one byte wide, so that pair
	// is 16 bits however long the nonce is, and enumerating it covers
	// every nonce at once. The candidate lanes are scored through the
	// same 7-of-8 channel Step 1 measures, over the pixels past the
	// unknown fragment.
	//
	// This is a real search, not an assertion: 65,536 candidate keys,
	// each producing three full lanes and scored against the observed
	// pixels. It is stated against the lockSeed reference — an attacker
	// without it does not reach this step, which is what Step 2 is for.
	assertMirrorLockBatchParity128(t, cfg, thLeak_trainHash, 512)
	t.Logf("=== Step 0 — 2^16 derived-interlock-key enumeration (nonce not granted) ===")
	step0Start := time.Now()
	bestKeyScore, bestKeyLo, bestKeyHi, keyTies := -1, 0, 0, 0
	buildLanes := func(bp lockBatchPRF48) ([3][]byte, [3][]byte) {
		b0, b1, b2 := make([]byte, laneLen), make([]byte, laneLen), make([]byte, laneLen)
		splitForTriple48LockedInto(cfg, kpa, bp, b0, b1, b2)
		barriers := [3][]byte{b0, b1, b2}
		var streams [3][]byte
		for i := 0; i < 3; i++ {
			streams[i], _ = laneStreamWithUnknownFragment(barriers[i], lens[i])
		}
		return barriers, streams
	}
	for kLo := 0; kLo < 256; kLo++ {
		for kHi := 0; kHi < 256; kHi++ {
			_, streams := buildLanes(mirrorLockBatchPRF48_128(lockSeed, uint64(kLo), uint64(kHi)))
			score := 0
			for i := 0; i < 3; i++ {
				score += laneLeakPixelMatches(regions[i], widths[i], startPixels[i], streams[i])
			}
			switch {
			case score > bestKeyScore:
				bestKeyScore, bestKeyLo, bestKeyHi, keyTies = score, kLo, kHi, 1
			case score == bestKeyScore:
				keyTies++
			}
		}
	}
	t.Logf("Step 0: top candidate key=(0x%02x,0x%02x) score=%d pixels, %d candidates tied at that score, %v",
		bestKeyLo, bestKeyHi, bestKeyScore, keyTies, time.Since(step0Start))

	barriers, lanes := buildLanes(mirrorLockBatchPRF48_128(lockSeed, uint64(bestKeyLo), uint64(bestKeyHi)))

	// ================================================================
	// Step 0b — read the interlock-nonce fragments off the lane fronts.
	//
	// With the barrier lanes known, the first walked pixel of each region
	// carries that region's fragment. Enumerating the 2048 per-pixel
	// (noisePos, dataHash) configurations and keeping only the readings
	// whose COBS decode reproduces the barrier lane past the fragment
	// yields the fragment itself. Where a region's pixel window leaves no
	// spare byte past the fragment the reading is under-constrained and
	// several fragments survive — that is a measurement, not a failure.
	recoveredIl := make([]byte, currentNonceSizeCfg(cfg))
	var fragSets [3][][]byte
	fragCandidates := [3]int{}
	uniqueBytes := 0
	prod := 1
	for i := 0; i < 3; i++ {
		fragSets[i] = recoverLaneFragments(regions[i], widths[i], startPixels[i], lens[i], barriers[i])
		fragCandidates[i] = len(fragSets[i])
		prod *= len(fragSets[i])
		if len(fragSets[i]) == 1 {
			copy(recoveredIl[offs[i]:offs[i]+lens[i]], fragSets[i][0])
			uniqueBytes += lens[i]
		} else if len(fragSets[i]) > 1 {
			// Ambiguous: the display carries the first survivor, and the
			// candidate count below is the honest statement of what was
			// recovered.
			copy(recoveredIl[offs[i]:offs[i]+lens[i]], fragSets[i][0])
		}
	}
	t.Logf("Step 0b: fragment candidates per region = %v (lens %v); %d of %d nonce bytes pinned uniquely, %d whole-nonce candidates remain",
		fragCandidates, lens, uniqueBytes, len(recoveredIl), prod)

	t.Logf("lane lengths: barrier=%d cobs+term=[%d %d %d] (leading %v bytes per lane unknown: code byte + fragment)",
		laneLen, len(lanes[0]), len(lanes[1]), len(lanes[2]),
		[3]int{lens[0] + 1, lens[1] + 1, lens[2] + 1})

	// Per-pixel 7-of-8 leak measurement per region. The walk starts at
	// the second pixel: the first one covers the COBS code byte and the
	// interlock-nonce fragment, which no candidate reconstruction
	// predicts, so measuring it would score a byte the attacker cannot
	// know.
	stats := [3]struct{ unique, ambiguous, miss int }{}
	for i := 0; i < 3; i++ {
		region := regions[i]
		width := widths[i]
		lane := lanes[i]
		spI := startPixels[i]
		totalBits := len(lane) * 8
		bitIndex := DataBitsPerPixel
		for pp := 1; pp < width && bitIndex < totalBits; pp++ {
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
	t.Logf("=== trainHash 7-of-8 leak measurement (fixed geometry) ===")
	total := 0
	unique := 0
	for i := 0; i < 3; i++ {
		tot := stats[i].unique + stats[i].ambiguous + stats[i].miss
		if tot == 0 {
			continue
		}
		t.Logf("region %d: total=%d unique=%d (%.1f%%) ambiguous=%d miss=%d",
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
	// Attacker does NOT peek lockSeed and does NOT hold the interlock
	// nonce. He enumerates 2^16 candidate (lo, hi) byte pairs — Components
	// [0]=lo, [1]=hi, [2..7]=0 — and, having no nonce, fixes one of his
	// own choosing. Per candidate: compute expected lane bytes via
	// splitForTriple48LockedInto + cobsEncode + 0x00. Run the same 7-of-8
	// leak measurement per pixel, over the pixels past the unknown
	// fragment. Record match count.
	//
	// Step 0's derived-key recovery is deliberately NOT carried into this
	// step. It is stated against the lockSeed reference, which is exactly
	// what this step assumes away; importing its output would make the
	// null verdict rest on a premise the threat model denies.
	//
	// Hypothesis under cascade defence: real lockSeed's cascade path
	// depends on Components[2..7] non-trivially (trainHash's non-
	// cancelling multiply-add). Attacker's synthetic space
	// (Components[2..7]=0) fundamentally does not reach real cascade
	// output — no candidate matches, even at correct (lo, hi). The
	// unknown interlock nonce is a second, independent gap: the candidate
	// derives its own key from the attacker's chosen nonce, which the
	// encoder's Rank Barrier did not use.
	// If cascade defence holds: top candidate's score at attacker-
	// realistic conditions ≈ random floor.
	// If cascade defence breaks: top candidate = real (lo, hi),
	// score = 100%.
	t.Logf("=== Step 2 — 2^16 lockSeed enumeration (no lockSeed peek, no interlock nonce) ===")
	attackerNonce := make([]byte, currentNonceSizeCfg(cfg))
	type lcScore struct {
		lo, hi byte
		match  int
	}
	// Sentinel init: maxMatch = -1 so first tested candidate always
	// registers as firstAtMax. tiedCount tracks how many candidates
	// hit the running max — a large tie count under a broken cascade
	// indicates structural collapse (many synthetic seeds equally
	// consistent with the observation). scoreHist bins by match count
	// for the full-distribution readout.
	maxMatch := -1
	firstAtMax := lcScore{}
	tiedCount := 0
	scoreHist := make(map[int]int, 76) // 0..75 possible match counts
	// Real lockSeed's rawLo/rawHi (from Debug — used only for the
	// terminal-stage validation printout, NOT for candidate ranking).
	realLo := byte(meta.Debug.Lock[0])
	realHi := byte(meta.Debug.Lock[1])
	realMatch := 0
	for lo := 0; lo < 256; lo++ {
		for hi := 0; hi < 256; hi++ {
			candLock, _ := SeedFromComponents128(thLeak_trainHash,
				uint64(lo), uint64(hi), 0, 0, 0, 0, 0, 0)
			candBp := buildLockBatchPRF48_128Cfg(cfg, candLock, attackerNonce)
			cLane0 := make([]byte, laneLen)
			cLane1 := make([]byte, laneLen)
			cLane2 := make([]byte, laneLen)
			splitForTriple48LockedInto(cfg, kpa, candBp, cLane0, cLane1, cLane2)
			cLanes := [3][]byte{cLane0, cLane1, cLane2}
			var cobs [3][]byte
			for i := 0; i < 3; i++ {
				cobs[i], _ = laneStreamWithUnknownFragment(cLanes[i], lens[i])
			}
			totalMatch := 0
			for i := 0; i < 3; i++ {
				region := regions[i]
				width := widths[i]
				lane := cobs[i]
				spI := startPixels[i]
				totalBits := len(lane) * 8
				bitIndex := DataBitsPerPixel
				for pp := 1; pp < width && bitIndex < totalBits; pp++ {
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
			scoreHist[totalMatch]++
			switch {
			case totalMatch > maxMatch:
				maxMatch = totalMatch
				firstAtMax = lcScore{byte(lo), byte(hi), totalMatch}
				tiedCount = 1
			case totalMatch == maxMatch:
				tiedCount++
			}
			if byte(lo) == realLo && byte(hi) == realHi {
				realMatch = totalMatch
			}
		}
	}
	// Histogram summary: sorted ascending by score.
	var histKeys []int
	for k := range scoreHist {
		histKeys = append(histKeys, k)
	}
	sort.Ints(histKeys)
	var histParts []string
	for _, k := range histKeys {
		histParts = append(histParts, fmt.Sprintf("%d/%d: %d", k, total, scoreHist[k]))
	}
	t.Logf("score distribution across 65,536 candidates: %s", strings.Join(histParts, ", "))
	// Convergence threshold: four fifths of the scored pixels.
	convergeAt := total * 4 / 5
	realIsMax := realMatch == maxMatch
	switch {
	case maxMatch == 0:
		t.Logf("Step 2 BLOCKED: all 65,536 candidates at 0/%d — cascade defence holds structurally", total)
		t.Logf("real (labonly): lo=0x%02x hi=0x%02x match=%d/%d", realLo, realHi, realMatch, total)
	case tiedCount == 1:
		t.Logf("unique winner: lo=0x%02x hi=0x%02x match=%d/%d", firstAtMax.lo, firstAtMax.hi, firstAtMax.match, total)
		t.Logf("real (labonly): lo=0x%02x hi=0x%02x match=%d/%d (real is winner: %v)", realLo, realHi, realMatch, total, realIsMax)
		if maxMatch > convergeAt {
			t.Logf("Step 2 CONVERGED: cascade defence broken (unique top candidate matches > %d/%d)", convergeAt, total)
		} else {
			t.Logf("Step 2 BLOCKED: unique top candidate at %d/%d (~random floor); cascade defence holds", maxMatch, total)
		}
	default:
		t.Logf("collapse detected: %d candidates tied at max=%d/%d (first: lo=0x%02x hi=0x%02x)", tiedCount, maxMatch, total, firstAtMax.lo, firstAtMax.hi)
		t.Logf("real (labonly): lo=0x%02x hi=0x%02x match=%d/%d (real also at max: %v)", realLo, realHi, realMatch, total, realIsMax)
		if maxMatch > convergeAt {
			t.Logf("Step 2 CONVERGED: cascade defence broken (top score > %d/%d across %d tied candidates — synthetic space structurally collapses to accepting subgroup)", convergeAt, total, tiedCount)
		} else {
			t.Logf("Step 2 BLOCKED: top score at %d/%d (~random floor) despite %d ties; cascade defence holds", maxMatch, total, tiedCount)
		}
	}

	// ---------- Lab-only validation (post-hoc, decorative) ----------
	// The recorded interlock nonce is read HERE and nowhere above. Steps
	// 0 and 0b produced their answers from the observed pixels plus the
	// lockSeed reference; these lines only say whether they landed.
	truthIlNonce, _ := hex.DecodeString(meta.InterlockNonce)
	truthKeyLo, truthKeyHi := lockSeed.deriveInterLockSeed(truthIlNonce)
	t.Logf("--- labonly validation ---")
	t.Logf("derived interlock key: recovered=(0x%02x,0x%02x) truth=(0x%02x,0x%02x) match=%v",
		bestKeyLo, bestKeyHi, truthKeyLo, truthKeyHi,
		uint64(bestKeyLo) == truthKeyLo && uint64(bestKeyHi) == truthKeyHi)
	inSet := [3]bool{}
	allIn := true
	for i := 0; i < 3; i++ {
		want := truthIlNonce[offs[i] : offs[i]+lens[i]]
		for _, c := range fragSets[i] {
			if bytes.Equal(c, want) {
				inSet[i] = true
				break
			}
		}
		allIn = allIn && inSet[i]
	}
	t.Logf("interlock nonce: first-survivor=%s truth=%s; true fragment present in the candidate set per region=%v (all three: %v)",
		hex.EncodeToString(recoveredIl), meta.InterlockNonce, inSet, allIn)

	// Terminal-stage gate on the recovery machinery, not on the attack.
	// The fragment reader mirrors the decoder's per-pixel unmask by hand;
	// if that mirror drifts, every candidate set comes back empty and the
	// harness would otherwise still report PASS, since an empty set is a
	// legitimate measurement outcome elsewhere. Under a primitive whose
	// lanes do depend on the nonce the true fragment must be reachable,
	// so its absence means the mirror broke rather than that the attack
	// narrowed. This consumes ground truth after every decision is made.
	for i := 0; i < 3; i++ {
		if len(fragSets[i]) == 0 {
			t.Errorf("region %d: fragment reader returned no candidates at all — "+
				"unmaskPixelWindow has drifted from the decoder", i+1)
		} else if !inSet[i] {
			t.Errorf("region %d: true fragment absent from %d candidates — "+
				"unmaskPixelWindow has drifted from the decoder", i+1, len(fragSets[i]))
		}
	}
}
