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
	"os"
	"path/filepath"
	"testing"
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
	lockSeed, _ := SeedFromComponents128(thLeak_trainHash, meta.Debug.Lock...)
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

	// Per-pixel 7-of-8 leak measurement per region.
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
	// Attacker does NOT peek lockSeed. He enumerates 2^16 candidate
	// (lo, hi) byte pairs via trainHashSeedConst(lo, hi) — Components
	// [0]=lo, [1]=hi, [2..7]=0. Per candidate: compute expected lane
	// bytes via splitForTriple48LockedInto + cobsEncode + 0x00. Run
	// the same 7-of-8 leak measurement per pixel. Record match count.
	//
	// Hypothesis under cascade defence: real lockSeed's cascade path
	// depends on Components[2..7] non-trivially (trainHash's non-
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
			candLock, _ := SeedFromComponents128(thLeak_trainHash,
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
