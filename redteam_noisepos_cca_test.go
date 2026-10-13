//go:build redteam

package itb

// Noise-position observations under MAC + Reveal (CCA) on real
// authenticated wires.
//
// Under MAC + Reveal an attacker submits altered ciphertexts and learns
// whether each one authenticates. Flipping the noise bit of a channel
// byte leaves the decoded payload, and with it the MAC, intact; flipping
// any other bit breaks the MAC. Eight flips per pixel therefore reveal
// the noise position of every physical pixel of every region. Pixel
// boundaries (8 bytes each, right after the header) and region
// boundaries (third = W*H / 3) are public, so the attacker holds three
// arrays obs_i[j] = noise position of physical pixel j of region i.
//
// The noise hash runs one counter across the container: region i hashes
// counter i*third + p at stream step p. Two attacks run against those
// arrays, each using only the oracle's accept / reject answers, the
// header (nonce, W, H) and public parameters; ground truth (startPixel_i
// from the start seeds) is read only in the final report.
//
//   - Region alignment (TestRedTeamNoisePosCCARegionAlignment): search
//     for a cyclic shift under which two regions' arrays coincide, and,
//     when region 3 is one pixel longer, for the window that pins both
//     absolute start offsets. A positive control builds the arrays of a
//     layout in which every region's noise counter starts at 0 and checks
//     that the search recovers the offsets there.
//
//   - Public-part match (TestRedTeamNoisePosCCALinearMatch): for a
//     GF(2)-linear primitive the noise hash output splits as a seed-only
//     constant XOR a public function of the input. The attack assumes the
//     same split for the position — a 3-bit constant XOR the position
//     computed with an all-zero seed — enumerates the constant (8) and
//     startPixel_i per region, and matches. The position mixes the two
//     words by integer addition before the fold, so the split does not
//     carry through to it for any primitive, the GF(2)-linear one
//     included; the match is run on every primitive to show it finds
//     nothing.
//
// Primitives (ITB_REDTEAM_NOISEPOS_HASH, comma list, default all):
// siphash (PRF-grade), aesitb128 (the Non-PRF inner-role registry
// primitive), fnv1a (T-function lab helper), crc128 (GF(2)-linear lab
// helper). ITB_REDTEAM_NOISEPOS_TRIALS (default 4) messages of
// ITB_REDTEAM_NOISEPOS_SIZE bytes (default 1500) per primitive, fresh
// seeds and MAC key per message, 1024-bit keys, 128-bit nonce.
//
// Reproduction:
//
//	go test -tags redteam -run 'TestRedTeamNoisePosCCA' -v ./
//	ITB_REDTEAM_NOISEPOS_HASH=crc128 ITB_REDTEAM_NOISEPOS_TRIALS=10 \
//	    go test -tags redteam -run 'TestRedTeamNoisePosCCALinearMatch' -v ./

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fnv1a128Fast is fnv1a128BrokenLab over native 128-bit arithmetic:
// state = seed1:seed0, per byte state ^= b, state *= 2^88 + 0x13B mod
// 2^128. The oracle decrypts thousands of wires, which the big.Int
// reference cannot afford; equality with the reference is checked at
// the start of every run.
func fnv1a128Fast(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo, hi = seed0, seed1
	for _, b := range data {
		lo ^= uint64(b)
		carry, plo := bits.Mul64(lo, 0x13B)
		hi = hi*0x13B + carry + lo<<24
		lo = plo
	}
	return lo, hi
}

type noisePosPrim struct {
	name string
	hash HashFunc128
}

func noisePosPrims(t *testing.T) []noisePosPrim {
	t.Helper()
	aes, _, _ := MakeAESITB128Hash()
	all := map[string]HashFunc128{
		"siphash":   sipHash128,
		"aesitb128": aes,
		"fnv1a":     fnv1a128Fast,
		"crc128":    crc128BrokenLab,
	}
	order := []string{"siphash", "aesitb128", "fnv1a", "crc128"}
	if v := os.Getenv("ITB_REDTEAM_NOISEPOS_HASH"); v != "" {
		order = strings.Split(v, ",")
	}
	var out []noisePosPrim
	for _, n := range order {
		n = strings.TrimSpace(n)
		h, ok := all[n]
		if !ok {
			t.Fatalf("unknown ITB_REDTEAM_NOISEPOS_HASH entry %q", n)
		}
		out = append(out, noisePosPrim{n, h})
	}
	// The fast FNV-1a must equal the big.Int reference.
	buf := make([]byte, 20)
	for i := 0; i < 64; i++ {
		rand.Read(buf)
		s0, s1 := binary.LittleEndian.Uint64(buf[:8]), binary.LittleEndian.Uint64(buf[8:16])
		a0, a1 := fnv1a128Fast(buf, s0, s1)
		b0, b1 := fnv1a128BrokenLab(buf, s0, s1)
		if a0 != b0 || a1 != b1 {
			t.Fatalf("fnv1a128Fast diverges from fnv1a128BrokenLab")
		}
	}
	return out
}

func noisePosEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// noisePosCCAWire is one authenticated wire plus what the oracle and the
// header give the attacker, and the lab-only truth for the report.
type noisePosCCAWire struct {
	nonce      []byte
	total      int
	sizes      [3]int
	base       [3]int
	obs        [3][]int // -1: pixel not resolved to exactly one accepted flip
	unresolved int
	truthSP    [3]int // lab only — final report
}

// noisePosCCAObserve encrypts one random message and runs the MAC +
// Reveal oracle over every pixel of every region (channel 0, eight
// flips). The oracle is the defender's decryptor; the attacker sees
// only accept / reject.
func noisePosCCAObserve(t *testing.T, h HashFunc128, size int) noisePosCCAWire {
	t.Helper()
	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	var s [8]*Seed128
	for i := range s {
		var err error
		if s[i], err = NewSeed128(1024, h); err != nil {
			t.Fatal(err)
		}
	}
	macKey := make([]byte, 32)
	rand.Read(macKey)
	mac := func(d []byte) []byte { m := hmac.New(sha256.New, macKey); m.Write(d); return m.Sum(nil) }
	msg := make([]byte, size)
	rand.Read(msg)
	wire, err := EncryptAuthenticated3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], msg, mac)
	if err != nil {
		t.Fatal(err)
	}

	nlen := currentNonceSizeCfg(cfg)
	body := wire[streamIDPrefixLen:]
	var w noisePosCCAWire
	w.nonce = append([]byte(nil), body[:nlen]...)
	w.total = int(binary.BigEndian.Uint16(body[nlen:])) * int(binary.BigEndian.Uint16(body[nlen+2:]))
	third := w.total / 3
	w.sizes = [3]int{third, third, w.total - 2*third}
	w.base = [3]int{0, third, 2 * third}
	containerOff := streamIDPrefixLen + nlen + 4

	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan [2]int)
	for k := 0; k < runtime.NumCPU(); k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tw := bytes.Clone(wire)
			for job := range jobs {
				i, j := job[0], job[1]
				off := containerOff + (w.base[i]+j)*Channels
				found, hits := -1, 0
				for b := 0; b < 8; b++ {
					tw[off] ^= 1 << b
					if _, err := DecryptAuthenticated3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], tw, mac); err == nil {
						found, hits = b, hits+1
					}
					tw[off] ^= 1 << b
				}
				if hits != 1 {
					found = -1
				}
				mu.Lock()
				w.obs[i][j] = found
				if found < 0 {
					w.unresolved++
				}
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < 3; i++ {
		w.obs[i] = make([]int, w.sizes[i])
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < w.sizes[i]; j++ {
			jobs <- [2]int{i, j}
		}
	}
	close(jobs)
	wg.Wait()

	for i := 0; i < 3; i++ {
		w.truthSP[i] = s[5+i].deriveStartPixel(w.nonce, w.sizes[i])
	}
	return w
}

func noisePosEq(a, b int) bool { return a < 0 || b < 0 || a == b }

// noisePosRelative returns every shift d with b[(j+d) mod |b|] == a[j]
// for all j.
func noisePosRelative(a, b []int) []int {
	var out []int
	for d := 0; d < len(b); d++ {
		ok := true
		for j := range a {
			if !noisePosEq(b[(j+d)%len(b)], a[j]) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, d)
		}
	}
	return out
}

// noisePosAbsolute returns every (w, s) for which the |a|-long window of
// b starting at w equals the rotation of a starting at s. With |b| =
// |a| + 1 and a shared position sequence, the single solution is both
// regions' step 0, which pins both absolute start offsets.
func noisePosAbsolute(a, b []int) [][2]int {
	var out [][2]int
	for w := 0; w < len(b); w++ {
		for s := 0; s < len(a); s++ {
			ok := true
			for k := range a {
				if !noisePosEq(b[(w+k)%len(b)], a[(s+k)%len(a)]) {
					ok = false
					break
				}
			}
			if ok {
				out = append(out, [2]int{w, s})
			}
		}
	}
	return out
}

// noisePosShiftScore returns the match fraction of a against b at shift d.
func noisePosShiftScore(a, b []int, d int) float64 {
	m := 0
	for j := range a {
		if noisePosEq(b[(j+d)%len(b)], a[j]) {
			m++
		}
	}
	return float64(m) / float64(len(a))
}

type noisePosAlignResult struct {
	Hash          string  `json:"hash"`
	Trials        int     `json:"trials"`
	RelativeExact int     `json:"relative_offset_exact"`
	AbsoluteExact int     `json:"absolute_startpixel_exact"`
	AbsoluteRuns  int     `json:"absolute_runs"`
	TrueShiftMean float64 `json:"true_shift_match_mean"`
	BestShiftMean float64 `json:"best_shift_match_mean"`
	Unresolved    int     `json:"unresolved_pixels"`
}

func TestRedTeamNoisePosCCARegionAlignment(t *testing.T) {
	trials := noisePosEnvInt("ITB_REDTEAM_NOISEPOS_TRIALS", 4)
	size := noisePosEnvInt("ITB_REDTEAM_NOISEPOS_SIZE", 1500)
	var results []noisePosAlignResult

	for _, p := range noisePosPrims(t) {
		r := noisePosAlignResult{Hash: p.name, Trials: trials}
		for tr := 0; tr < trials; tr++ {
			w := noisePosCCAObserve(t, p.hash, size)
			r.Unresolved += w.unresolved

			// Attacker: arrays only.
			rel := noisePosRelative(w.obs[0], w.obs[1])
			var abs [][2]int
			if w.sizes[2] != w.sizes[0] {
				abs = noisePosAbsolute(w.obs[0], w.obs[2])
			}
			best := 0.0
			for d := 0; d < w.sizes[1]; d++ {
				if v := noisePosShiftScore(w.obs[0], w.obs[1], d); v > best {
					best = v
				}
			}

			// Lab-only validation below this line.
			trueD := (w.truthSP[1] - w.truthSP[0] + w.sizes[1]) % w.sizes[1]
			if len(rel) == 1 && rel[0] == trueD {
				r.RelativeExact++
			}
			if w.sizes[2] != w.sizes[0] {
				r.AbsoluteRuns++
				if len(abs) == 1 && abs[0] == [2]int{w.truthSP[2], w.truthSP[0]} {
					r.AbsoluteExact++
				}
			}
			r.TrueShiftMean += noisePosShiftScore(w.obs[0], w.obs[1], trueD) / float64(trials)
			r.BestShiftMean += best / float64(trials)
		}
		t.Logf("%-9s relative offset exact %d/%d, absolute startPixel exact %d/%d, true-shift match %.3f (chance 0.125), best shift %.3f, unresolved pixels %d",
			r.Hash, r.RelativeExact, r.Trials, r.AbsoluteExact, r.AbsoluteRuns, r.TrueShiftMean, r.BestShiftMean, r.Unresolved)
		if r.RelativeExact != 0 || r.AbsoluteExact != 0 {
			t.Errorf("%s: region alignment recovered start offsets", r.Hash)
		}
		// The GF(2)-linear crc128 carries structured correlation between
		// noise counters, which lifts its shift scores above chance
		// without producing an exact alignment; its noise positions are
		// recovered outright by the public-part match instead, so the
		// chance-level bound applies to the other primitives only.
		if p.name != "crc128" && r.TrueShiftMean > 0.25 {
			t.Errorf("%s: true-shift match %.3f is far above chance", r.Hash, r.TrueShiftMean)
		}
		results = append(results, r)
	}

	// Positive control: the same search on the arrays of a layout in
	// which every region's noise counter starts at 0, built from a real
	// noise seed and the true start offsets of a real wire geometry.
	ns, err := NewSeed128(1024, sipHash128)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	const total = 35 * 35
	third := total / 3
	sizes := [3]int{third, third, total - 2*third}
	buf := make([]byte, 4+len(nonce))
	copy(buf[4:], nonce)
	var sp [3]int
	var ctl [3][]int
	for i := 0; i < 3; i++ {
		var x [8]byte
		rand.Read(x[:])
		sp[i] = int(binary.LittleEndian.Uint64(x[:]) % uint64(sizes[i]))
		ctl[i] = make([]int, sizes[i])
		for p := 0; p < sizes[i]; p++ {
			lo, hi := ns.blockHash128(buf, p)
			ctl[i][(sp[i]+p)%sizes[i]] = int(noisePosition(lo, hi))
		}
	}
	rel := noisePosRelative(ctl[0], ctl[1])
	if len(rel) != 1 || rel[0] != (sp[1]-sp[0]+sizes[1])%sizes[1] {
		t.Errorf("positive control: shared-counter layout not aligned (candidates %v)", rel)
	} else {
		t.Logf("positive control (every region's noise counter from 0): relative offset recovered exactly")
	}

	noisePosEmit(t, "region_alignment.json", results)
}

type noisePosLinearResult struct {
	Hash       string `json:"hash"`
	Regions    int    `json:"regions"`
	Exact      int    `json:"unique_candidate_equals_truth"`
	Candidates int    `json:"total_candidates"`
	Unresolved int    `json:"unresolved_pixels"`
}

func TestRedTeamNoisePosCCALinearMatch(t *testing.T) {
	trials := noisePosEnvInt("ITB_REDTEAM_NOISEPOS_TRIALS", 4)
	size := noisePosEnvInt("ITB_REDTEAM_NOISEPOS_SIZE", 1500)
	var results []noisePosLinearResult

	for _, p := range noisePosPrims(t) {
		// The attacker's public-part evaluator: the same primitive under
		// an all-zero seed of the assumed key size.
		zero, err := SeedFromComponents128(p.hash, make([]uint64, 1024/64)...)
		if err != nil {
			t.Fatal(err)
		}
		r := noisePosLinearResult{Hash: p.name}
		for tr := 0; tr < trials; tr++ {
			w := noisePosCCAObserve(t, p.hash, size)
			r.Unresolved += w.unresolved

			// Attacker: oracle arrays, header nonce, public part.
			buf := make([]byte, 4+len(w.nonce))
			copy(buf[4:], w.nonce)
			pub := make([]int, w.total)
			for c := 0; c < w.total; c++ {
				lo, hi := zero.blockHash128(buf, c)
				pub[c] = int(noisePosition(lo, hi))
			}
			var found [3][][2]int
			for i := 0; i < 3; i++ {
				T := w.sizes[i]
				for k := 0; k < 8; k++ {
					for sp := 0; sp < T; sp++ {
						ok := true
						for j := 0; j < T && ok; j++ {
							if w.obs[i][j] >= 0 && w.obs[i][j] != k^pub[w.base[i]+(j-sp+T)%T] {
								ok = false
							}
						}
						if ok {
							found[i] = append(found[i], [2]int{k, sp})
						}
					}
				}
			}

			// Lab-only validation below this line.
			for i := 0; i < 3; i++ {
				r.Regions++
				r.Candidates += len(found[i])
				if len(found[i]) == 1 && found[i][0][1] == w.truthSP[i] {
					r.Exact++
				}
			}
		}
		t.Logf("%-9s unique (noise constant, startPixel) == truth in %d/%d regions, %d candidates in total, unresolved pixels %d",
			r.Hash, r.Exact, r.Regions, r.Candidates, r.Unresolved)
		if r.Exact != 0 {
			t.Errorf("%s: public-part match recovered %d regions", r.Hash, r.Exact)
		}
		results = append(results, r)
	}
	noisePosEmit(t, "linear_match.json", results)
}

func noisePosEmit(t *testing.T, name string, v any) {
	t.Helper()
	dir := redteamOutputDir("noisepos_cca")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("[emit] skipped: %v", err)
		return
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Logf("[emit] skipped: %v", err)
		return
	}
	t.Logf("[emit] %s", path)
}
