// order5_chainhash_go — 5th-order (2^40-text) Λ-set integral through
// ChainHash<AES-ITB-128>, every cascade depth r <= --rounds in one pass.
//
// Usage:
//
//	go run scripts/redteam/itb/theory/aesitb128/order5_chainhash_go/main.go [flags]
//
// Pure Go, no cgo. The cascade is driven one round at a time through the
// shipped 4-lane batched arm (the internal/aesitbasm 13-byte chain-absorb
// kernel — the code the registry's aesitb128 BatchHash arm dispatches to),
// so every depth's h_r is available for XOR accumulation from one sweep of
// the cube:
//
//	h_1 = H(data, c[0], c[1])
//	h_r = H(data, c[2r-2] ^ lo(h_{r-1}), c[2r-1] ^ hi(h_{r-1}))
//
// This is the Seed128.ChainHash128 recurrence; the startup self-test pins
// the driven per-depth values to the shipped single arm
// (hashes.AESITB128PairWithKey) on random texts before the sweep starts.
//
// Observables per depth (the columns of order4_chainhash.py):
//
//	discard on           lo lane (8 bytes) of h_r — what ITB's encoder sees
//	discard off, raw     full 16-byte h_r
//	discard off, peeled  P^-1 through the last call exposes seed_r ^ h_{r-1};
//	                     over an even Λ-set the constant seed_r cancels, so
//	                     the peeled XOR-sum at depth r equals the raw XOR-sum
//	                     at depth r-1 (at r = 1 it is the constant seed block,
//	                     balanced trivially). Reported from the raw sums — no
//	                     inversion is run.
//
// Λ-set: the five active data bytes carry the 40-bit text index (byte k of
// --active carries index bits 8k..8k+7); the remaining data bytes hold a
// random constant. Default --active 1,6,11,12,0: positions {1, 6, 11, 12}
// form the ShiftRows diagonal that lands in state column 3 (position
// 4*((c+row) mod 4) + row for c = 3), the only diagonal fully inside the 13
// data bytes of the one-block lab shape (bytes 13..15 are PKCS#7 pad). With
// the diagonal in index bits 0..31, every completed 2^32 sub-cube (one fixed
// value of the fifth byte) is on its own a valid diagonal order-4 Λ-set, so
// an early kill leaves valid order-4 verdicts in the log.
//
// Work is split into 2^(log2-texts - log2-sub) sub-cubes pulled from an
// atomic counter by --workers goroutines; a checkpoint line with the
// sub-cube's own balanced counts is printed after every sub-cube, and a
// heartbeat line (texts done, rate, ETA) every --heartbeat. --log2-texts
// below 40 (or --log2-sub below 32) is a smoke configuration: the top active
// byte does not cover all 256 values, so the sums are not a Λ-set integral.
//
// fixedKey is the aesitb/ reference key (attacker-known, as in the Python
// mirror chainhashes/aesitb128.py); components come from --seed (0 =
// crypto/rand) or --comps.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	mrand "math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/aesitbasm"
)

const (
	shape      = 13 // one-block lab shape: 13 data bytes + 3 PKCS#7 pad bytes
	lanes      = 4  // batched-arm lane count
	activeCnt  = 5  // order of the integral
	maxRounds  = 64 // component pairs the driver allocates for
	reportStep = 1 << 16
)

// fixedKey is the aesitb/ package reference key — the Python mirror's
// FIXED_KEY. Treated as attacker-known.
var fixedKey = [16]byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
}

type config struct {
	rounds    int
	workers   int
	log2Texts uint
	log2Sub   uint
	active    [activeCnt]int
	comps     []uint64
	fixed     [shape]byte
}

// depthAcc accumulates one cascade depth: the XOR-sum of (lo, hi), the
// first value seen, and the OR of every value's difference from it (a
// non-zero byte in diffOr marks that output byte as active).
type depthAcc struct {
	xor    [2]uint64
	first  [2]uint64
	diffOr [2]uint64
	seen   bool
}

func (d *depthAcc) add(v [2]uint64) {
	if !d.seen {
		d.first = v
		d.seen = true
	}
	d.xor[0] ^= v[0]
	d.xor[1] ^= v[1]
	d.diffOr[0] |= v[0] ^ d.first[0]
	d.diffOr[1] |= v[1] ^ d.first[1]
}

func (d *depthAcc) merge(o *depthAcc) {
	if !o.seen {
		return
	}
	if !d.seen {
		*d = *o
		return
	}
	d.xor[0] ^= o.xor[0]
	d.xor[1] ^= o.xor[1]
	d.diffOr[0] |= o.diffOr[0] | (o.first[0] ^ d.first[0])
	d.diffOr[1] |= o.diffOr[1] | (o.first[1] ^ d.first[1])
}

type accum struct {
	d     []depthAcc
	texts uint64
}

func newAccum(rounds int) *accum { return &accum{d: make([]depthAcc, rounds)} }

func (a *accum) merge(o *accum) {
	for r := range a.d {
		a.d[r].merge(&o.d[r])
	}
	a.texts += o.texts
}

// counts returns (#active, #balanced) over the first nbytes bytes of the
// (lo, hi) pair.
func (d *depthAcc) counts(nbytes int) (active, balanced int) {
	for b := 0; b < nbytes; b++ {
		w, sh := d.xor[b/8], uint(8*(b%8))
		if (w>>sh)&0xFF == 0 {
			balanced++
		}
		if (d.diffOr[b/8]>>sh)&0xFF != 0 {
			active++
		}
	}
	return
}

// cascadeGroup runs all depths on one 4-lane group. out[r] receives the
// four lanes' h_{r+1}.
func cascadeGroup(cfg *config, ptrs *[4]*byte, out [][4][2]uint64) {
	var seeds [4][2]uint64
	for l := 0; l < lanes; l++ {
		seeds[l] = [2]uint64{cfg.comps[0], cfg.comps[1]}
	}
	for r := 0; r < cfg.rounds; r++ {
		if r > 0 {
			c0, c1 := cfg.comps[2*r], cfg.comps[2*r+1]
			prev := &out[r-1]
			for l := 0; l < lanes; l++ {
				seeds[l][0] = c0 ^ prev[l][0]
				seeds[l][1] = c1 ^ prev[l][1]
			}
		}
		aesitbasm.AESITB128ChainAbsorb13x4(&fixedKey, &seeds, ptrs, &out[r])
	}
}

// runSubCube sweeps sub-cube `sub` (text indices sub<<log2Sub .. +2^log2Sub)
// and returns its accumulator. progress is bumped every reportStep texts.
func runSubCube(cfg *config, sub uint64, progress *uint64) *accum {
	acc := newAccum(cfg.rounds)
	var bufs [lanes][shape]byte
	var ptrs [4]*byte
	for l := range bufs {
		bufs[l] = cfg.fixed
		ptrs[l] = &bufs[l][0]
	}
	out := make([][4][2]uint64, cfg.rounds)
	size := uint64(1) << cfg.log2Sub
	base := sub << cfg.log2Sub
	for i := uint64(0); i < size; i += lanes {
		for l := 0; l < lanes; l++ {
			idx := base + i + uint64(l)
			for k := 0; k < activeCnt; k++ {
				bufs[l][cfg.active[k]] = byte(idx >> (8 * uint(k)))
			}
		}
		cascadeGroup(cfg, &ptrs, out)
		for r := 0; r < cfg.rounds; r++ {
			d := &acc.d[r]
			for l := 0; l < lanes; l++ {
				d.add(out[r][l])
			}
		}
		if (i+lanes)%reportStep == 0 {
			atomic.AddUint64(progress, reportStep)
		}
	}
	acc.texts = size
	return acc
}

// selfTest pins the batched-arm-driven per-depth values to the shipped
// single arm on random texts.
func selfTest(cfg *config) error {
	h, _ := hashes.AESITB128PairWithKey(fixedKey)
	var bufs [lanes][shape]byte
	var ptrs [4]*byte
	for l := range bufs {
		if _, err := rand.Read(bufs[l][:]); err != nil {
			return err
		}
		ptrs[l] = &bufs[l][0]
	}
	out := make([][4][2]uint64, cfg.rounds)
	cascadeGroup(cfg, &ptrs, out)
	for l := 0; l < lanes; l++ {
		lo, hi := h(bufs[l][:], cfg.comps[0], cfg.comps[1])
		for r := 0; r < cfg.rounds; r++ {
			if r > 0 {
				lo, hi = h(bufs[l][:], cfg.comps[2*r]^lo, cfg.comps[2*r+1]^hi)
			}
			if out[r][l] != [2]uint64{lo, hi} {
				return fmt.Errorf("lane %d depth %d: driven (%016x,%016x) != sequential (%016x,%016x)",
					l, r+1, out[r][l][0], out[r][l][1], lo, hi)
			}
		}
	}
	return nil
}

func verdict(balanced int, rexp float64, hasRexp bool) string {
	if !hasRexp {
		return "constant (seed block)"
	}
	if float64(balanced) > rexp+1 {
		return "HIGHER-ORDER LEAK"
	}
	return "random (no 5th-order leak)"
}

func printTable(w *os.File, title string, acc *accum) {
	fmt.Fprintf(w, "%s\n", title)
	fmt.Fprintf(w, "%5s %-20s %8s %10s %9s  verdict\n", "depth", "observable", "#active", "#balanced", "rand_exp")
	for r := 0; r < len(acc.d); r++ {
		aLo, bLo := acc.d[r].counts(8)
		aFull, bFull := acc.d[r].counts(16)
		fmt.Fprintf(w, "%5d %-20s %8d %10d %9.3f  %s\n", r+1, "discard on", aLo, bLo, 8/256.0, verdict(bLo, 8/256.0, true))
		fmt.Fprintf(w, "%5d %-20s %8d %10d %9.3f  %s\n", r+1, "discard off, raw", aFull, bFull, 16/256.0, verdict(bFull, 16/256.0, true))
		if r == 0 {
			fmt.Fprintf(w, "%5d %-20s %8d %10d %9s  %s\n", r+1, "discard off, peeled", 0, 16, "-", verdict(16, 0, false))
		} else {
			aP, bP := acc.d[r-1].counts(16)
			fmt.Fprintf(w, "%5d %-20s %8d %10d %9.3f  %s\n", r+1, "discard off, peeled", aP, bP, 16/256.0, verdict(bP, 16/256.0, true))
		}
	}
}

func parseActive(s string) ([activeCnt]int, error) {
	var a [activeCnt]int
	parts := strings.Split(s, ",")
	if len(parts) != activeCnt {
		return a, fmt.Errorf("--active needs %d positions, got %d", activeCnt, len(parts))
	}
	seen := map[int]bool{}
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 || v >= shape || seen[v] {
			return a, fmt.Errorf("--active position %q must be a distinct integer in [0, %d)", p, shape)
		}
		seen[v] = true
		a[i] = v
	}
	return a, nil
}

func parseComps(s string, n int) ([]uint64, error) {
	parts := strings.Split(s, ",")
	if len(parts) != n {
		return nil, fmt.Errorf("--comps needs %d hex words, got %d", n, len(parts))
	}
	out := make([]uint64, n)
	for i, p := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("--comps word %d: %v", i, err)
		}
		out[i] = v
	}
	return out, nil
}

func fmtComps(c []uint64) string {
	parts := make([]string, len(c))
	for i, v := range c {
		parts[i] = fmt.Sprintf("%016x", v)
	}
	return strings.Join(parts, ",")
}

func main() {
	rounds := flag.Int("rounds", 16, "cascade depth R (all depths 1..R are reported)")
	workers := flag.Int("workers", runtime.NumCPU(), "goroutines")
	log2Texts := flag.Uint("log2-texts", 40, "log2 of the text count (40 = order-5 Λ-set; less = smoke only)")
	log2Sub := flag.Uint("log2-sub", 32, "log2 of the sub-cube checkpoint size (32 = one order-4 Λ-set per sub-cube)")
	activeStr := flag.String("active", "1,6,11,12,0", "five active data byte positions; byte k carries index bits 8k..8k+7")
	seed := flag.Int64("seed", 0, "math/rand seed for components and the fixed bytes (0 = crypto/rand)")
	compsStr := flag.String("comps", "", "explicit 2R comma-separated hex components (overrides --seed)")
	heartbeat := flag.Duration("heartbeat", time.Minute, "progress line interval")
	flag.Parse()

	if *rounds < 1 || *rounds > maxRounds {
		fmt.Fprintf(os.Stderr, "--rounds must be in [1, %d]\n", maxRounds)
		os.Exit(2)
	}
	if *log2Sub < 2 || *log2Sub > *log2Texts || *log2Texts > 40 {
		fmt.Fprintln(os.Stderr, "need 2 <= --log2-sub <= --log2-texts <= 40")
		os.Exit(2)
	}
	if *workers < 1 {
		*workers = 1
	}
	active, err := parseActive(*activeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	cfg := &config{rounds: *rounds, workers: *workers, log2Texts: *log2Texts, log2Sub: *log2Sub, active: active}
	nComps := 2 * cfg.rounds
	var rng *mrand.Rand
	if *seed != 0 {
		rng = mrand.New(mrand.NewSource(*seed))
	}
	randomBytes := func(b []byte) {
		if rng != nil {
			rng.Read(b)
			return
		}
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintln(os.Stderr, "crypto/rand:", err)
			os.Exit(1)
		}
	}
	if *compsStr != "" {
		cfg.comps, err = parseComps(*compsStr, nComps)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		raw := make([]byte, 8*nComps)
		randomBytes(raw)
		cfg.comps = make([]uint64, nComps)
		for i := range cfg.comps {
			cfg.comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
	}
	randomBytes(cfg.fixed[:])

	if err := selfTest(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "self-test FAILED:", err)
		os.Exit(1)
	}

	nSub := uint64(1) << (cfg.log2Texts - cfg.log2Sub)
	total := uint64(1) << cfg.log2Texts
	fmt.Printf("5th-order integral through ChainHash<AES-ITB-128>: 2^%d texts, active bytes %v, "+
		"data_len=%d (one-block lab shape), depths 1..%d, %d workers, 2^%d sub-cubes of 2^%d texts\n",
		cfg.log2Texts, cfg.active, shape, cfg.rounds, cfg.workers, cfg.log2Texts-cfg.log2Sub, cfg.log2Sub)
	fmt.Printf("self-test OK (driven cascade == shipped single arm, %d lanes x %d depths)\n", lanes, cfg.rounds)
	fmt.Printf("fixed_key=%s fixed_bytes=%s\ncomps=%s\n", hex.EncodeToString(fixedKey[:]), hex.EncodeToString(cfg.fixed[:]), fmtComps(cfg.comps))
	if cfg.log2Texts < 40 || cfg.log2Sub < 32 {
		fmt.Println("NOTE: smoke configuration — the sums below are not a Λ-set integral")
	}

	t0 := time.Now()
	var progress uint64
	var next uint64
	var mu sync.Mutex
	global := newAccum(cfg.rounds)
	done := uint64(0)

	stop := make(chan struct{})
	var hb sync.WaitGroup
	hb.Add(1)
	go func() {
		defer hb.Done()
		tick := time.NewTicker(*heartbeat)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				n := atomic.LoadUint64(&progress)
				el := time.Since(t0).Seconds()
				rate := float64(n) / el
				eta := 0.0
				if rate > 0 {
					eta = float64(total-n) / rate
				}
				fmt.Printf("  ... heartbeat: %d/%d texts (%.1f %%), %.0f s, %.1f M texts/s, ETA %.0f s, %d/%d sub-cubes done\n",
					n, total, 100*float64(n)/float64(total), el, rate/1e6, eta, atomic.LoadUint64(&done), nSub)
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < cfg.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				sub := atomic.AddUint64(&next, 1) - 1
				if sub >= nSub {
					return
				}
				acc := runSubCube(cfg, sub, &progress)
				mu.Lock()
				global.merge(acc)
				k := atomic.AddUint64(&done, 1)
				el := time.Since(t0).Seconds()
				rate := float64(atomic.LoadUint64(&progress)) / el
				var sb strings.Builder
				// The sub-cube index is index bits [log2Sub, log2Texts); at the
				// default split it is exactly the fifth active byte's value.
				fmt.Fprintf(&sb, "[ckpt %d/%d] sub-cube %d", k, nSub, sub)
				switch {
				case nSub == 1:
					sb.WriteString(" (whole cube):")
				case cfg.log2Sub == 32 && cfg.log2Texts == 40:
					fmt.Fprintf(&sb, " (fifth active byte 0x%02x):", byte(sub))
				default:
					fmt.Fprintf(&sb, " (index bits %d..%d = %#x):", cfg.log2Sub, cfg.log2Texts-1, sub)
				}
				for r := 0; r < cfg.rounds; r++ {
					_, bLo := acc.d[r].counts(8)
					_, bFull := acc.d[r].counts(16)
					fmt.Fprintf(&sb, " r%d=%d/%d", r+1, bLo, bFull)
				}
				fmt.Fprintf(&sb, " | %.0f s, %.1f M texts/s, ETA %.0f s", el, rate/1e6,
					float64(total-atomic.LoadUint64(&progress))/rate)
				fmt.Println(sb.String())
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(stop)
	hb.Wait()

	el := time.Since(t0).Seconds()
	rate := float64(global.texts) / el
	printTable(os.Stdout, fmt.Sprintf("cumulative over %d sub-cubes (%d texts):", done, global.texts), global)
	fmt.Printf("DONE (%.0f s, %.1f M texts/s over %d depths; projected 2^40 at this rate: %.0f s = %.2f h)\n",
		el, rate/1e6, cfg.rounds, float64(uint64(1)<<40)/rate, float64(uint64(1)<<40)/rate/3600)
}
