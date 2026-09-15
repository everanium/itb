// order5_aes2r_go — 5th-order (2^40-text) Λ-set integral through
// ChainHash<aes2r>, every cascade depth r <= --rounds in one pass: the aes2r
// counterpart of scripts/redteam/itb/theory/aesitb128/order5_chainhash_go.
//
// Usage:
//
//	go run scripts/redteam/itb/theory/aes2r/order5_aes2r_go/main.go [flags]
//
// aes2r is round-reduced standard AES over one padded 16-byte block with the
// seed as the AES key (chainhashes/aes2r.py: key = seed_hi<<64 | seed_lo as 16
// big-endian bytes, pt = data[:15] || 0x80, lo = last 8 big-endian ct bytes,
// hi = first 8). The cascade is the Seed128.ChainHash128 recurrence:
//
//	h_1 = AES_NR(pt, key(c[0], c[1]))
//	h_r = AES_NR(pt, key(c[2r-2] ^ lo(h_{r-1}), c[2r-1] ^ hi(h_{r-1})))
//
// so at r >= 2 every call carries a fresh data-dependent key and its own key
// expansion — the cost per text is dominated by NR+1 round keys per call, not
// by the rounds. The rounds run through go-aes RoundHW / FinalRoundHW (AES-NI)
// when the host has it, pinned against the software rounds and the FIPS-197
// KAT by the startup self-test.
//
// Observables per depth: `discard on` (lo lane, 8 bytes) and `discard off`
// (full 16-byte ct). There is no `peeled` column: aes2r's last call is a keyed
// permutation, so no public inverse exists.
//
// Λ-set: the five active data bytes carry the 40-bit text index (byte k of
// --active carries index bits 8k..8k+7); the remaining data bytes hold a random
// constant; byte 15 is the fixed pad. Default --active 1,6,11,12,0: {1,6,11,12}
// is the ShiftRows diagonal landing in state column 3 (the square5_go set), so
// with it in index bits 0..31 every completed 2^32 sub-cube is on its own a
// valid diagonal order-4 Λ-set and an early stop leaves valid order-4 verdicts.
//
// The 2^40 sweep is split into 2^(log2-texts - log2-sub) sub-cubes pulled from
// an atomic counter by --workers goroutines. --resume FILE persists every
// finished sub-cube's per-depth accumulators (XOR-sum, first value, activity
// OR) so the sweep can be chained across bounded invocations: --max-seconds
// stops handing out new sub-cubes after the budget (running ones finish), and
// a later run with the same --resume file skips the finished ones and merges.
// The final table is printed from the merged state; --report-only prints it
// without sweeping. A truncated cube is not an order-5 integral — the report
// states the number of sub-cubes merged and marks the order-5 row as partial
// until all are in, while every complete 2^32 group of sub-cubes (index bits
// 32..39 fixed) is reported as an order-4 verdict on its own.
//
// This is a lab baseline probe (chosen data, both lanes reported), the mirror
// of the aesitb128 order-5 probe, not a shipped-attacker-model measurement.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aes "github.com/jedisct1/go-aes"
)

const (
	maxActive = 5
	maxRounds = 64
	maxNR     = 10
)

// activeCnt is the Λ-set order (the number of active positions given), 4 or 5.
var activeCnt = maxActive

// ---- AES tables (FIPS-197, column-major state s[row + 4*col]) ----------------
var (
	sbox [256]byte
	mul  [4][256]byte
	rcon = [11]byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}
)

func gmul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return p
}

func initAES() {
	var inv [256]byte
	for a := 1; a < 256; a++ {
		for b := 1; b < 256; b++ {
			if gmul(byte(a), byte(b)) == 1 {
				inv[a] = byte(b)
				break
			}
		}
	}
	for x := 0; x < 256; x++ {
		b := inv[x]
		var s byte
		for i := 0; i < 8; i++ {
			bit := ((b >> i) & 1) ^ ((b >> ((i + 4) % 8)) & 1) ^
				((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 6) % 8)) & 1) ^
				((b >> ((i + 7) % 8)) & 1) ^ ((0x63 >> i) & 1)
			s |= bit << i
		}
		sbox[x] = s
	}
	if sbox[0x00] != 0x63 || sbox[0x01] != 0x7C || sbox[0x53] != 0xED || sbox[0xFF] != 0x16 {
		panic("S-box generation mismatch")
	}
	for m := 0; m < 4; m++ {
		for x := 0; x < 256; x++ {
			mul[m][x] = gmul(byte(m), byte(x))
		}
	}
}

func shiftRows(s [16]byte) [16]byte {
	var o [16]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			o[r+4*c] = s[r+4*((c+r)%4)]
		}
	}
	return o
}

func mixColumns(s [16]byte) [16]byte {
	var o [16]byte
	for c := 0; c < 4; c++ {
		a0, a1, a2, a3 := s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
		o[4*c] = mul[2][a0] ^ mul[3][a1] ^ a2 ^ a3
		o[4*c+1] = a0 ^ mul[2][a1] ^ mul[3][a2] ^ a3
		o[4*c+2] = a0 ^ a1 ^ mul[2][a2] ^ mul[3][a3]
		o[4*c+3] = mul[3][a0] ^ a1 ^ a2 ^ mul[2][a3]
	}
	return o
}

// keyExpandInto is the allocation-free AES-128 key schedule (nr+1 round keys).
func keyExpandInto(key [16]byte, nr int, rks *[maxNR + 1][16]byte) {
	// Word-level schedule: each 4-byte column is one little-endian uint32
	// (byte 0 in the low bits), so RotWord is a byte rotation of the word and
	// SubWord four table lookups.
	rks[0] = key
	w0 := binary.LittleEndian.Uint32(key[0:4])
	w1 := binary.LittleEndian.Uint32(key[4:8])
	w2 := binary.LittleEndian.Uint32(key[8:12])
	w3 := binary.LittleEndian.Uint32(key[12:16])
	for k := 1; k <= nr; k++ {
		t := (w3 >> 8) | (w3 << 24)
		t = uint32(sbox[byte(t)]) | uint32(sbox[byte(t>>8)])<<8 | uint32(sbox[byte(t>>16)])<<16 | uint32(sbox[byte(t>>24)])<<24
		t ^= uint32(rcon[k])
		w0 ^= t
		w1 ^= w0
		w2 ^= w1
		w3 ^= w2
		binary.LittleEndian.PutUint32(rks[k][0:4], w0)
		binary.LittleEndian.PutUint32(rks[k][4:8], w1)
		binary.LittleEndian.PutUint32(rks[k][8:12], w2)
		binary.LittleEndian.PutUint32(rks[k][12:16], w3)
	}
}

// useHW routes encRK through the go-aes AES-NI round primitives.
var useHW bool

// encRK runs nr standard AES rounds (final round without MixColumns).
func encRK(block [16]byte, rks *[maxNR + 1][16]byte, nr int) [16]byte {
	s := block
	for i := range s {
		s[i] ^= rks[0][i]
	}
	if useHW {
		b := (*aes.Block)(&s)
		for r := 1; r < nr; r++ {
			aes.RoundHW(b, (*aes.Block)(&rks[r]))
		}
		aes.FinalRoundHW(b, (*aes.Block)(&rks[nr]))
		return s
	}
	for r := 1; r < nr; r++ {
		for i := range s {
			s[i] = sbox[s[i]]
		}
		s = shiftRows(s)
		s = mixColumns(s)
		for i := range s {
			s[i] ^= rks[r][i]
		}
	}
	for i := range s {
		s[i] = sbox[s[i]]
	}
	s = shiftRows(s)
	for i := range s {
		s[i] ^= rks[nr][i]
	}
	return s
}

func seedKey(lo, hi uint64) [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], hi)
	binary.BigEndian.PutUint64(b[8:16], lo)
	return b
}

// cascade evaluates every depth 1..rounds on one padded block; out[r-1]
// receives h_r as (lo, hi) in the aes2r.py lane convention.
func cascade(pt [16]byte, comps []uint64, rounds, nr int, rks *[maxNR + 1][16]byte, out [][2]uint64) {
	lo, hi := comps[0], comps[1]
	for r := 0; r < rounds; r++ {
		if r > 0 {
			lo ^= comps[2*r]
			hi ^= comps[2*r+1]
		}
		keyExpandInto(seedKey(lo, hi), nr, rks)
		st := encRK(pt, rks, nr)
		lo = binary.BigEndian.Uint64(st[8:16])
		hi = binary.BigEndian.Uint64(st[0:8])
		out[r] = [2]uint64{lo, hi}
	}
}

// ---- self-test ------------------------------------------------------------------
func selfTest() error {
	key := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	pt := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	want := [16]byte{0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A}
	var rks [maxNR + 1][16]byte
	keyExpandInto(key, 10, &rks)
	saved := useHW
	defer func() { useHW = saved }()
	useHW = false
	if got := encRK(pt, &rks, 10); got != want {
		return fmt.Errorf("FIPS-197 KAT mismatch (software): %x", got)
	}
	if aes.UseHardwareAcceleration() {
		useHW = true
		if got := encRK(pt, &rks, 10); got != want {
			return fmt.Errorf("FIPS-197 KAT mismatch (AES-NI): %x", got)
		}
		for nr := 2; nr <= maxNR; nr++ {
			for it := 0; it < 8; it++ {
				var k, b [16]byte
				fillBytes(uint64(nr)*0x9E37+uint64(it), k[:])
				fillBytes(uint64(nr)*0x51ED+uint64(it)^0xABCD, b[:])
				keyExpandInto(k, nr, &rks)
				useHW = false
				sw := encRK(b, &rks, nr)
				useHW = true
				if hw := encRK(b, &rks, nr); hw != sw {
					return fmt.Errorf("AES-NI / software round mismatch at nr=%d", nr)
				}
			}
		}
	}
	// aes2r.py sample: _aes2r_128(b"\x01\x02\x03\x04\x05", 0xdead, 0xbeef) at
	// NR = 2 is reproduced by the Python module on import; the lane packing
	// here follows the same big-endian convention and is checked structurally
	// (lo = ct[8:16], hi = ct[0:8]) via the cascade on a fixed vector.
	var out [1][2]uint64
	pt2 := padBlock([]byte{1, 2, 3, 4, 5})
	cascade(pt2, []uint64{0xdead, 0xbeef}, 1, 2, &rks, out[:])
	st := encRK(pt2, &rks, 2)
	if out[0][0] != binary.BigEndian.Uint64(st[8:16]) || out[0][1] != binary.BigEndian.Uint64(st[0:8]) {
		return fmt.Errorf("lane packing mismatch")
	}
	return nil
}

func padBlock(data []byte) [16]byte {
	var b [16]byte
	n := len(data)
	if n > 15 {
		n = 15
	}
	copy(b[:n], data[:n])
	b[15] = 0x80
	return b
}

// ---- deterministic randomness -----------------------------------------------
func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

func fillBytes(seed uint64, b []byte) {
	s := seed
	for i := 0; i < len(b); {
		s = splitmix64(s)
		for j := 0; j < 8 && i < len(b); j++ {
			b[i] = byte(s >> (8 * j))
			i++
		}
	}
}

// ---- accumulators -------------------------------------------------------------
type depthAcc struct {
	Xor    [2]uint64 `json:"xor"`
	First  [2]uint64 `json:"first"`
	DiffOr [2]uint64 `json:"diffor"`
	Seen   bool      `json:"seen"`
}

func (d *depthAcc) add(v [2]uint64) {
	if !d.Seen {
		d.First = v
		d.Seen = true
	}
	d.Xor[0] ^= v[0]
	d.Xor[1] ^= v[1]
	d.DiffOr[0] |= v[0] ^ d.First[0]
	d.DiffOr[1] |= v[1] ^ d.First[1]
}

func (d *depthAcc) merge(o *depthAcc) {
	if !o.Seen {
		return
	}
	if !d.Seen {
		*d = *o
		return
	}
	d.Xor[0] ^= o.Xor[0]
	d.Xor[1] ^= o.Xor[1]
	d.DiffOr[0] |= o.DiffOr[0] | (o.First[0] ^ d.First[0])
	d.DiffOr[1] |= o.DiffOr[1] | (o.First[1] ^ d.First[1])
}

func (d *depthAcc) counts(nbytes int) (active, balanced int) {
	for b := 0; b < nbytes; b++ {
		w, sh := d.Xor[b/8], uint(8*(b%8))
		if (w>>sh)&0xFF == 0 {
			balanced++
		}
		if (d.DiffOr[b/8]>>sh)&0xFF != 0 {
			active++
		}
	}
	return
}

type accum struct {
	D     []depthAcc `json:"d"`
	Texts uint64     `json:"texts"`
}

func newAccum(rounds int) *accum { return &accum{D: make([]depthAcc, rounds)} }

func (a *accum) merge(o *accum) {
	for r := range a.D {
		a.D[r].merge(&o.D[r])
	}
	a.Texts += o.Texts
}

// state is the resume file: the probe parameters it was produced under and
// the per-sub-cube accumulators.
type state struct {
	NR        int               `json:"nr"`
	Rounds    int               `json:"rounds"`
	Log2Texts uint              `json:"log2_texts"`
	Log2Sub   uint              `json:"log2_sub"`
	Active    [maxActive]int    `json:"active"`
	Comps     []uint64          `json:"comps"`
	Fixed     [16]byte          `json:"fixed"`
	Subs      map[string]*accum `json:"subs"`
}

type config struct {
	nr, rounds, workers int
	log2Texts, log2Sub  uint
	active              [maxActive]int
	comps               []uint64
	fixed               [16]byte
}

// runSubCube sweeps sub-cube `sub` and returns its accumulator.
func runSubCube(cfg *config, sub uint64, progress *uint64) *accum {
	acc := newAccum(cfg.rounds)
	var rks [maxNR + 1][16]byte
	out := make([][2]uint64, cfg.rounds)
	pt := cfg.fixed
	size := uint64(1) << cfg.log2Sub
	base := sub << cfg.log2Sub
	for i := uint64(0); i < size; i++ {
		idx := base + i
		for k := 0; k < activeCnt; k++ {
			pt[cfg.active[k]] = byte(idx >> (8 * uint(k)))
		}
		cascade(pt, cfg.comps, cfg.rounds, cfg.nr, &rks, out)
		for r := 0; r < cfg.rounds; r++ {
			acc.D[r].add(out[r])
		}
		if (i+1)&0xFFFF == 0 {
			atomic.AddUint64(progress, 1<<16)
		}
	}
	acc.Texts = size
	return acc
}

func verdict(balanced int, rexp float64) string {
	if float64(balanced) > rexp+1 {
		return "HIGHER-ORDER LEAK"
	}
	return "random (no leak)"
}

func printTable(title string, acc *accum) {
	fmt.Println(title)
	fmt.Printf("%5s %-16s %8s %10s %9s  verdict\n", "depth", "observable", "#active", "#balanced", "rand_exp")
	for r := 0; r < len(acc.D); r++ {
		aLo, bLo := acc.D[r].counts(8)
		aFull, bFull := acc.D[r].counts(16)
		fmt.Printf("%5d %-16s %8d %10d %9.3f  %s\n", r+1, "discard on", aLo, bLo, 8/256.0, verdict(bLo, 8/256.0))
		fmt.Printf("%5d %-16s %8d %10d %9.3f  %s\n", r+1, "discard off", aFull, bFull, 16/256.0, verdict(bFull, 16/256.0))
	}
}

func parseActive(s string) ([maxActive]int, error) {
	var a [maxActive]int
	parts := strings.Split(s, ",")
	if len(parts) != 4 && len(parts) != 5 {
		return a, fmt.Errorf("--active needs 4 or 5 positions, got %d", len(parts))
	}
	activeCnt = len(parts)
	seen := map[int]bool{}
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 || v > 14 || seen[v] {
			return a, fmt.Errorf("--active position %q must be a distinct integer in [0, 14] (byte 15 is the pad)", p)
		}
		seen[v] = true
		a[i] = v
	}
	return a, nil
}

func fmtComps(c []uint64) string {
	parts := make([]string, len(c))
	for i, v := range c {
		parts[i] = fmt.Sprintf("%016x", v)
	}
	return strings.Join(parts, ",")
}

func loadState(path string) (*state, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.Subs == nil {
		st.Subs = map[string]*accum{}
	}
	return &st, nil
}

func saveState(path string, st *state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// report prints the merged table plus, when the sub-cube size is 2^32 or
// smaller, one order-4 verdict per complete 2^32 group (index bits 32..39
// fixed = the fifth active byte's value).
func report(cfg *config, st *state) {
	nSub := uint64(1) << (cfg.log2Texts - cfg.log2Sub)
	global := newAccum(cfg.rounds)
	done := 0
	keys := make([]int, 0, len(st.Subs))
	for k := range st.Subs {
		v, _ := strconv.Atoi(k)
		keys = append(keys, v)
	}
	sort.Ints(keys)
	for _, k := range keys {
		global.merge(st.Subs[strconv.Itoa(k)])
		done++
	}
	if activeCnt == 5 && cfg.log2Sub <= 32 && cfg.log2Texts > 32 {
		per := uint64(1) << (32 - cfg.log2Sub)
		groups := uint64(1) << (cfg.log2Texts - 32)
		fmt.Printf("order-4 verdicts per complete 2^32 group (fifth active byte fixed), lo/full balanced per depth:\n")
		complete := 0
		for g := uint64(0); g < groups; g++ {
			acc := newAccum(cfg.rounds)
			n := 0
			for s := g * per; s < (g+1)*per; s++ {
				if a, ok := st.Subs[strconv.FormatUint(s, 10)]; ok {
					acc.merge(a)
					n++
				}
			}
			if uint64(n) != per {
				continue
			}
			complete++
			var sb strings.Builder
			fmt.Fprintf(&sb, "  group 0x%02x:", g)
			for r := 0; r < cfg.rounds; r++ {
				_, bLo := acc.D[r].counts(8)
				_, bFull := acc.D[r].counts(16)
				fmt.Fprintf(&sb, " r%d=%d/%d", r+1, bLo, bFull)
			}
			fmt.Println(sb.String())
		}
		fmt.Printf("  %d/%d order-4 groups complete\n", complete, groups)
	}
	partial := ""
	if uint64(done) != nSub {
		partial = fmt.Sprintf(" — PARTIAL: %d/%d sub-cubes merged, the order-%d sum is not yet a Λ-set integral", done, nSub, activeCnt)
	}
	printTable(fmt.Sprintf("cumulative over %d/%d sub-cubes (%d texts)%s:", done, nSub, global.Texts, partial), global)
}

func main() {
	initAES()

	rounds := flag.Int("rounds", 4, "cascade depth R (all depths 1..R are reported)")
	nr := flag.Int("nr", 2, "aes2r AES round count (2 = the baseline control primitive)")
	workers := flag.Int("workers", runtime.NumCPU(), "goroutines")
	log2Texts := flag.Uint("log2-texts", 40, "log2 of the text count (40 = order-5 Λ-set; less = smoke only)")
	log2Sub := flag.Uint("log2-sub", 28, "log2 of the sub-cube checkpoint size")
	activeStr := flag.String("active", "1,6,11,12,0", "active data byte positions (5 = order 5, 4 = order 4, e.g. 0,1,2,3 = the idx-only column); byte k carries index bits 8k..8k+7")
	seed := flag.Int64("seed", 0, "deterministic seed for components and the fixed bytes (0 = crypto/rand)")
	resume := flag.String("resume", "", "resume file (JSON): finished sub-cubes are skipped and merged")
	maxSeconds := flag.Float64("max-seconds", 0, "stop handing out new sub-cubes after this budget (0 = no limit)")
	reportOnly := flag.Bool("report-only", false, "print the merged table from --resume without sweeping")
	hw := flag.Bool("hw", aes.UseHardwareAcceleration(), "AES-NI round path")
	heartbeat := flag.Duration("heartbeat", time.Minute, "progress line interval")
	flag.Parse()

	if *rounds < 1 || *rounds > maxRounds {
		fmt.Fprintf(os.Stderr, "--rounds must be in [1, %d]\n", maxRounds)
		os.Exit(2)
	}
	if *nr < 2 || *nr > maxNR {
		fmt.Fprintf(os.Stderr, "--nr must be in [2, %d]\n", maxNR)
		os.Exit(2)
	}
	if *log2Sub < 8 || *log2Sub > *log2Texts || *log2Texts > 40 {
		fmt.Fprintln(os.Stderr, "need 8 <= --log2-sub <= --log2-texts <= 40")
		os.Exit(2)
	}
	if *log2Texts < 40 && *activeStr == "1,6,11,12,0" && *log2Texts == 32 {
		// a 2^32 sweep over the default list is an order-4 diagonal set.
		*activeStr = "1,6,11,12"
	}
	if *workers < 1 {
		*workers = 1
	}
	if *hw && !aes.UseHardwareAcceleration() {
		fmt.Fprintln(os.Stderr, "--hw: no AES-NI on this host; using the software rounds")
		*hw = false
	}
	useHW = *hw
	if err := selfTest(); err != nil {
		fmt.Fprintln(os.Stderr, "self-test FAILED:", err)
		os.Exit(1)
	}
	active, err := parseActive(*activeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	runtime.GOMAXPROCS(*workers)

	cfg := &config{nr: *nr, rounds: *rounds, workers: *workers, log2Texts: *log2Texts, log2Sub: *log2Sub, active: active}

	var st *state
	if *resume != "" {
		if s, err := loadState(*resume); err == nil {
			st = s
			if st.NR != cfg.nr || st.Rounds != cfg.rounds || st.Log2Texts != cfg.log2Texts || st.Log2Sub != cfg.log2Sub || st.Active != cfg.active {
				fmt.Fprintln(os.Stderr, "--resume: file parameters differ from the flags")
				os.Exit(2)
			}
			cfg.comps = st.Comps
			cfg.fixed = st.Fixed
		} else if !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "--resume:", err)
			os.Exit(2)
		}
	}
	if st == nil {
		nComps := 2 * cfg.rounds
		raw := make([]byte, 8*nComps)
		if *seed != 0 {
			fillBytes(uint64(*seed), raw)
			fillBytes(uint64(*seed)^0x5151515151515151, cfg.fixed[:15])
		} else {
			if _, err := rand.Read(raw); err != nil {
				panic(err)
			}
			if _, err := rand.Read(cfg.fixed[:15]); err != nil {
				panic(err)
			}
		}
		cfg.fixed[15] = 0x80
		cfg.comps = make([]uint64, nComps)
		for i := range cfg.comps {
			cfg.comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		st = &state{NR: cfg.nr, Rounds: cfg.rounds, Log2Texts: cfg.log2Texts, Log2Sub: cfg.log2Sub,
			Active: cfg.active, Comps: cfg.comps, Fixed: cfg.fixed, Subs: map[string]*accum{}}
	}

	nSub := uint64(1) << (cfg.log2Texts - cfg.log2Sub)
	total := uint64(1) << cfg.log2Texts
	fmt.Printf("order-%d integral through ChainHash<aes2r NR=%d>: 2^%d texts, active bytes %v, depths 1..%d, %d workers, 2^%d sub-cubes of 2^%d texts, aes-ni=%v\n",
		activeCnt, cfg.nr, cfg.log2Texts, cfg.active[:activeCnt], cfg.rounds, cfg.workers, cfg.log2Texts-cfg.log2Sub, cfg.log2Sub, useHW)
	fmt.Printf("self-test OK (FIPS-197 KAT software%s + lane packing)\n", map[bool]string{true: " + AES-NI parity", false: ""}[aes.UseHardwareAcceleration()])
	fmt.Printf("fixed_bytes=%x comps=%s\n", cfg.fixed[:], fmtComps(cfg.comps))
	if cfg.log2Texts < uint(8*activeCnt) {
		fmt.Printf("NOTE: smoke configuration — the sums below are not an order-%d Λ-set integral\n", activeCnt)
	}
	if *reportOnly {
		report(cfg, st)
		return
	}
	fmt.Printf("resume: %d/%d sub-cubes already done\n", len(st.Subs), nSub)

	t0 := time.Now()
	var progress, next, done uint64
	var mu sync.Mutex
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
				fmt.Printf("  ... heartbeat: %d texts this run (%.1f M texts/s), %.0f s, %d/%d sub-cubes done in total\n",
					n, float64(n)/el/1e6, el, uint64(len(st.Subs)), nSub)
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < cfg.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if *maxSeconds > 0 && time.Since(t0).Seconds() > *maxSeconds {
					return
				}
				sub := atomic.AddUint64(&next, 1) - 1
				if sub >= nSub {
					return
				}
				key := strconv.FormatUint(sub, 10)
				mu.Lock()
				_, have := st.Subs[key]
				mu.Unlock()
				if have {
					continue
				}
				acc := runSubCube(cfg, sub, &progress)
				mu.Lock()
				st.Subs[key] = acc
				k := atomic.AddUint64(&done, 1)
				if *resume != "" && (k%8 == 0) {
					if err := saveState(*resume, st); err != nil {
						fmt.Fprintln(os.Stderr, "resume save:", err)
					}
				}
				var sb strings.Builder
				fmt.Fprintf(&sb, "[ckpt %d/%d] sub-cube %d:", len(st.Subs), nSub, sub)
				for r := 0; r < cfg.rounds; r++ {
					_, bLo := acc.D[r].counts(8)
					_, bFull := acc.D[r].counts(16)
					fmt.Fprintf(&sb, " r%d=%d/%d", r+1, bLo, bFull)
				}
				el := time.Since(t0).Seconds()
				rate := float64(atomic.LoadUint64(&progress)) / el
				remaining := float64((nSub-uint64(len(st.Subs)))*(uint64(1)<<cfg.log2Sub)) / rate
				fmt.Fprintf(&sb, " | %.0f s, %.1f M texts/s, ETA %.0f s", el, rate/1e6, remaining)
				fmt.Println(sb.String())
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(stop)
	hb.Wait()
	if *resume != "" {
		if err := saveState(*resume, st); err != nil {
			fmt.Fprintln(os.Stderr, "resume save:", err)
		}
	}
	el := time.Since(t0).Seconds()
	n := atomic.LoadUint64(&progress)
	_ = total
	fmt.Printf("this run: %d sub-cubes, %d texts, %.0f s, %.1f M texts/s over %d depths (projected 2^40 at this rate: %.2f h)\n",
		done, n, el, float64(n)/el/1e6, cfg.rounds, float64(uint64(1)<<40)/(float64(n)/el)/3600)
	report(cfg, st)
}
