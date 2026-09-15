// square5_go — Go 5-round Square on the aes2r control primitive, the feasible
// counterpart of the pure-Python higher_round_square_aes2r.py NR=5 cell (2^32
// texts is ~36 h in Python, ~seconds here).
//
// Usage:
//
//	go run scripts/redteam/itb/theory/aes2r/square5_go/main.go [flags]
//
// aes2r is raw standard AES over one padded block with a secret key = seed
// (chainhashes/aes2r.py). Unlike the AES-ITB-128 sponge (public round constants,
// additive seed, MixColumns on every round), aes2r's final round has NO
// MixColumns and its rounds use secret expanded round keys, so the recovery is
// the textbook last-round-key Square: over a set balanced before the last round
// the peel is
//
//	W[p] = ct[p],   Sum_texts InvSubBytes(ct[p] ^ k_last[p]) == 0,
//
// with no InvMixColumns step. At NR = 5 the state is balanced after 4 rounds
// only for an order-4 (2^32) diagonal set (FKLSSW higher-order integral), the
// aes2r analogue of the AES-ITB-128 T = 5 shape-36 cell. The last-round key is
// inverted through the AES-128 key schedule to the master key = seed and
// verified on fresh chosen texts; the ground-truth comparison is a terminal
// report only, never consulted by the engine (attacker-realism discipline).
//
// The diagonal is {1, 6, 11, 12} (maps to output column 3 under the shared
// ShiftRows, avoiding plaintext byte 15 which aes2r's pad fixes to 0x80).
//
// Raw NR = 5 (rounds = 1, fixed key) is the 2^32 recovery cell. ChainHash r = 2
// (rounds = 2, per-text keys) is the dissolution control: the last call's key is
// data-dependent, so no fixed last-round key verifies — mirrors keyrecover_r2.py.
//
// Attacker-model flags. The defaults are the lab grants of the cell above:
// --observable full (the whole 16-byte ct) and --nonce chosen (any data byte
// may be active, so the {1, 6, 11, 12} diagonal spans bytes an ITB attacker
// never picks). --observable lo restricts the peel to ct[8:16] — the lo lane
// of chainhashes/aes2r.py (the last 8 big-endian bytes = state columns 2, 3),
// the only half ITB's encoder would consume; the last-round-key bytes at
// positions 0..7 are then unconstrained and the master key sits behind a 2^64
// enumeration of that hidden half. --nonce idx-only confines the active set to
// data bytes 0..3 (the LE32(idx) convention: aes2r has no shipping shape, so
// the idx / nonce / pad byte mapping is a convention — bytes 0..3 counter,
// 4..14 nonce, 15 pad) with the other bytes a random constant per set that the
// attacker sees but did not choose; the four counter bytes form one state
// column, so an idx-only order-4 set carries the 3-round property only.
// --model realistic is the shorthand for both. In lo mode the lab-grant cell
// is run on the same seeds in the same invocation as the positive control.
//
// --hw routes the AES rounds through go-aes RoundHW / FinalRoundHW (AES-NI;
// pinned against the software rounds by the self-test); it changes throughput
// only.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aes "github.com/jedisct1/go-aes"
)

const lanes = 4

// maxNR bounds the round-key array of the allocation-free oracle path.
const maxNR = 10

// ---- AES tables (FIPS-197, column-major state s[row + 4*col]) ----------------
var (
	sbox  [256]byte
	isbox [256]byte
	mul   [16][256]byte
	rcon  = [11]byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}
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
	for x := 0; x < 256; x++ {
		isbox[sbox[x]] = byte(x)
	}
	for m := 0; m < 16; m++ {
		for x := 0; x < 256; x++ {
			mul[m][x] = gmul(byte(m), byte(x))
		}
	}
}

func subBytes(s *[16]byte) {
	for i := range s {
		s[i] = sbox[s[i]]
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

// keyExpand returns nr+1 round keys of 16 bytes each (AES-128 schedule).
func keyExpand(key [16]byte, nr int) [][16]byte {
	words := make([][4]byte, 4*(nr+1))
	for i := 0; i < 4; i++ {
		words[i] = [4]byte{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]}
	}
	for i := 4; i < len(words); i++ {
		t := words[i-1]
		if i%4 == 0 {
			t = [4]byte{t[1], t[2], t[3], t[0]}
			for j := range t {
				t[j] = sbox[t[j]]
			}
			t[0] ^= rcon[i/4]
		}
		for j := 0; j < 4; j++ {
			words[i][j] = words[i-4][j] ^ t[j]
		}
	}
	rks := make([][16]byte, nr+1)
	for k := 0; k <= nr; k++ {
		for c := 0; c < 4; c++ {
			copy(rks[k][4*c:4*c+4], words[4*k+c][:])
		}
	}
	return rks
}

// invKeySchedule inverts the AES-128 schedule from the round-nr key to the
// master key (round-0 key).
func invKeySchedule(kLast [16]byte, nr int) [16]byte {
	total := 4 * (nr + 1)
	w := make([][4]byte, total)
	for c := 0; c < 4; c++ {
		w[4*nr+c] = [4]byte{kLast[4*c], kLast[4*c+1], kLast[4*c+2], kLast[4*c+3]}
	}
	for i := total - 1; i >= 4; i-- {
		if i%4 == 0 {
			t := [4]byte{w[i-1][1], w[i-1][2], w[i-1][3], w[i-1][0]}
			for j := range t {
				t[j] = sbox[t[j]]
			}
			t[0] ^= rcon[i/4]
			for j := 0; j < 4; j++ {
				w[i-4][j] = w[i][j] ^ t[j]
			}
		} else {
			for j := 0; j < 4; j++ {
				w[i-4][j] = w[i][j] ^ w[i-1][j]
			}
		}
	}
	var master [16]byte
	for c := 0; c < 4; c++ {
		copy(master[4*c:4*c+4], w[c][:])
	}
	return master
}

// encRK runs nr AES rounds with pre-expanded round keys; final round has no
// MixColumns (standard AES).
func encRK(block [16]byte, rks [][16]byte, nr int) [16]byte {
	s := block
	for i := range s {
		s[i] ^= rks[0][i]
	}
	for r := 1; r < nr; r++ {
		subBytes(&s)
		s = shiftRows(s)
		s = mixColumns(s)
		for i := range s {
			s[i] ^= rks[r][i]
		}
	}
	subBytes(&s)
	s = shiftRows(s)
	for i := range s {
		s[i] ^= rks[nr][i]
	}
	return s
}

func encKey(block, key [16]byte, nr int) [16]byte {
	return encRK(block, keyExpand(key, nr), nr)
}

// useHW routes encRKFast through the go-aes AES-NI round primitives. Set once
// in main from --hw after the self-test pins HW == SW.
var useHW bool

// keyExpandInto is the allocation-free AES-128 key schedule (nr+1 round keys
// into a fixed array) used by the per-text oracle path, where at r >= 2 every
// cascade call carries a fresh data-dependent key.
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

// encRKFast is encRK over a fixed round-key array, with the AES-NI round path
// when useHW is set (RoundHW = SubBytes, ShiftRows, MixColumns, AddRoundKey;
// FinalRoundHW omits MixColumns — the standard AES round semantics encRK
// implements in software).
func encRKFast(block [16]byte, rks *[maxNR + 1][16]byte, nr int) [16]byte {
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
		subBytes(&s)
		s = shiftRows(s)
		s = mixColumns(s)
		for i := range s {
			s[i] ^= rks[r][i]
		}
	}
	subBytes(&s)
	s = shiftRows(s)
	for i := range s {
		s[i] ^= rks[nr][i]
	}
	return s
}

// padBlock is aes2r's injective one-block pad: data[:15] || 0x80 (byte 15 fixed).
func padBlock(data []byte) [16]byte {
	var b [16]byte
	n := len(data)
	if n > 15 {
		n = 15
	}
	copy(b[:n], data[:n])
	b[15] = 0x80
	for i := n; i < 15; i++ {
		b[i] = 0
	}
	return b
}

func seedKey(lo, hi uint64) [16]byte {
	// key = seed_hi<<64 | seed_lo, big-endian 16 bytes (matches aes2r.py).
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], hi)
	binary.BigEndian.PutUint64(b[8:16], lo)
	return b
}

// ---- one-round pin self-test ------------------------------------------------
func oneRound(s [16]byte) [16]byte {
	subBytes(&s)
	s = shiftRows(s)
	return mixColumns(s)
}

// selfTest pins the AES core against the FIPS-197 10-round KAT, the key-schedule
// inversion round-trip, and the {1,6,11,12} diagonal -> column 3 property.
func selfTest() error {
	key := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	pt := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	ct := encKey(pt, key, 10)
	want := [16]byte{0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A}
	if ct != want {
		return fmt.Errorf("FIPS-197 KAT mismatch: %x", ct)
	}
	for nr := 3; nr <= 6; nr++ {
		rks := keyExpand(key, nr)
		if invKeySchedule(rks[nr], nr) != key {
			return fmt.Errorf("key-schedule inversion mismatch at nr=%d", nr)
		}
	}
	// keyExpandInto == keyExpand, and encRKFast (software and, when the host
	// has AES-NI, hardware) == encRK on random blocks / keys at every nr.
	savedHW := useHW
	defer func() { useHW = savedHW }()
	for nr := 2; nr <= maxNR; nr++ {
		for it := 0; it < 16; it++ {
			var k, b [16]byte
			fillBytes(uint64(nr)*0x9E37+uint64(it), k[:])
			fillBytes(uint64(nr)*0x51ED+uint64(it)^0xABCD, b[:])
			ref := encRK(b, keyExpand(k, nr), nr)
			var rks [maxNR + 1][16]byte
			keyExpandInto(k, nr, &rks)
			for r := 0; r <= nr; r++ {
				if rks[r] != keyExpand(k, nr)[r] {
					return fmt.Errorf("keyExpandInto mismatch at nr=%d round %d", nr, r)
				}
			}
			useHW = false
			if got := encRKFast(b, &rks, nr); got != ref {
				return fmt.Errorf("encRKFast (software) mismatch at nr=%d", nr)
			}
			if aes.UseHardwareAcceleration() {
				useHW = true
				if got := encRKFast(b, &rks, nr); got != ref {
					return fmt.Errorf("encRKFast (AES-NI) mismatch at nr=%d", nr)
				}
			}
		}
	}
	for _, p := range []int{1, 6, 11, 12} {
		var base [16]byte
		for i := range base {
			base[i] = byte(0x30 + i + p)
		}
		ref := oneRound(base)
		var varying [16]bool
		for v := 1; v < 256; v++ {
			st := base
			st[p] ^= byte(v)
			o := oneRound(st)
			for i := 0; i < 16; i++ {
				if o[i] != ref[i] {
					varying[i] = true
				}
			}
		}
		for i := 0; i < 16; i++ {
			if varying[i] != (i >= 12) {
				return fmt.Errorf("diagonal pin failed: input byte %d varies output byte %d (want column 3 only)", p, i)
			}
		}
	}
	return nil
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

func fillRandom(useSeed bool, seed uint64, b []byte) {
	if useSeed {
		fillBytes(seed, b)
		return
	}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}

// ---- oracle -----------------------------------------------------------------
// oracleCT returns the 16-byte ct state for one text. rounds == 1 is raw aes2r
// (fixed key rks0); rounds >= 2 is ChainHash with XOR feed-forward (per-text
// keys), used as the dissolution control.
func oracleCT(data []byte, comps []uint64, rounds, nr int, rks0 [][16]byte) [16]byte {
	pt := padBlock(data)
	var rks [maxNR + 1][16]byte
	if rounds == 1 {
		for k := 0; k <= nr; k++ {
			rks[k] = rks0[k]
		}
		return encRKFast(pt, &rks, nr)
	}
	lo, hi := comps[0], comps[1]
	keyExpandInto(seedKey(lo, hi), nr, &rks)
	st := encRKFast(pt, &rks, nr)
	lo = binary.BigEndian.Uint64(st[8:16])
	hi = binary.BigEndian.Uint64(st[0:8])
	for i := 2; i < 2*rounds; i += 2 {
		kLo := comps[i] ^ lo
		kHi := comps[i+1] ^ hi
		keyExpandInto(seedKey(kLo, kHi), nr, &rks)
		st = encRKFast(pt, &rks, nr)
		lo = binary.BigEndian.Uint64(st[8:16])
		hi = binary.BigEndian.Uint64(st[0:8])
	}
	return st
}

// ---- global-parity higher-order integral (last-round-key peel) --------------
type mask [16][256]bool

func (cfg *config) globalParityMask(comps []uint64, rks0 [][16]byte, setSeed uint64, hashNS *int64) *mask {
	order := cfg.order
	lowPos := cfg.active[0]
	high := cfg.active[1:order]
	outer := uint64(1) << (8 * uint(order-1))

	var base [16]byte
	fillRandom(cfg.useSeed, setSeed, base[:])
	base[15] = 0x80

	type parityTab [16][256]bool
	nw := cfg.workers
	if nw < 1 {
		nw = 1
	}
	locals := make([]parityTab, nw)

	var next uint64
	var wg sync.WaitGroup
	th := time.Now()
	for w := 0; w < nw; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			buf := base
			par := &locals[id]
			for {
				o := atomic.AddUint64(&next, 1) - 1
				if o >= outer {
					break
				}
				for k := 0; k < len(high); k++ {
					buf[high[k]] = byte(o >> (8 * uint(k)))
				}
				for v := 0; v < 256; v++ {
					buf[lowPos] = byte(v)
					ct := oracleCT(buf[:15], comps, cfg.rounds, cfg.nr, rks0)
					for p := 0; p < 16; p++ {
						par[p][ct[p]] = !par[p][ct[p]]
					}
				}
			}
		}(w)
	}
	wg.Wait()
	atomic.AddInt64(hashNS, time.Since(th).Nanoseconds())

	var parity [16][256]bool
	for w := 0; w < nw; w++ {
		for p := 0; p < 16; p++ {
			for v := 0; v < 256; v++ {
				if locals[w][p][v] {
					parity[p][v] = !parity[p][v]
				}
			}
		}
	}

	m := &mask{}
	for p := 0; p < 16; p++ {
		for g := 0; g < 256; g++ {
			var x byte
			for v := 0; v < 256; v++ {
				if parity[p][v] {
					x ^= isbox[byte(v)^byte(g)]
				}
			}
			m[p][g] = x == 0
		}
	}
	if cfg.observable == "lo" {
		// Only ct[8:16] (state columns 2, 3) is visible: the last-round-key
		// bytes at positions 0..7 stay unconstrained.
		for p := 0; p < 8; p++ {
			for g := 0; g < 256; g++ {
				m[p][g] = true
			}
		}
	}
	return m
}

// visiblePositions returns the ct positions the observable exposes.
func (cfg *config) visiblePositions() (lo, hi int) {
	if cfg.observable == "lo" {
		return 8, 15
	}
	return 0, 15
}

// survivorSummary reports, over the visible positions, how many carry exactly
// one surviving last-round-key byte and how many carry none.
func (cfg *config) survivorSummary(m *mask) (unique, empty, visible int) {
	lo, hi := cfg.visiblePositions()
	for p := lo; p <= hi; p++ {
		n := 0
		for g := 0; g < 256; g++ {
			if m[p][g] {
				n++
			}
		}
		visible++
		switch n {
		case 0:
			empty++
		case 1:
			unique++
		}
	}
	return
}

// finishFromMask enumerates the last-round-key survivor product, inverts each
// candidate to a master key and verifies it on four fresh chosen texts. Returns
// the verified master (raw only; ChainHash r >= 2 has no single master so this
// correctly fails) and whether it verified.
func (cfg *config) finishFromMask(m *mask, comps []uint64, rks0 [][16]byte, trialSeed uint64) ([16]byte, bool) {
	const productCap = 1 << 20
	var cand [16][]byte
	product := uint64(1)
	for p := 0; p < 16; p++ {
		for g := 0; g < 256; g++ {
			if m[p][g] {
				cand[p] = append(cand[p], byte(g))
			}
		}
		if len(cand[p]) == 0 {
			return [16]byte{}, false
		}
		product *= uint64(len(cand[p]))
		if product > productCap {
			return [16]byte{}, false
		}
	}
	var vd [4][16]byte
	for i := 0; i < 4; i++ {
		fillRandom(cfg.useSeed, trialSeed^splitmix64(uint64(0xF00D+i)), vd[i][:15])
		vd[i][15] = 0x80
	}
	var kLast [16]byte
	var idx [16]int
	for {
		for p := 0; p < 16; p++ {
			kLast[p] = cand[p][idx[p]]
		}
		master := invKeySchedule(kLast, cfg.nr)
		mrks := keyExpand(master, cfg.nr)
		ok := 0
		for i := 0; i < 4; i++ {
			if encRK(vd[i], mrks, cfg.nr) == oracleCT(vd[i][:15], comps, cfg.rounds, cfg.nr, rks0) {
				ok++
			}
		}
		if ok == 4 {
			return master, true
		}
		q := 0
		for ; q < 16; q++ {
			idx[q]++
			if idx[q] < len(cand[q]) {
				break
			}
			idx[q] = 0
		}
		if q == 16 {
			break
		}
	}
	return [16]byte{}, false
}

// ---- config + driver --------------------------------------------------------
type config struct {
	order, rounds, nr, workers, trials int
	useSeed                            bool
	seed                               uint64
	active                             []int
	observable, nonceModel             string
}

// isFlagSet reports whether a flag was given explicitly on the command line.
func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func parseActive(s string, n int) ([]int, error) {
	var a []int
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 || v > 14 || seen[v] {
			return nil, fmt.Errorf("--active position %q must be a distinct integer in [0, 14] (byte 15 is the pad)", p)
		}
		seen[v] = true
		a = append(a, v)
	}
	if len(a) < n {
		return nil, fmt.Errorf("--active needs at least --order=%d positions, got %d", n, len(a))
	}
	return a[:n], nil
}

func main() {
	initAES()
	if err := selfTest(); err != nil {
		fmt.Fprintln(os.Stderr, "self-test FAILED:", err)
		os.Exit(1)
	}

	order := flag.Int("order", 4, "Lambda-set order (4 = 2^32 diagonal set for NR=5)")
	rounds := flag.Int("rounds", 1, "ChainHash depth (1 = raw aes2r; >=2 = feed-forward control)")
	nr := flag.Int("nr", 5, "aes2r AES round count")
	workers := flag.Int("workers", 16, "goroutines")
	trials := flag.Int("trials", 1, "trials with fresh key / components")
	seed := flag.Int64("seed", 0, "deterministic seed (0 = crypto/rand)")
	activeStr := flag.String("active", "1,6,11,12", "active data byte positions, low byte first (default: the {1,6,11,12} diagonal; idx-only: 0,1,2,3)")
	observable := flag.String("observable", "full", "attacker observable: full (16-byte ct, lab grant) | lo (ct[8:16] = the aes2r lo lane, state columns 2, 3)")
	nonceModel := flag.String("nonce", "chosen", "who picks the non-active data bytes: chosen (lab grant) | idx-only (active set confined to bytes 0..3, the rest a random constant per set)")
	model := flag.String("model", "", "shorthand: realistic = --observable lo --nonce idx-only; lab = --observable full --nonce chosen")
	hw := flag.Bool("hw", aes.UseHardwareAcceleration(), "AES-NI round path (go-aes RoundHW / FinalRoundHW); throughput only")
	labControl := flag.Bool("lab-control", true, "in lo / idx-only mode also run the lab-grant cell on the same seeds as the positive control")
	flag.Parse()

	switch *model {
	case "":
	case "realistic":
		if !isFlagSet("observable") {
			*observable = "lo"
		}
		if !isFlagSet("nonce") {
			*nonceModel = "idx-only"
		}
	case "lab":
	default:
		fmt.Fprintln(os.Stderr, "--model must be realistic | lab")
		os.Exit(2)
	}
	if *observable != "full" && *observable != "lo" {
		fmt.Fprintln(os.Stderr, "--observable must be full | lo")
		os.Exit(2)
	}
	if *nonceModel != "chosen" && *nonceModel != "idx-only" {
		fmt.Fprintln(os.Stderr, "--nonce must be chosen | idx-only")
		os.Exit(2)
	}
	if *order < 1 || *order > 4 {
		fmt.Fprintln(os.Stderr, "--order must be in [1, 4]")
		os.Exit(2)
	}
	if *nr < 2 || *nr > maxNR {
		fmt.Fprintf(os.Stderr, "--nr must be in [2, %d]\n", maxNR)
		os.Exit(2)
	}
	if *nonceModel == "idx-only" && !isFlagSet("active") {
		*activeStr = "0,1,2,3"
	}
	active, err := parseActive(*activeStr, *order)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *nonceModel == "idx-only" {
		for _, p := range active {
			if p > 3 {
				fmt.Fprintf(os.Stderr, "--nonce idx-only: active position %d is not a counter byte (allowed 0..3)\n", p)
				os.Exit(2)
			}
		}
	}
	if *hw && !aes.UseHardwareAcceleration() {
		fmt.Fprintln(os.Stderr, "--hw: no AES-NI on this host; using the software rounds")
		*hw = false
	}
	useHW = *hw
	if *workers < 1 {
		*workers = 1
	}
	runtime.GOMAXPROCS(*workers)

	cfg := &config{
		order: *order, rounds: *rounds, nr: *nr, workers: *workers, trials: *trials,
		useSeed: *seed != 0, seed: uint64(*seed), active: active,
		observable: *observable, nonceModel: *nonceModel,
	}

	fmt.Printf("aes2r %d-round Square (last-round-key peel) — order=%d (2^%d texts/set), rounds=%d, nr=%d, trials=%d, workers=%d\n",
		cfg.nr, cfg.order, 8*cfg.order, cfg.rounds, cfg.nr, cfg.trials, cfg.workers)
	fmt.Printf("  self-test OK (FIPS-197 10-round KAT + key-schedule inversion + {1,6,11,12} diagonal pin + keyExpandInto / encRKFast parity)\n")
	fmt.Printf("  attacker model: observable=%s, nonce=%s, active=%v, aes-ni=%v\n", cfg.observable, cfg.nonceModel, cfg.active, useHW)

	cfg.runTrials()
	if *labControl && (cfg.observable == "lo" || cfg.nonceModel == "idx-only") {
		lab := *cfg
		lab.observable, lab.nonceModel = "full", "chosen"
		lab.active = []int{1, 6, 11, 12}[:cfg.order]
		fmt.Printf("\n  lab control (same binary, same seeds, observable=full, nonce=chosen, active=%v):\n", lab.active)
		lab.runTrials()
	}
}

// runTrials runs cfg.trials trials of the last-round-key Square on the
// configured observable / active set and prints the verdict. The ground-truth
// comparison is a terminal report only.
func (cfg *config) runTrials() {
	setTexts := uint64(1) << (8 * uint(cfg.order))
	var hashNS int64
	hits := 0
	var consumed uint64
	t0 := time.Now()
	for tr := 0; tr < cfg.trials; tr++ {
		trialSeed := cfg.seed ^ splitmix64(uint64(tr)*0x1234567)
		comps := make([]uint64, 2*cfg.rounds)
		raw := make([]byte, 8*len(comps))
		fillRandom(cfg.useSeed, trialSeed, raw)
		for i := range comps {
			comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		trueMaster := seedKey(comps[0], comps[1])
		rks0 := keyExpand(trueMaster, cfg.nr)

		acc := &mask{}
		for p := 0; p < 16; p++ {
			for g := 0; g < 256; g++ {
				acc[p][g] = true
			}
		}
		var found bool
		var master [16]byte
		for s := 0; s < 3; s++ {
			sm := cfg.globalParityMask(comps, rks0, trialSeed^splitmix64(uint64(s)*0x2545F4914F6CDD1D), &hashNS)
			for p := 0; p < 16; p++ {
				for g := 0; g < 256; g++ {
					acc[p][g] = acc[p][g] && sm[p][g]
				}
			}
			consumed += setTexts
			if m, ok := cfg.finishFromMask(acc, comps, rks0, trialSeed); ok {
				master, found = m, true
				break
			}
			empty := false
			for p := 0; p < 16 && !empty; p++ {
				n := 0
				for g := 0; g < 256; g++ {
					if acc[p][g] {
						n++
					}
				}
				if n == 0 {
					empty = true
				}
			}
			if empty {
				break
			}
		}
		gt := found && cfg.rounds == 1 && master == trueMaster
		if found {
			hits++
		}
		unique, empty, visible := cfg.survivorSummary(acc)
		fmt.Printf("  trial %d: %s  (ground truth %v; last-round-key survivors over the %d visible positions: unique %d, empty %d)\n", tr,
			map[bool]string{true: "master VERIFIED", false: "no verifying master (fails)"}[found], gt, visible, unique, empty)
	}
	wall := time.Since(t0)

	tag := "fails"
	if cfg.rounds == 1 && hits >= cfg.trials {
		tag = "RECOVERS master key (= seed)"
	}
	fmt.Printf("  result: %d/%d verified  ->  %s\n", hits, cfg.trials, tag)
	if cfg.observable == "lo" {
		fmt.Printf("  lo lane: positions 0..7 of the last round key are hidden — even a fully resolved visible half leaves the master key behind a 2^64 enumeration (structural, not run)\n")
	}
	fmt.Printf("  chosen texts consumed: %d  wall %.2fs (hash %.2fs)\n", consumed, wall.Seconds(), float64(hashNS)/1e9)
}
