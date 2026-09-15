// keyrecover_kbyte_go — Go port of the classical 4-round Square kappa-byte
// key-recovery engine through ChainHash<AES-ITB-128>, generalised to
// order-N Lambda-sets and every cascade depth.
//
// Usage:
//
//	go run scripts/redteam/itb/theory/aesitb128/keyrecover_kbyte_go/main.go [flags]
//
// Pure Go, no cgo. The oracle drives the ChainHash cascade one round at a
// time through the shipped 4-lane batched arm
// (internal/aesitbasm.AESITB128ChainAbsorb{13,20,36,68}x4 — the code the
// registry's aesitb128 BatchHash arm dispatches to), so the throughput
// matches the shipped kernel rather than a numpy mirror.
//
// The classical engine is the discard-off key recovery of
// scripts/redteam/itb/theory/aesitb128/keyrecover_r2_20byte.py (square_classic):
// at the shipped 20-byte per-pixel shape one primitive call is T = 4 AES
// rounds, so at cascade depth r = 2 the peeled last-call seed is
//
//	Y = k2 XOR h1(d),   h1(d) = P(K1 XOR pad(d)),   P = 4 public AES rounds
//	W = InvMixColumns(Y XOR RC[1]),   W[p] = kappa[p] XOR ShiftRows(SubBytes(X'))[p]
//
// where X' is the state entering P's last round (balanced over a Lambda-set),
// k2 = comps[2:4] is the constant last-call component pair, and
// kappa = InvMixColumns(k2). Per state byte a 2^8 guess with the balance test
// XOR_texts InvSubBytes(W[p] XOR g) == 0 singles out kappa[p]; k2 = MixColumns(kappa),
// h1(d0) = Y[0] XOR k2, and one public P^-1 (invertGeneric) on h1 exposes the
// first-call seed block. Both component pairs of a two-call cascade are then
// returned and verified on fresh chosen texts; the ground-truth comparison
// against the true components is a terminal-stage report only, never consulted
// by the engine (attacker-realism discipline).
//
// The peeled value Y is not recomputed by inverse AES per text: it is exactly
// the seed block the cascade feeds into its last call
// (comps[2r-2] XOR lo(h_{r-1}), comps[2r-1] XOR hi(h_{r-1})), which a real
// attacker obtains by the public P^-1 and which this driver captures for free
// from the cascade recurrence (the order5_chainhash_go identity). invertGeneric
// is still ported and pinned by the self-test, and is used by the finish step.
//
// Discrimination.  A wrong guess passes the balance test with probability
// ~2^-8 per byte regardless of Lambda-set size, so one large order-N set still
// leaves ~2 candidates per byte. Uniqueness comes from independent order-1
// sub-blocks (256 texts varying the lowest active byte, the rest fixed) whose
// survivor masks are ANDed: the mask converges to a unique kappa in a few
// sub-blocks at r = 2 and empties in a few sub-blocks at r >= 3. Because the
// kappa engine's order is fixed by T (T = 4 at the 20-byte shape needs only
// order 1), raising --order above 1 at data-len 20 multiplies redundant
// sub-blocks and adds no key-recovery information — with --early-exit (default
// on) every cell converges in the same handful of sub-blocks. A full
// early-exit-off sweep of an order-N set only confirms the mask stays empty at
// r >= 3 at scale (a negative result). The order that is load-bearing for key
// recovery grows with the per-pixel shape's round count, not the cascade
// depth: data-len 36 (T = 5) is the 5-round Square regime that needs an
// order-4 (2^32) diagonal set, the cell keyrecover_r2_20byte.py names as not
// run.
//
// pair-constancy is the T-1 == 2 engine ported verbatim from
// keyrecover_r2_20byte.py (square_pairconst); it fails at the 20-byte shape and
// backs the negative-control row.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
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
	lanes     = 4
	maxRounds = 64
	maxLen    = 68 // largest shipped per-pixel shape
)

// fixedKey is the aesitb/ reference key (bytes 0x00, 0x11, ... 0xFF), the
// Python mirror's FIXED_KEY. Treated as attacker-known.
var fixedKey = [16]byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
}

// NUMS round constants (aesitb.go aesITBRoundConstants). RC entries are raw
// 16-byte blocks, not little-endian words.
var rc = [8][16]byte{
	{0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A},
	{0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C, 0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19},
	{0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xBB, 0x67, 0xAE, 0x85, 0x84, 0xCA, 0xA7, 0x3B},
	{0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B, 0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1},
	{0x51, 0x0E, 0x52, 0x7F, 0xAD, 0xE6, 0x82, 0xD1, 0x9B, 0x05, 0x68, 0x8C, 0x2B, 0x3E, 0x6C, 0x1F},
	{0x1F, 0x83, 0xD9, 0xAB, 0xFB, 0x41, 0xBD, 0x6B, 0x5B, 0xE0, 0xCD, 0x19, 0x13, 0x7E, 0x21, 0x79},
	{0xCB, 0xBB, 0x9D, 0x5D, 0xC1, 0x05, 0x9E, 0xD8, 0x62, 0x9A, 0x29, 0x2A, 0x36, 0x7C, 0xD5, 0x07},
	{0x91, 0x59, 0x01, 0x5A, 0x30, 0x70, 0xDD, 0x17, 0x15, 0x2F, 0xEC, 0xD8, 0xF7, 0x0E, 0x59, 0x39},
}

// ---- AES building blocks (FIPS-197, column-major state s[4*col+row]) --------
var (
	sbox  [256]byte
	isbox [256]byte
	mul   [16][256]byte // mul[m][x] = GF(2^8) multiply x by m, for m in 0..15
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
	// multiplicative inverse in GF(2^8), then the AES affine transform.
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

func invMixColumns(s [16]byte) [16]byte {
	var o [16]byte
	for c := 0; c < 4; c++ {
		a0, a1, a2, a3 := s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
		o[4*c] = mul[14][a0] ^ mul[11][a1] ^ mul[13][a2] ^ mul[9][a3]
		o[4*c+1] = mul[9][a0] ^ mul[14][a1] ^ mul[11][a2] ^ mul[13][a3]
		o[4*c+2] = mul[13][a0] ^ mul[9][a1] ^ mul[14][a2] ^ mul[11][a3]
		o[4*c+3] = mul[11][a0] ^ mul[13][a1] ^ mul[9][a2] ^ mul[14][a3]
	}
	return o
}

func invShiftRows(s [16]byte) [16]byte {
	var o [16]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			o[r+4*c] = s[r+4*(((c-r)%4+4)%4)]
		}
	}
	return o
}

func invRound(s, rcv [16]byte) [16]byte {
	for i := range s {
		s[i] ^= rcv[i]
	}
	s = invMixColumns(s)
	s = invShiftRows(s)
	for i := range s {
		s[i] = isbox[s[i]]
	}
	return s
}

func pkcs7(data []byte) []byte {
	pad := 16 - len(data)%16
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// invertGeneric recovers (seed0, seed1) from one (data, full 16-byte output)
// pair: it walks the two finaliser rounds and every absorbed block backwards,
// the only unknown falling out as the initial seed block XOR fixedKey.
func invertGeneric(data []byte, out16 [16]byte) (uint64, uint64) {
	state := out16
	state = invRound(state, rc[1])
	state = invRound(state, rc[0])
	padded := pkcs7(data)
	nblk := len(padded) / 16
	for i := nblk - 1; i >= 0; i-- {
		state = invRound(state, rc[i%8])
		for j := 0; j < 16; j++ {
			state[j] ^= padded[16*i+j]
		}
	}
	for j := 0; j < 16; j++ {
		state[j] ^= fixedKey[j]
	}
	return binary.LittleEndian.Uint64(state[0:8]), binary.LittleEndian.Uint64(state[8:16])
}

func seedBytes(lo, hi uint64) [16]byte {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], lo)
	binary.LittleEndian.PutUint64(b[8:16], hi)
	return b
}

// ---- oracle: ChainHash cascade through the shipped batched arm --------------
func chainAbsorb(shape int, seeds *[4][2]uint64, ptrs *[4]*byte, out *[4][2]uint64) {
	switch shape {
	case 13:
		aesitbasm.AESITB128ChainAbsorb13x4(&fixedKey, seeds, ptrs, out)
	case 20:
		aesitbasm.AESITB128ChainAbsorb20x4(&fixedKey, seeds, ptrs, out)
	case 36:
		aesitbasm.AESITB128ChainAbsorb36x4(&fixedKey, seeds, ptrs, out)
	case 68:
		aesitbasm.AESITB128ChainAbsorb68x4(&fixedKey, seeds, ptrs, out)
	default:
		panic("unsupported shape")
	}
}

// cascadeGroup runs all cascade depths on one 4-lane group and returns the
// seed pair fed to the LAST call per lane — the peeled value Y that a real
// attacker recovers via the public P^-1. out[r] receives the four lanes' h_{r+1}.
func cascadeGroup(comps []uint64, rounds, shape int, ptrs *[4]*byte, out [][4][2]uint64) (last [4][2]uint64) {
	var seeds [4][2]uint64
	for l := 0; l < lanes; l++ {
		seeds[l] = [2]uint64{comps[0], comps[1]}
	}
	for r := 0; r < rounds; r++ {
		if r > 0 {
			c0, c1 := comps[2*r], comps[2*r+1]
			prev := &out[r-1]
			for l := 0; l < lanes; l++ {
				seeds[l][0] = c0 ^ prev[l][0]
				seeds[l][1] = c1 ^ prev[l][1]
			}
		}
		if r == rounds-1 {
			last = seeds
		}
		chainAbsorb(shape, &seeds, ptrs, &out[r])
	}
	return
}

// chainSingle evaluates the ChainHash cascade on one text via the shipped
// single arm — used for the low-volume finish verification only.
func chainSingle(h func([]byte, uint64, uint64) (uint64, uint64), data []byte, comps []uint64, rounds int) (uint64, uint64) {
	lo, hi := h(data, comps[0], comps[1])
	for i := 2; i < 2*rounds; i += 2 {
		lo, hi = h(data, comps[i]^lo, comps[i+1]^hi)
	}
	return lo, hi
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

// ---- config -----------------------------------------------------------------
type config struct {
	order     int
	rounds    int
	workers   int
	trials    int
	dataLen   int
	shape     int
	engine    string
	useSeed   bool
	seed      uint64
	earlyExit bool
	active    []int
	order1Max int // sub-block cap for order 1 (independent Lambda-sets)

	// baseTemplate is the fixed Lambda-set constant for order N >= 2, generated
	// once per trial so every sub-block shares it (a genuine order-N set). Set
	// by the trial loop before runClassical / runPairConst / finish.
	baseTemplate [maxLen]byte

	// observable selects the attacker observable: "full" (the lab grant — the
	// full 128-bit h_r, peeled through the public P^-1 to the last-call seed
	// pair Y) or "lo" (the shipped observable — lo(h_r) only, the 8 bytes the
	// encoder consumes; no full-state peel exists). nonceModel selects who
	// picks the non-idx data bytes: "chosen" (lab grant — every data byte
	// attacker-chosen, so a Lambda-set may span nonce bytes) or "idx-only"
	// (shipped model — the active set is confined to the sequential counter
	// bytes, every other byte is a random constant the attacker sees but did
	// not pick; a fresh constant per set models a fresh nonce per message).
	observable string
	nonceModel string
	sets       int // lo-lane mode: independent sets (messages) per trial at order >= 2
}

// order1Active returns the positions order-1 cycles its varying byte through.
// Capped at three (the LE32(idx) bytes at the shipped 20-byte shape) so an
// order-1 run stays a pixel-index-only attacker, matching keyrecover_r2_20byte.py.
func (cfg *config) order1Active() []int {
	n := len(cfg.active)
	if n > 3 {
		n = 3
	}
	return cfg.active[:n]
}

// subBlockTemplate returns the fixed data-len bytes of sub-block sub for a
// given trial, plus the position of the low active byte that varies 0..255.
//
// order 1: each sub-block is an independent Lambda-set — a fresh constant and
// the active position cycling through cfg.active (matches keyrecover_r2_20byte.py:
// three sets active in idx bytes 0 / 1 / 2). order N >= 2: one Lambda-set — the
// constant is fixed for the trial and sub blocks enumerate the order-1 high
// active bytes across cfg.active[1..].
func (cfg *config) subBlockTemplate(trialSeed uint64, sub uint64) ([maxLen]byte, int) {
	if cfg.order == 1 {
		var t [maxLen]byte
		fillRandom(cfg.useSeed, trialSeed^splitmix64(sub^0xA5A5A5A5), t[:cfg.dataLen])
		a := cfg.order1Active()
		return t, a[int(sub)%len(a)]
	}
	// order N >= 2: one Lambda-set — the constant is the trial's base template,
	// generated once; sub blocks enumerate the order-1 high active bytes.
	t := cfg.baseTemplate
	for k := 1; k < cfg.order; k++ {
		t[cfg.active[k]] = byte(sub >> (8 * uint(k-1)))
	}
	return t, cfg.active[0]
}

func (cfg *config) totalSubBlocks() uint64 {
	if cfg.order == 1 {
		return uint64(cfg.order1Max)
	}
	return uint64(1) << (8 * uint(cfg.order-1))
}

// ---- classical engine -------------------------------------------------------
type mask [16][256]bool

func fullMask() *mask {
	m := &mask{}
	for p := 0; p < 16; p++ {
		for g := 0; g < 256; g++ {
			m[p][g] = true
		}
	}
	return m
}

func (m *mask) andInto(o *mask) {
	for p := 0; p < 16; p++ {
		for g := 0; g < 256; g++ {
			m[p][g] = m[p][g] && o[p][g]
		}
	}
}

// state classifies a mask: unique (every byte exactly one candidate), empty
// (some byte zero candidates), or ambiguous.
func (m *mask) classify() (kappa [16]byte, unique, empty bool) {
	unique = true
	for p := 0; p < 16; p++ {
		n := 0
		last := byte(0)
		for g := 0; g < 256; g++ {
			if m[p][g] {
				n++
				last = byte(g)
			}
		}
		if n == 0 {
			empty = true
			return
		}
		if n != 1 {
			unique = false
		} else {
			kappa[p] = last
		}
	}
	return
}

// subBlockMask hashes one 256-text order-1 sub-block through the oracle and
// returns the per-byte balance-test survivor mask. hashNS / kappaNS accumulate
// the split timings.
func (cfg *config) subBlockMask(h func([]byte, uint64, uint64) (uint64, uint64), comps []uint64,
	template [maxLen]byte, lowPos int, hashNS, kappaNS *int64) *mask {

	var parity [16][256]bool
	var bufs [lanes][maxLen]byte
	var ptrs [lanes]*byte
	for l := 0; l < lanes; l++ {
		bufs[l] = template
		ptrs[l] = &bufs[l][0]
	}
	out := make([][4][2]uint64, cfg.rounds)

	th := time.Now()
	for base := 0; base < 256; base += lanes {
		for l := 0; l < lanes; l++ {
			bufs[l][lowPos] = byte(base + l)
		}
		last := cascadeGroup(comps, cfg.rounds, cfg.shape, &ptrs, out)
		for l := 0; l < lanes; l++ {
			yb := seedBytes(last[l][0], last[l][1])
			for i := 0; i < 16; i++ {
				yb[i] ^= rc[1][i]
			}
			w := invMixColumns(yb)
			for p := 0; p < 16; p++ {
				parity[p][w[p]] = !parity[p][w[p]]
			}
		}
	}
	atomic.AddInt64(hashNS, time.Since(th).Nanoseconds())

	tk := time.Now()
	m := &mask{}
	for p := 0; p < 16; p++ {
		for g := 0; g < 256; g++ {
			var x byte
			for v := 0; v < 256; v++ {
				if parity[p][v] {
					x ^= isbox[v^g]
				}
			}
			m[p][g] = x == 0
		}
	}
	atomic.AddInt64(kappaNS, time.Since(tk).Nanoseconds())
	_ = h
	return m
}

// runClassical recovers kappa for one trial; returns kappa, whether it is
// unique, and the number of sub-blocks (256-text units) consumed.
func (cfg *config) runClassical(h func([]byte, uint64, uint64) (uint64, uint64), trialSeed uint64,
	comps []uint64, hashNS, kappaNS *int64) ([16]byte, bool, uint64) {

	total := cfg.totalSubBlocks()

	// Require at least minSets independent sub-blocks before honouring a
	// unique verdict — a single balanced Lambda-set leaves ~2 candidates per
	// byte, so a two-block convergence can be a spurious agreement of random
	// masks. keyrecover_r2_20byte.py intersects three sets (768 texts); this
	// mirrors that floor. An empty mask is a definitive fail and exits at once.
	minSets := 3
	if minSets > int(total) {
		minSets = int(total)
	}

	if cfg.earlyExit {
		acc := fullMask()
		var consumed uint64
		for sub := uint64(0); sub < total; sub++ {
			tpl, lowPos := cfg.subBlockTemplate(trialSeed, sub)
			sm := cfg.subBlockMask(h, comps, tpl, lowPos, hashNS, kappaNS)
			acc.andInto(sm)
			consumed++
			kappa, unique, empty := acc.classify()
			if unique && int(consumed) >= minSets {
				return kappa, true, consumed
			}
			if empty {
				return [16]byte{}, false, consumed
			}
		}
		kappa, unique, _ := acc.classify()
		return kappa, unique, consumed
	}

	// Full sweep: partition sub-blocks across workers, AND-merge the masks.
	var next uint64
	var mu sync.Mutex
	global := fullMask()
	var wg sync.WaitGroup
	for w := 0; w < cfg.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := fullMask()
			for {
				sub := atomic.AddUint64(&next, 1) - 1
				if sub >= total {
					break
				}
				tpl, lowPos := cfg.subBlockTemplate(trialSeed, sub)
				sm := cfg.subBlockMask(h, comps, tpl, lowPos, hashNS, kappaNS)
				local.andInto(sm)
			}
			mu.Lock()
			global.andInto(local)
			mu.Unlock()
		}()
	}
	wg.Wait()
	kappa, unique, _ := global.classify()
	return kappa, unique, total
}

// ---- pair-constancy engine (ported verbatim from square_pairconst) ----------
// M is the MixColumns coefficient matrix (FIPS-197 5.1.3).
var mMat = [4][4]int{{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}}

// runPairConst runs the T-1 == 2 engine on one Lambda-set (256 texts, low
// active byte). It fails at the 20-byte shape (T = 4); returns kappa and
// whether it is unique.
func (cfg *config) runPairConst(h func([]byte, uint64, uint64) (uint64, uint64), trialSeed uint64,
	comps []uint64, hashNS, kappaNS *int64) ([16]byte, bool) {

	tpl, lowPos := cfg.subBlockTemplate(trialSeed, 0)
	if cfg.order != 1 {
		lowPos = cfg.active[0]
	}
	// The active input byte sits at (row rp, column cp) of the first block;
	// after round 1 it saturates column c1 = (cp - rp) mod 4, and ShiftRows
	// of round 2 hands column c the row j_c = (c1 - c) mod 4 of it. For the
	// byte-0 set of keyrecover_r2.py this is c1 = 0, j_c = -c mod 4.
	rp, cp := lowPos%16%4, lowPos%16/4
	c1 := ((cp-rp)%4 + 4) % 4

	var bufs [lanes][maxLen]byte
	var ptrs [lanes]*byte
	for l := 0; l < lanes; l++ {
		bufs[l] = tpl
		ptrs[l] = &bufs[l][0]
	}
	out := make([][4][2]uint64, cfg.rounds)

	// W over the 256 texts.
	var W [256][16]byte
	th := time.Now()
	for base := 0; base < 256; base += lanes {
		for l := 0; l < lanes; l++ {
			bufs[l][lowPos] = byte(base + l)
		}
		last := cascadeGroup(comps, cfg.rounds, cfg.shape, &ptrs, out)
		for l := 0; l < lanes; l++ {
			yb := seedBytes(last[l][0], last[l][1])
			for i := 0; i < 16; i++ {
				yb[i] ^= rc[1][i]
			}
			W[base+l] = invMixColumns(yb)
		}
	}
	atomic.AddInt64(hashNS, time.Since(th).Nanoseconds())

	tk := time.Now()
	defer func() { atomic.AddInt64(kappaNS, time.Since(tk).Nanoseconds()) }()

	// cands[p] as a 256-bool candidate set; nil == not yet constrained.
	var cands [16]*[256]bool
	setInit := func(p int, s map[byte]bool) {
		if cands[p] == nil {
			cands[p] = &[256]bool{}
			for g := range s {
				cands[p][g] = true
			}
			return
		}
		var keep [256]bool
		for g := range s {
			if cands[p][g] {
				keep[g] = true
			}
		}
		*cands[p] = keep
	}

	for c := 0; c < 4; c++ {
		i := ((c1-c)%4 + 4) % 4
		var pos [4]int
		for r := 0; r < 4; r++ {
			pos[r] = r + 4*(((c-r)%4+4)%4)
		}
		// S[j][g][t] = isbox[W[t][pos[j]] ^ g]
		var S [4][256][256]byte
		for j := 0; j < 4; j++ {
			for g := 0; g < 256; g++ {
				for t := 0; t < 256; t++ {
					S[j][g][t] = isbox[W[t][pos[j]]^byte(g)]
				}
			}
		}
		pairs := [6][2]int{{0, 1}, {1, 2}, {2, 3}, {0, 2}, {1, 3}, {0, 3}}
		for _, pr := range pairs {
			j, j2 := pr[0], pr[1]
			mA := mMat[j2][i]
			mB := mMat[j][i]
			// A[g] = mul(mA, S[j][g]) minus its first text; B[g] = mul(mB, S[j2][g]) minus first.
			rows := map[string][]int{}
			for g := 0; g < 256; g++ {
				var row [256]byte
				a0 := mul[mA][S[j][g][0]]
				for t := 0; t < 256; t++ {
					row[t] = mul[mA][S[j][g][t]] ^ a0
				}
				key := string(row[:])
				rows[key] = append(rows[key], g)
			}
			pj := map[byte]bool{}
			pj2 := map[byte]bool{}
			for g2 := 0; g2 < 256; g2++ {
				var row [256]byte
				b0 := mul[mB][S[j2][g2][0]]
				for t := 0; t < 256; t++ {
					row[t] = mul[mB][S[j2][g2][t]] ^ b0
				}
				if hit, ok := rows[string(row[:])]; ok {
					for _, g := range hit {
						pj[byte(g)] = true
					}
					pj2[byte(g2)] = true
				}
			}
			setInit(pos[j], pj)
			setInit(pos[j2], pj2)
		}
	}

	var kappa [16]byte
	for p := 0; p < 16; p++ {
		if cands[p] == nil {
			return kappa, false
		}
		n := 0
		last := byte(0)
		for g := 0; g < 256; g++ {
			if cands[p][g] {
				n++
				last = byte(g)
			}
		}
		if n != 1 {
			return kappa, false
		}
		kappa[p] = last
	}
	return kappa, true
}

// ---- finish + verification --------------------------------------------------
// finish reconstructs the two-call component set from kappa and verifies it on
// four fresh chosen texts against the true depth-r oracle. Returns the
// recovered components, the verified count (out of 4), and whether the
// recovered components byte-exactly match the ground truth (terminal report).
func (cfg *config) finish(h func([]byte, uint64, uint64) (uint64, uint64), trialSeed uint64,
	comps []uint64, kappa [16]byte) ([]uint64, int, bool) {

	k2 := mixColumns(kappa)
	// sub-block 0, low active byte 0, is text0.
	tpl, lowPos := cfg.subBlockTemplate(trialSeed, 0)
	tpl[lowPos] = 0
	text0 := tpl[:cfg.dataLen]

	var bufs [lanes][maxLen]byte
	var ptrs [lanes]*byte
	for l := 0; l < lanes; l++ {
		bufs[l] = tpl
		ptrs[l] = &bufs[l][0]
	}
	out := make([][4][2]uint64, cfg.rounds)
	last := cascadeGroup(comps, cfg.rounds, cfg.shape, &ptrs, out)
	y0 := seedBytes(last[0][0], last[0][1])

	var h1 [16]byte
	for i := 0; i < 16; i++ {
		h1[i] = y0[i] ^ k2[i]
	}
	s0, s1 := invertGeneric(text0, h1)
	recovered := []uint64{
		s0, s1,
		binary.LittleEndian.Uint64(k2[0:8]),
		binary.LittleEndian.Uint64(k2[8:16]),
	}

	ok := 0
	var d [maxLen]byte
	for i := 0; i < 4; i++ {
		fillRandom(cfg.useSeed, trialSeed^splitmix64(uint64(0xF00D+i)), d[:cfg.dataLen])
		tl, th := chainSingle(h, d[:cfg.dataLen], comps, cfg.rounds)
		rl, rh := chainSingle(h, d[:cfg.dataLen], recovered, 2)
		if tl == rl && th == rh {
			ok++
		}
	}
	gt := recovered[0] == comps[0] && recovered[1] == comps[1] &&
		recovered[2] == comps[2] && recovered[3] == comps[3]
	return recovered, ok, gt
}

// ---- self-tests -------------------------------------------------------------
// generic KAT vectors from aesitb/aesitb_test.go (data = bytes(range(n))).
var kat = []struct {
	n      int
	s0, s1 uint64
	want   string
}{
	{0, 0x0, 0x0, "d03e268799c14203bdb3e663165d6b23"},
	{1, 0x0, 0x0, "f2a4e404c80c84451e35cadcc7f22bb9"},
	{15, 0x0, 0x0, "95be57f5a239f3ab144382b7cd8695de"},
	{16, 0x0, 0x0, "3171e8f8165c8ff5203ac9aa371c719a"},
	{17, 0x0, 0x0, "48d3f6fcc2985cf31a074ea2c78b1d09"},
	{31, 0x0, 0x0, "064e72d014e7a41c4fc3b7d1b938f625"},
	{32, 0x0, 0x0, "e08f48e9037d3bc81d03dc0adc1b9d3b"},
	{33, 0x0, 0x0, "7370df93d8fd5e118d33484f582e1750"},
	{63, 0x0, 0x0, "c17822cc92d1a5fb712a1ea655de82ad"},
	{64, 0x0, 0x0, "81615890aab0306bf4b32bbe2d7ca1af"},
	{0, 0x1, 0x0, "787e6d0bae570d2ec58796bcbf68c172"},
	{0, 0x0, 0x1, "e9d430852929ab3d88c240ddc40f823c"},
	{5, 0x123456789abcdef, 0xfedcba9876543210, "7486079419f3f0767b579065d6cc3d93"},
	{16, 0xffffffffffffffff, 0xffffffffffffffff, "2eae20695db216506bd63f96fda12ca0"},
	{33, 0x7, 0x9, "dccfc56b263e1a2fc13052534f15092e"},
	{64, 0x8000000000000000, 0x1, "a7a8e09b329611b7aec6a97b0e75cd25"},
}

func selfTest(cfg *config, h func([]byte, uint64, uint64) (uint64, uint64)) error {
	// (1) shipped single arm reproduces the Python generic KATs, and
	//     invertGeneric round-trips it.
	for _, v := range kat {
		data := make([]byte, v.n)
		for i := range data {
			data[i] = byte(i)
		}
		lo, hi := h(data, v.s0, v.s1)
		got := seedBytes(lo, hi)
		if hex.EncodeToString(got[:]) != v.want {
			return fmt.Errorf("generic KAT mismatch at len=%d: got %s want %s",
				v.n, hex.EncodeToString(got[:]), v.want)
		}
		is0, is1 := invertGeneric(data, got)
		if is0 != v.s0 || is1 != v.s1 {
			return fmt.Errorf("invertGeneric mismatch at len=%d", v.n)
		}
	}
	// (2) batched ChainAbsorb-driven cascade == sequential single arm per depth,
	//     at every shipped shape.
	for _, shape := range []int{13, 20, 36, 68} {
		var bufs [lanes][maxLen]byte
		var ptrs [lanes]*byte
		for l := 0; l < lanes; l++ {
			fillBytes(uint64(shape)*0x9E37+uint64(l), bufs[l][:shape])
			ptrs[l] = &bufs[l][0]
		}
		comps := make([]uint64, 2*cfg.rounds)
		raw := make([]byte, 8*len(comps))
		fillBytes(0xC0FFEE^uint64(shape), raw)
		for i := range comps {
			comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		out := make([][4][2]uint64, cfg.rounds)
		cascadeGroup(comps, cfg.rounds, shape, &ptrs, out)
		for l := 0; l < lanes; l++ {
			lo, hi := h(bufs[l][:shape], comps[0], comps[1])
			for r := 0; r < cfg.rounds; r++ {
				if r > 0 {
					lo, hi = h(bufs[l][:shape], comps[2*r]^lo, comps[2*r+1]^hi)
				}
				if out[r][l] != [2]uint64{lo, hi} {
					return fmt.Errorf("cascade parity shape=%d lane=%d depth=%d: driven (%016x,%016x) != seq (%016x,%016x)",
						shape, l, r+1, out[r][l][0], out[r][l][1], lo, hi)
				}
			}
		}
	}
	return nil
}

// ---- driver -----------------------------------------------------------------
func parseActive(s string, n int) ([]int, error) {
	parts := strings.Split(s, ",")
	seen := map[int]bool{}
	var a []int
	for _, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 || v >= maxLen || seen[v] {
			return nil, fmt.Errorf("--active position %q must be a distinct integer in [0, %d)", p, maxLen)
		}
		seen[v] = true
		a = append(a, v)
	}
	if len(a) < n {
		return nil, fmt.Errorf("--active needs at least --order=%d positions, got %d", n, len(a))
	}
	return a, nil
}

func depthTexts(order int) string {
	if order == 1 {
		return "768 (3 sets)"
	}
	return fmt.Sprintf("2^%d", 8*order)
}

// ---- forward ShiftRows + one round (diagonal self-test only) ----------------
func shiftRows(s [16]byte) [16]byte {
	var o [16]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			o[r+4*c] = s[r+4*((c+r)%4)]
		}
	}
	return o
}

// oneRound applies one forward AES round (SubBytes, ShiftRows, MixColumns) with
// no round-constant add — used only to pin the diagonal in selfTestDiagonal.
func oneRound(s [16]byte) [16]byte {
	for i := range s {
		s[i] = sbox[s[i]]
	}
	s = shiftRows(s)
	return mixColumns(s)
}

// selfTestDiagonal confirms that under the shipped ShiftRows each diagonal input
// byte {0, 5, 10, 15} lands in column 0 after one round: varying it alone makes
// exactly output bytes 0..3 vary and bytes 4..15 stay constant. This is the
// column-saturation property the order-4 higher-order set relies on (a diagonal
// becomes a fully active column after round 1, so the state is balanced after
// round 4 — the classical FKLSSW 4-round higher-order integral).
func selfTestDiagonal() error {
	for _, p := range []int{0, 5, 10, 15} {
		var base [16]byte
		fillBytes(0xD1A9^uint64(p), base[:])
		var varying [16]bool
		ref := oneRound(base)
		for v := 1; v < 256; v++ {
			st := base
			st[p] = base[p] ^ byte(v)
			o := oneRound(st)
			for i := 0; i < 16; i++ {
				if o[i] != ref[i] {
					varying[i] = true
				}
			}
		}
		for i := 0; i < 16; i++ {
			if varying[i] != (i < 4) {
				return fmt.Errorf("diagonal pin failed: input byte %d varies output byte %d (want column 0 only)", p, i)
			}
		}
	}
	return nil
}

// ---- global-parity higher-order integral engine -----------------------------
// One order-N Lambda-set is 2^(8N) texts spanning the N active positions (a
// diagonal for the column-saturation property). The peeled value
//
//	W[p] = InvMixColumns(Y ^ RC[1])[p] = kappa[p] ^ ShiftRows(SubBytes(X'))[p],
//
// with X' the state entering P's last round and kappa = InvMixColumns(k2),
// mirrors the order-1 kappa engine exactly. Over a set balanced after T-1
// rounds, XOR_texts InvSubBytes(W[p] ^ kappa[p]) == 0 singles out kappa[p]. The
// only difference from runClassical is the SET: the whole 2^(8N) is summed into
// one 16x256 parity table (not order-1 sub-blocks ANDed). Order-1 balances after
// 3 rounds (peel round 4, T <= 4); an order-4 diagonal balances after 4 rounds
// (peel round 5, T = 5). Below the full codebook no zero-sum integral survives
// past 4 rounds at any order, so a single-round peel cannot reach T >= 6 (T = 6
// needs a 2-round peel ~2^64, T = 7 a 3-round peel ~2^128); square-6 runs here
// only as a negative control at shape 68. The parity table streams the set, so
// RAM is 16x256 per worker regardless of text count — the bound is work, not
// memory. At shape 36 the diagonal {0,5,10,15} spans nonce bytes (5/10/15; idx
// is LE32 in 0..3), so this is a chosen-nonce, discard-off (full-state) lab
// grant, not the pixel-index-only attacker of the shape-20 order-1 result.
func (cfg *config) globalParityMask(comps []uint64, setSeed uint64,
	hashNS, kappaNS *int64) *mask {

	order := cfg.order
	lowPos := cfg.active[0]
	high := cfg.active[1:order]
	outer := uint64(1) << (8 * uint(order-1)) // 2^(8(order-1)) high-byte combos

	var base [maxLen]byte
	fillRandom(cfg.useSeed, setSeed, base[:cfg.dataLen])

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
			var bufs [lanes][maxLen]byte
			var ptrs [lanes]*byte
			for l := 0; l < lanes; l++ {
				bufs[l] = base
				ptrs[l] = &bufs[l][0]
			}
			out := make([][4][2]uint64, cfg.rounds)
			par := &locals[id]
			for {
				o := atomic.AddUint64(&next, 1) - 1
				if o >= outer {
					break
				}
				for k := 0; k < len(high); k++ {
					b := byte(o >> (8 * uint(k)))
					for l := 0; l < lanes; l++ {
						bufs[l][high[k]] = b
					}
				}
				for b := 0; b < 256; b += lanes {
					for l := 0; l < lanes; l++ {
						bufs[l][lowPos] = byte(b + l)
					}
					last := cascadeGroup(comps, cfg.rounds, cfg.shape, &ptrs, out)
					for l := 0; l < lanes; l++ {
						yb := seedBytes(last[l][0], last[l][1])
						for i := 0; i < 16; i++ {
							yb[i] ^= rc[1][i]
						}
						wv := invMixColumns(yb)
						for p := 0; p < 16; p++ {
							par[p][wv[p]] = !par[p][wv[p]]
						}
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

	tk := time.Now()
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
	atomic.AddInt64(kappaNS, time.Since(tk).Nanoseconds())
	return m
}

// finishFromMask enumerates the per-byte survivor product of the mask and
// returns the kappa whose reconstructed two-call component set verifies on four
// fresh chosen texts (the r = 2 disambiguation the advisor's one-set path relies
// on). Bounded by productCap; returns false if the product is larger (caller
// ANDs another set), if a byte is empty (definitive fail), or if nothing
// verifies. At r >= 3 no two-call set reproduces the r-call cascade, so this
// verification correctly fails.
func (cfg *config) finishFromMask(h func([]byte, uint64, uint64) (uint64, uint64),
	trialSeed uint64, comps []uint64, m *mask) ([16]byte, bool) {

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

	tpl := cfg.baseTemplate
	for _, p := range cfg.active[:cfg.order] {
		tpl[p] = 0
	}
	text0 := append([]byte(nil), tpl[:cfg.dataLen]...)
	var bufs [lanes][maxLen]byte
	var ptrs [lanes]*byte
	for l := 0; l < lanes; l++ {
		bufs[l] = tpl
		ptrs[l] = &bufs[l][0]
	}
	out := make([][4][2]uint64, cfg.rounds)
	last := cascadeGroup(comps, cfg.rounds, cfg.shape, &ptrs, out)
	y0 := seedBytes(last[0][0], last[0][1])

	var vd [4][maxLen]byte
	for i := 0; i < 4; i++ {
		fillRandom(cfg.useSeed, trialSeed^splitmix64(uint64(0xF00D+i)), vd[i][:cfg.dataLen])
	}

	var kappa [16]byte
	var idx [16]int
	for {
		for p := 0; p < 16; p++ {
			kappa[p] = cand[p][idx[p]]
		}
		k2 := mixColumns(kappa)
		var h1 [16]byte
		for i := 0; i < 16; i++ {
			h1[i] = y0[i] ^ k2[i]
		}
		s0, s1 := invertGeneric(text0, h1)
		recovered := []uint64{s0, s1,
			binary.LittleEndian.Uint64(k2[0:8]),
			binary.LittleEndian.Uint64(k2[8:16])}
		ok := 0
		for i := 0; i < 4; i++ {
			tl, thh := chainSingle(h, vd[i][:cfg.dataLen], comps, cfg.rounds)
			rl, rh := chainSingle(h, vd[i][:cfg.dataLen], recovered, 2)
			if tl == rl && thh == rh {
				ok++
			}
		}
		if ok == 4 {
			return kappa, true
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

// runGlobalParity accumulates up to three independent order-N sets, ANDing their
// survivor masks, and returns a verified-unique kappa (via finishFromMask) plus
// the chosen-text count consumed. One 2^(8N) set already carries the correct
// kappa at r = 2; finishFromMask brute-forces the ~2^16 survivor product to pin
// it, so a single set usually suffices. A byte emptying is a definitive fail.
func (cfg *config) runGlobalParity(h func([]byte, uint64, uint64) (uint64, uint64),
	trialSeed uint64, comps []uint64, hashNS, kappaNS *int64) ([16]byte, bool, uint64) {

	setTexts := uint64(1) << (8 * uint(cfg.order))
	acc := fullMask()
	var consumed uint64
	for s := 0; s < 3; s++ {
		setSeed := trialSeed ^ splitmix64(uint64(s)*0x2545F4914F6CDD1D)
		acc.andInto(cfg.globalParityMask(comps, setSeed, hashNS, kappaNS))
		consumed += setTexts
		if kappa, ok := cfg.finishFromMask(h, trialSeed, comps, acc); ok {
			return kappa, true, consumed
		}
		if _, _, empty := acc.classify(); empty {
			return [16]byte{}, false, consumed
		}
	}
	return [16]byte{}, false, consumed
}

// squareEngine classifies the --engine string into an accumulator family and
// its design per-pixel round count T (the round count the engine is built for;
// a mismatch with the shape's T is a legitimate negative control).
func squareEngine(name string) (family string, designT int, ok bool) {
	switch name {
	case "classical", "classical-square-4":
		return "classical", 4, true
	case "classical-square-3":
		return "pair-constancy", 3, true
	case "pair-constancy":
		return "pair-constancy", 3, true
	case "classical-square-5":
		return "global-parity", 5, true
	case "classical-square-6":
		return "global-parity", 6, true
	}
	return "", 0, false
}

// shapeT returns the per-pixel round count T for a data length (nblk + 2
// finaliser rounds), matching the shipped sponge.
func shapeT(dataLen int) int {
	pad := 16 - dataLen%16
	return (dataLen+pad)/16 + 2
}

func main() {
	initAES()

	order := flag.Int("order", 1, "Lambda-set order (1 = column sets, 768 texts; N = one 2^(8N)-text diagonal set)")
	rounds := flag.Int("rounds", 2, "cascade depth R (number of ChainHash calls)")
	workers := flag.Int("workers", 16, "goroutines for the full early-exit-off sweep")
	trials := flag.Int("trials", 5, "trials with fresh components")
	dataLen := flag.Int("data-len", 20, "per-pixel shape in bytes (13 / 20 / 36 / 68)")
	seed := flag.Int64("seed", 0, "deterministic seed (0 = crypto/rand)")
	engine := flag.String("engine", "classical-square-4", "classical-square-4 (order-1 kappa, T=4) | classical-square-3 (pair-constancy, T=3) | classical-square-5 (order-4 global parity, T=5) | classical-square-6 (global parity, T=6 negative control) | pair-constancy | classical (alias of classical-square-4)")
	activeStr := flag.String("active", "0,1,2,3,4", "active byte positions; order 1 cycles only the first three (idx bytes); order N uses [0] as the varying byte and [1..N-1] as enumerated high bytes. global-parity engines default to the {0,5,10,15} diagonal and order 4")
	earlyExit := flag.Bool("early-exit", true, "stop a trial as soon as the mask converges or empties")
	order1Max := flag.Int("order1-max", 8, "max independent order-1 Lambda-sets before giving up")
	observable := flag.String("observable", "full", "attacker observable: full (lab grant: full 128-bit h_r, public P^-1 peel to the last-call seed pair) | lo (shipped: lo(h_r) only, no full-state peel)")
	nonceModel := flag.String("nonce", "chosen", "who picks the non-active data bytes: chosen (lab grant: any data byte may be active) | idx-only (shipped: active set confined to the sequential counter bytes, every other byte a random constant per set = a fresh nonce per message)")
	model := flag.String("model", "", "shorthand: realistic = --observable lo --nonce idx-only; lab = --observable full --nonce chosen (explicit --observable / --nonce win)")
	sets := flag.Int("sets", 3, "lo-lane mode, order >= 2: independent order-N sets (messages) per trial")
	labControl := flag.Bool("lab-control", true, "lo-lane mode: also run the lab-grant engine (observable=full) on the same seeds as the positive control")
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
		if !isFlagSet("observable") {
			*observable = "full"
		}
		if !isFlagSet("nonce") {
			*nonceModel = "chosen"
		}
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

	if *rounds < 1 || *rounds > maxRounds {
		fmt.Fprintf(os.Stderr, "--rounds must be in [1, %d]\n", maxRounds)
		os.Exit(2)
	}
	if *order < 1 || *order > 8 {
		fmt.Fprintln(os.Stderr, "--order must be in [1, 8]")
		os.Exit(2)
	}
	switch *dataLen {
	case 13, 20, 36, 68:
	default:
		fmt.Fprintln(os.Stderr, "--data-len must be one of 13 / 20 / 36 / 68")
		os.Exit(2)
	}
	family, designT, ok := squareEngine(*engine)
	if !ok {
		fmt.Fprintln(os.Stderr, "--engine must be one of classical-square-{3,4,5,6} | pair-constancy | classical")
		os.Exit(2)
	}
	// global-parity engines default to the {0,5,10,15} diagonal (column-0
	// saturation) and order 4 when the user left BOTH shared defaults; an
	// explicit --active or --order is always respected.
	if family == "global-parity" && *activeStr == "0,1,2,3,4" && *order == 1 {
		*activeStr = "0,5,10,15"
		*order = 4
	}
	if *workers < 1 {
		*workers = 1
	}
	// Under the shipped nonce model the shared default active list is trimmed
	// to the sequential-counter bytes of the shape (an explicit --active is
	// validated below instead).
	if *nonceModel == "idx-only" && !isFlagSet("active") {
		lo, hi := idxPositions(*dataLen)
		parts := make([]string, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			parts = append(parts, strconv.Itoa(p))
		}
		*activeStr = strings.Join(parts, ",")
	}
	active, err := parseActive(*activeStr, *order)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, p := range active {
		if p >= *dataLen {
			fmt.Fprintf(os.Stderr, "--active position %d is outside --data-len=%d\n", p, *dataLen)
			os.Exit(2)
		}
	}
	if *nonceModel == "idx-only" {
		lo, hi := idxPositions(*dataLen)
		for _, p := range active {
			if p < lo || p > hi {
				fmt.Fprintf(os.Stderr, "--nonce idx-only: active position %d is not a sequential-counter byte (allowed %d..%d at data-len %d)\n", p, lo, hi, *dataLen)
				os.Exit(2)
			}
		}
	}
	runtime.GOMAXPROCS(*workers)

	cfg := &config{
		order: *order, rounds: *rounds, workers: *workers, trials: *trials,
		dataLen: *dataLen, shape: *dataLen, engine: *engine,
		useSeed: *seed != 0, seed: uint64(*seed), earlyExit: *earlyExit,
		active: active, order1Max: *order1Max,
		observable: *observable, nonceModel: *nonceModel, sets: *sets,
	}

	h, _ := hashes.AESITB128PairWithKey(fixedKey)
	if err := selfTest(cfg, h); err != nil {
		fmt.Fprintln(os.Stderr, "self-test FAILED:", err)
		os.Exit(1)
	}
	if err := selfTestDiagonal(); err != nil {
		fmt.Fprintln(os.Stderr, "self-test FAILED:", err)
		os.Exit(1)
	}

	shT := shapeT(cfg.dataLen)
	fmt.Println(strings.Repeat("=", 96))
	fmt.Printf("Go kappa-byte key recovery through ChainHash<AES-ITB-128> — engine=%s (family=%s)\n", cfg.engine, family)
	fmt.Println(strings.Repeat("=", 96))
	fmt.Printf("  order=%d (%s chosen texts per set), rounds=%d, data-len=%d (T=%d), design-T=%d, trials=%d\n",
		cfg.order, depthTexts(cfg.order), cfg.rounds, cfg.dataLen, shT, designT, cfg.trials)
	if shT != designT {
		fmt.Printf("  NOTE: shape T=%d != engine design-T=%d — running as a negative control (recovery not expected)\n", shT, designT)
	}
	fmt.Printf("  active=%v, early-exit=%v, workers=%d, seed=%d\n",
		cfg.active, cfg.earlyExit, cfg.workers, *seed)
	fmt.Printf("  self-test OK (16 generic KATs + invertGeneric round-trip + batched cascade parity 4 shapes + diagonal pin)\n")
	fmt.Printf("  attacker model: observable=%s, nonce=%s\n", cfg.observable, cfg.nonceModel)
	fmt.Println()

	if cfg.observable == "lo" {
		cfg.runLoLaneTrials(h)
		if *labControl {
			fmt.Println()
			fmt.Printf("  lab control (same binary, same seeds, observable=full, engine=%s family=%s):\n", cfg.engine, family)
			cfg.runLabTrials(h, family)
		}
		return
	}

	cfg.runLabTrials(h, family)
}

// runLabTrials runs the lab-grant engines (observable = full: the last-call
// seed pair Y captured from the cascade recurrence, i.e. the public P^-1 peel
// of the full 128-bit h_r) over cfg.trials trials and prints the recovery
// verdict. The ground-truth comparison is a terminal report only.
func (cfg *config) runLabTrials(h func([]byte, uint64, uint64) (uint64, uint64), family string) {
	var hashNS, kappaNS int64
	var consumedTexts uint64
	hits, verified, found := 0, 0, 0
	t0 := time.Now()

	for tr := 0; tr < cfg.trials; tr++ {
		trialSeed := cfg.seed ^ splitmix64(uint64(tr)*0x1234567)
		comps := make([]uint64, 2*cfg.rounds)
		raw := make([]byte, 8*len(comps))
		fillRandom(cfg.useSeed, trialSeed, raw)
		for i := range comps {
			comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		// One fixed Lambda-set constant per trial (shared by every order-N
		// sub-block); order 1 draws its own per-sub-block constants instead.
		cfg.baseTemplate = [maxLen]byte{}
		fillRandom(cfg.useSeed, trialSeed^0x5151515151515151, cfg.baseTemplate[:cfg.dataLen])

		var kappa [16]byte
		var unique bool
		var consumed uint64

		switch family {
		case "classical":
			kappa, unique, consumed = cfg.runClassical(h, trialSeed, comps, &hashNS, &kappaNS)
			consumedTexts += consumed * 256
		case "pair-constancy":
			kappa, unique = cfg.runPairConst(h, trialSeed, comps, &hashNS, &kappaNS)
			consumedTexts += 256
		case "global-parity":
			var texts uint64
			kappa, unique, texts = cfg.runGlobalParity(h, trialSeed, comps, &hashNS, &kappaNS)
			consumedTexts += texts
		}

		if unique {
			found++
			_, ok, gt := cfg.finish(h, trialSeed, comps, kappa)
			if ok == 4 {
				verified++
				if gt {
					hits++
				}
			}
		}
	}
	wall := time.Since(t0)

	tag := "fails"
	if cfg.trials > 0 && hits > 0 && hits >= cfg.trials-1 {
		tag = "RECOVERS both seed blocks"
	}
	fmt.Printf("  result: unique kappa %d/%d, verified %d/%d, ground truth %d/%d  ->  %s\n",
		found, cfg.trials, verified, cfg.trials, hits, cfg.trials, tag)
	fmt.Printf("  chosen texts consumed: %d (%.0f/trial)\n", consumedTexts, float64(consumedTexts)/float64(cfg.trials))
	fmt.Printf("  wall %.2fs  (hash %.2fs, kappa %.2fs)\n",
		wall.Seconds(), float64(hashNS)/1e9, float64(kappaNS)/1e9)
	if hashNS > 0 {
		rate := float64(consumedTexts) / (float64(hashNS) / 1e9)
		fmt.Printf("  single-thread hash rate: %.2f M texts/s at depth %d, shape %d (x%d cascade calls/text)\n",
			rate/1e6, cfg.rounds, cfg.shape, cfg.rounds)
	}
}

// ---- shipped-observable mode (--observable lo) ------------------------------
//
// The lab engines above run on the full 128-bit h_r peeled through the public
// P^-1 to the last-call seed pair Y — a grant the shipped pipeline never
// makes: the encoder consumes lo(h_r) only (process_generic.go — noisePos,
// rotation and the per-channel XOR mask all derive from h[0]), and the
// Interlocked Barrier consumes its own single-call fill output through the
// combinadic unrank, never on the wire. With the hi lane hidden the full-state
// peel does not exist, so the kappa-byte engine has no Y to work on; the one
// step that remains public is the LAST finaliser round on the two visible
// state columns (RC[1] known, InvMixColumns per column):
//
//	w[0..7] = InvMixColumns(lo(h_r) ^ RC[1][0:8])   (columns 0, 1 of SR(SB(X')))
//
// where X' is the state entering that round. Over a Lambda-set, X' is balanced
// exactly when the integral survives to the last round, so the per-position
// balance test Sum_texts InvSubBytes(w[p] ^ g) == 0 with g = 0 (RC[1] already
// removed — there is no unknown post-whitening on this lane) is a
// distinguisher, not a recovery: nothing key-dependent is peeled. The
// g-survivor count per position is reported alongside so a balanced reading
// is visible as "g = 0 survives" rather than as a chance survivor
// (floor: one survivor of 256 per position at random).
//
// Recovery on this observable has no engine here: the residual route is the
// 2^64 hi-lane enumeration that integral_aesitb128.py extrapolates. The
// verdict printed is therefore "no candidate (structural)", never "0/N".
//
// The lo-lane oracle is an attacker-favourable upper bound on the wire: a
// known-plaintext attacker reads h[0] only through noisePos / rotation /
// xorMask across two seeds, with per-pixel ambiguity, never exactly.

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

// idxPositions returns the inclusive range of sequential-counter bytes of a
// per-pixel shape — the only data bytes whose value the attacker sees enumerate
// naturally: LE32(idx) at bytes 0..3 for the 20 / 36 / 68-byte pixel shapes,
// LE64(groupIdx) at bytes 1..8 for the 13-byte Interlocked Barrier fill shape
// (byte 0 is the 0x03 domain tag, bytes 9..12 are reserved zeros).
func idxPositions(shape int) (int, int) {
	if shape == 13 {
		return 1, 8
	}
	return 0, 3
}

// loTables accumulates the lo-lane observable over one Lambda-set. raw[p][v]
// is the XOR-parity of value v at lo byte p; peeled[p][v] the same for the
// column-peeled value w[p]. first / diffOr track per-byte activity.
type loTables struct {
	raw, peeled [8][256]bool
	first       [8]byte
	diffOr      [8]byte
	seen        bool
	texts       uint64
}

func (t *loTables) add(lo uint64) {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], lo)
	if !t.seen {
		copy(t.first[:], b[:8])
		t.seen = true
	}
	for p := 0; p < 8; p++ {
		t.raw[p][b[p]] = !t.raw[p][b[p]]
		t.diffOr[p] |= b[p] ^ t.first[p]
	}
	for i := 0; i < 8; i++ {
		b[i] ^= rc[1][i]
	}
	// InvMixColumns is column-local; columns 2 and 3 carry zeros and are
	// never read.
	w := invMixColumns(b)
	for p := 0; p < 8; p++ {
		t.peeled[p][w[p]] = !t.peeled[p][w[p]]
	}
	t.texts++
}

func (t *loTables) merge(o *loTables) {
	if !o.seen {
		return
	}
	for p := 0; p < 8; p++ {
		for v := 0; v < 256; v++ {
			t.raw[p][v] = t.raw[p][v] != o.raw[p][v]
			t.peeled[p][v] = t.peeled[p][v] != o.peeled[p][v]
		}
	}
	if !t.seen {
		t.first = o.first
		t.seen = true
	}
	for p := 0; p < 8; p++ {
		t.diffOr[p] |= o.diffOr[p] | (o.first[p] ^ t.first[p])
	}
	t.texts += o.texts
}

// loVerdict summarises one Lambda-set on the lo lane.
type loVerdict struct {
	active    int    // lo bytes that vary over the set
	rawBal    int    // lo bytes whose XOR-sum over the set is zero
	peeledBal int    // peeled positions where g = 0 survives (X' balanced there)
	survivors [8]int // g-survivor count per peeled position (floor ~1)
}

func (t *loTables) verdict() loVerdict {
	var v loVerdict
	for p := 0; p < 8; p++ {
		var x byte
		for val := 0; val < 256; val++ {
			if t.raw[p][val] {
				x ^= byte(val)
			}
		}
		if x == 0 {
			v.rawBal++
		}
		if t.diffOr[p] != 0 {
			v.active++
		}
		for g := 0; g < 256; g++ {
			var y byte
			for val := 0; val < 256; val++ {
				if t.peeled[p][val] {
					y ^= isbox[byte(val)^byte(g)]
				}
			}
			if y == 0 {
				v.survivors[p]++
				if g == 0 {
					v.peeledBal++
				}
			}
		}
	}
	return v
}

// loSet sweeps one Lambda-set through the lo-lane oracle: lowPos is the byte
// that runs over 0..255, high[] the enumerated higher active bytes (empty at
// order 1); every other data byte is a random constant drawn from setSeed — a
// nonce the attacker sees but did not choose. Only lo(h_r) is read from the
// cascade; the last-call seed pair the driver could capture is never touched.
func (cfg *config) loSet(comps []uint64, setSeed uint64, lowPos int, high []int) *loTables {
	outer := uint64(1) << (8 * uint(len(high)))
	var base [maxLen]byte
	fillRandom(cfg.useSeed, setSeed, base[:cfg.dataLen])

	nw := cfg.workers
	if uint64(nw) > outer {
		nw = int(outer)
	}
	if nw < 1 {
		nw = 1
	}
	locals := make([]loTables, nw)
	var next uint64
	var wg sync.WaitGroup
	for w := 0; w < nw; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var bufs [lanes][maxLen]byte
			var ptrs [lanes]*byte
			for l := 0; l < lanes; l++ {
				bufs[l] = base
				ptrs[l] = &bufs[l][0]
			}
			out := make([][4][2]uint64, cfg.rounds)
			t := &locals[id]
			for {
				o := atomic.AddUint64(&next, 1) - 1
				if o >= outer {
					break
				}
				for k := range high {
					b := byte(o >> (8 * uint(k)))
					for l := 0; l < lanes; l++ {
						bufs[l][high[k]] = b
					}
				}
				for b := 0; b < 256; b += lanes {
					for l := 0; l < lanes; l++ {
						bufs[l][lowPos] = byte(b + l)
					}
					cascadeGroup(comps, cfg.rounds, cfg.shape, &ptrs, out)
					for l := 0; l < lanes; l++ {
						t.add(out[cfg.rounds-1][l][0])
					}
				}
			}
		}(w)
	}
	wg.Wait()
	acc := &loTables{}
	for w := range locals {
		acc.merge(&locals[w])
	}
	return acc
}

// runLoLaneTrials is the --observable lo driver: per trial fresh components,
// then either cfg.order1Max independent order-1 sets (fresh nonce each, the
// active byte cycling through the first three --active positions, matching
// the lab order-1 engine) or cfg.sets independent order-N sets. Prints the
// per-set balance verdicts and the structural recovery reading.
func (cfg *config) runLoLaneTrials(h func([]byte, uint64, uint64) (uint64, uint64)) {
	_ = h
	const floor = 8 / 256.0
	fmt.Println(strings.Repeat("-", 96))
	fmt.Printf("Lo-lane observable screen (shipped: lo(h_r) only, no full-state peel) — order=%d, rounds=%d, data-len=%d (T=%d), nonce=%s\n",
		cfg.order, cfg.rounds, cfg.dataLen, shapeT(cfg.dataLen), cfg.nonceModel)
	fmt.Printf("  per set: 8 lo bytes; raw balanced = XOR-sum zero; peeled balanced = g=0 survives the last-round column peel; floor %.3f per lane\n", floor)
	fmt.Println(strings.Repeat("-", 96))

	t0 := time.Now()
	var totalTexts uint64
	var sumRaw, sumPeeled float64
	nSetsTotal := 0
	for tr := 0; tr < cfg.trials; tr++ {
		trialSeed := cfg.seed ^ splitmix64(uint64(tr)*0x1234567)
		comps := make([]uint64, 2*cfg.rounds)
		raw := make([]byte, 8*len(comps))
		fillRandom(cfg.useSeed, trialSeed, raw)
		for i := range comps {
			comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}

		nSets := cfg.sets
		if cfg.order == 1 {
			nSets = cfg.order1Max
		}
		trRaw, trPeeled := 0, 0
		for s := 0; s < nSets; s++ {
			setSeed := trialSeed ^ splitmix64(uint64(s)*0x2545F4914F6CDD1D^0x77)
			lowPos := cfg.active[0]
			var high []int
			if cfg.order == 1 {
				a := cfg.order1Active()
				lowPos = a[s%len(a)]
			} else {
				high = cfg.active[1:cfg.order]
			}
			t := cfg.loSet(comps, setSeed, lowPos, high)
			v := t.verdict()
			totalTexts += t.texts
			trRaw += v.rawBal
			trPeeled += v.peeledBal
			fmt.Printf("  trial %d set %d (low byte %d, high %v, %d texts): active %d/8, raw balanced %d/8, peeled balanced %d/8, g-survivors %v\n",
				tr, s, lowPos, high, t.texts, v.active, v.rawBal, v.peeledBal, v.survivors)
		}
		sumRaw += float64(trRaw) / float64(nSets)
		sumPeeled += float64(trPeeled) / float64(nSets)
		nSetsTotal += nSets
	}
	wall := time.Since(t0)
	meanRaw := sumRaw / float64(cfg.trials)
	meanPeeled := sumPeeled / float64(cfg.trials)
	tagRaw := "floor"
	if meanRaw > floor+1 {
		tagRaw = "STRUCTURED (integral leak)"
	}
	tagPeeled := "floor"
	if meanPeeled > floor+1 {
		tagPeeled = "STRUCTURED (integral leak after the column peel)"
	}
	fmt.Println(strings.Repeat("-", 96))
	fmt.Printf("  result: mean balanced per set — raw lo %.2f/8 (%s), peeled lo %.2f/8 (%s); floor %.3f\n",
		meanRaw, tagRaw, meanPeeled, tagPeeled, floor)
	fmt.Printf("  recovery: no candidate (structural) — the kappa engine's peel needs the hidden hi lane; residual route 2^64 hi-lane enumeration\n")
	fmt.Printf("  texts consumed: %d over %d sets; wall %.2fs\n", totalTexts, nSetsTotal, wall.Seconds())
}
