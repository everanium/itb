package itb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math"
	mrand "math/rand/v2"
	"testing"
)

// TestNoiseFold3Coverage pins the fold's linear structure: each input
// bit reaches exactly one output bit, and the three output bits draw on
// 32, 16 and 16 input bits.
func TestNoiseFold3Coverage(t *testing.T) {
	var counts [3]int
	for i := 0; i < 64; i++ {
		out := noiseFold3(uint64(1) << i)
		hit := 0
		for b := 0; b < 3; b++ {
			if out>>b&1 == 1 {
				counts[b]++
				hit++
			}
		}
		if hit != 1 {
			t.Fatalf("input bit %d reaches %d output bits, want 1", i, hit)
		}
	}
	if counts != [3]int{32, 16, 16} {
		t.Fatalf("output bit fan-in = %v, want [32 16 16]", counts)
	}
}

// TestNoiseFold3Uniform checks that uniform input words give a uniform
// position over [0, 8).
func TestNoiseFold3Uniform(t *testing.T) {
	const n = 1 << 18
	r := mrand.New(mrand.NewPCG(1, 2))
	var hist [8]int
	for i := 0; i < n; i++ {
		v := noiseFold3(r.Uint64())
		if v > 7 {
			t.Fatalf("position %d out of range", v)
		}
		hist[v]++
	}
	exp := float64(n) / 8
	sigma := math.Sqrt(exp * 7 / 8)
	for v, c := range hist {
		if math.Abs(float64(c)-exp) > 6*sigma {
			t.Fatalf("position %d count %d, expected %.0f ± %.0f", v, c, exp, 6*sigma)
		}
	}
}

// regionNoisePositions returns the noise positions of steps [0, n) of a
// region whose noise-hash counter starts at base.
func regionNoisePositions(noiseSeed *Seed128, nonce []byte, base, n int) []uint {
	buf := make([]byte, 4+len(nonce))
	copy(buf[4:], nonce)
	out := make([]uint, n)
	for p := 0; p < n; p++ {
		lo, hi := noiseSeed.blockHash128(buf, base+p)
		out[p] = noisePosition(lo, hi)
	}
	return out
}

// maxCyclicShiftMatch returns the highest fraction of equal positions
// between a and b over every cyclic relative shift. Cyclic, because a
// region's pixels start at a secret offset and wrap around the region.
func maxCyclicShiftMatch(a, b []uint) float64 {
	n := len(a)
	best := 0.0
	for s := 0; s < n; s++ {
		eq := 0
		for p := 0; p < n; p++ {
			if a[p] == b[(p+s)%n] {
				eq++
			}
		}
		if f := float64(eq) / float64(n); f > best {
			best = f
		}
	}
	return best
}

// TestNoisePositionRegionsIndependent guards the property the noise
// counter base exists to provide: the three regions share the noise
// seed, yet their position sequences must not be shifts of one another.
// A matching shift would let an attacker who learns per-pixel noise
// positions (bit flips under a revealing MAC oracle) align the regions
// and recover their start offsets.
//
// The negative control starts every region's counter at 0 and shows the
// detector sees the full alignment that layout produces.
func TestNoisePositionRegionsIndependent(t *testing.T) {
	const third = 1024

	noiseSeed, err := NewSeed128(1024, sipHash128)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ctl := [2][]uint{
		regionNoisePositions(noiseSeed, nonce, 0, third),
		regionNoisePositions(noiseSeed, nonce, 0, third),
	}
	if f := maxCyclicShiftMatch(ctl[0], ctl[1]); f != 1 {
		t.Fatalf("negative control: shared-counter match fraction %.3f, want 1", f)
	}

	var seqs [3][]uint
	for i := range seqs {
		seqs[i] = regionNoisePositions(noiseSeed, nonce, noiseCounterBase(i, third), third)
	}
	// Independent sequences match at 1/8 per step (sigma about 0.01 at
	// this length); 0.2 sits far above the chance maximum over all
	// shifts and far below an alignment.
	const limit = 0.2
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			if f := maxCyclicShiftMatch(seqs[i], seqs[j]); f > limit {
				t.Fatalf("regions %d and %d align: match fraction %.3f > %.2f", i, j, f, limit)
			}
		}
	}
}

// cobsLaneValid reports whether decoded carries a COBS-framed lane: a
// terminator, and a prefix that round-trips through COBS unchanged.
func cobsLaneValid(decoded []byte) bool {
	fn := bytes.IndexByte(decoded, 0x00)
	if fn <= 0 {
		return false
	}
	stream := decoded[:fn]
	dec := cobsDecodeInto(make([]byte, fn), stream)
	return bytes.Equal(cobsEncodeInto(make([]byte, cobsEncodeBound(len(dec))), dec), stream)
}

// TestNoiseCounterBaseWiring checks that the encrypt path applies the
// per-region noise counter base: each region of a real wire decodes to
// a COBS-framed lane under its own base, and the second and third
// regions decode to different bytes under base 0. A wiring that left
// every region at base 0 would fail the first check on those regions.
func TestNoiseCounterBaseWiring(t *testing.T) {
	cfg := &Config{NonceBits: 128}
	var s [8]*Seed128
	for i := range s {
		var err error
		if s[i], err = NewSeed128(1024, sipHash128); err != nil {
			t.Fatal(err)
		}
	}
	plain := bytes.Repeat([]byte("noise counter base wiring "), 64)
	nonceLen := currentNonceSizeCfg(cfg)

	for trial := 0; trial < 8; trial++ {
		wire, err := Encrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
		if err != nil {
			t.Fatal(err)
		}
		body := wire[streamIDPrefixLen:]
		nonce := body[:nonceLen]
		width := int(binary.BigEndian.Uint16(body[nonceLen:]))
		height := int(binary.BigEndian.Uint16(body[nonceLen+2:]))
		container := body[nonceLen+4:]
		third, thirdPixels2, caps := tripleThirdCaps(width * height)
		widths := [3]int{third, third, thirdPixels2}
		offs := [4]int{0, third * Channels, 2 * third * Channels, (2*third + thirdPixels2) * Channels}
		data := [3]*Seed128{s[2], s[3], s[4]}
		start := [3]*Seed128{s[5], s[6], s[7]}

		decode := func(i, base int) []byte {
			region := bytes.Clone(container[offs[i]:offs[i+1]])
			out := make([]byte, caps[i])
			process128Cfg(cfg, s[0], data[i], start[i], nonce, region, widths[i], 1, out, false, 1, base)
			return out
		}
		for i := 0; i < 3; i++ {
			own := decode(i, noiseCounterBase(i, third))
			if !cobsLaneValid(own) {
				t.Fatalf("trial %d region %d: no COBS lane under its own noise counter base", trial, i)
			}
			if i > 0 && bytes.Equal(own, decode(i, 0)) {
				t.Fatalf("trial %d region %d: base 0 decodes identically to base %d", trial, i, noiseCounterBase(i, third))
			}
		}
	}
}

// TestNoisePositionRelatedLanes guards noiseMix: a primitive whose two
// output words are related by identity, complement or a constant XOR
// must still yield a uniform position over all eight values. The
// negative control folds the plain XOR of the two words, which cancels
// to a constant under every one of those relations.
func TestNoisePositionRelatedLanes(t *testing.T) {
	const n = 4096
	r := mrand.New(mrand.NewPCG(3, 4))
	c := r.Uint64()
	relations := map[string]func(lo uint64) uint64{
		"identity":   func(lo uint64) uint64 { return lo },
		"complement": func(lo uint64) uint64 { return ^lo },
		"xor const":  func(lo uint64) uint64 { return lo ^ c },
	}
	for name, rel := range relations {
		var mixed, plain [8]int
		for i := 0; i < n; i++ {
			lo := r.Uint64()
			hi := rel(lo)
			mixed[noisePosition(lo, hi)]++
			plain[noiseFold3(lo^hi)]++
		}
		distinct := func(h [8]int) int {
			k := 0
			for _, v := range h {
				if v > 0 {
					k++
				}
			}
			return k
		}
		if d := distinct(plain); d != 1 {
			t.Fatalf("%s: negative control: plain-XOR fold takes %d values, want 1", name, d)
		}
		if d := distinct(mixed); d != 8 {
			t.Fatalf("%s: noisePosition takes %d of 8 values", name, d)
		}
		exp := float64(n) / 8
		for v, k := range mixed {
			if math.Abs(float64(k)-exp) > 6*math.Sqrt(exp*7/8) {
				t.Fatalf("%s: position %d count %d, expected %.0f", name, v, k, exp)
			}
		}
	}
}
