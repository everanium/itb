package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/wrapper"
)

// innerHash is the registry primitive the measurements run under.
// Container geometry depends on byte lengths alone — payload, COBS
// framing, interlock-nonce fragments, the MinPixels floor — never on
// the primitive's output, so any 512-bit-wide registry entry yields
// the same sides and wire sizes. One entry is pinned so a run is
// reproducible.
const innerHash = "areion512"

// narrowestWidth is the narrowest native width in bits across the
// shipped registry; the ChainHash cascade depth the documentation quotes
// per key size (keyBits / width) is stated at this width when no width
// is named.
var narrowestWidth = func() int {
	n := 0
	for _, s := range hashes.Registry {
		if w := int(s.Width); n == 0 || w < n {
			n = w
		}
	}
	return n
}()

// shippedWidths are the native widths, in bits, the shipped registry
// covers, ascending.
var shippedWidths = func() []int {
	seen := map[int]bool{}
	for _, s := range hashes.Registry {
		seen[int(s.Width)] = true
	}
	var out []int
	for w := 128; w <= 512; w *= 2 {
		if seen[w] {
			out = append(out, w)
		}
	}
	return out
}()

// Key sizes the documentation tabulates, in canonical order.
var keySizes = []int{512, 1024, 2048}

// Container floor sizing modes: 1 = per-region, 2 = per-container.
var modes = []int{1, 2}

// Landauer bound on irreversible enumeration, as SCIENCE.md § 4
// derives it: erasing one bit at the cosmic microwave background
// temperature costs `k_B T ln 2`, and a mass-energy budget of
// ~4 × 10^69 J bounds the number of irreversible operations at
// `4 × 10^69 / (k_B T ln 2)`. Physical reference values, not
// construction parameters.
const (
	boltzmann    = 1.380649e-23 // J/K, exact by the 2019 SI definition of the kelvin
	cmbKelvin    = 2.7          // K, as the documentation rounds the CMB temperature
	energyBudget = 4e69         // J
)

// landauerBitCost is `k_B T ln 2` at the CMB temperature, in joules.
var landauerBitCost = boltzmann * cmbKelvin * math.Ln2

// landauerOps is the operation bound `energyBudget / landauerBitCost`.
var landauerOps = energyBudget / landauerBitCost

// landauerExp is log₂ landauerOps rounded to the integer exponent the
// documentation states (~2^306).
var landauerExp = int(math.Round(math.Log2(landauerOps)))

// payloadSizes are the data-size rows the documentation reports
// container geometry for, at a 1024-bit key under Mode 1. The MB-labelled
// rows mean MiB.
var payloadSizes = []struct {
	label string
	n     int
}{
	{"1460 B", 1460},
	{"10 KB", 10000},
	{"16 KiB", 16 << 10},
	{"64 KiB", 64 << 10},
	{"1 MiB", 1 << 20},
	{"4 MiB", 4 << 20},
	{"16 MiB", 16 << 20},
	{"64 MiB", 64 << 20},
}

// Container describes one measured Single Message container: the
// container side, the pixel count, and the Single Message wire length
// at the smallest payload.
type Container struct {
	Side  int
	P     int
	Wire  int
	Nonce int // main-nonce bytes N
}

// FloorFigures carries the floor-container figures for one (key size,
// mode) pair. Residue figures follow Proof 10 (PROOFS.md): with
// container `(s+1) × (s+1)` the guaranteed DRBG fill is
// `≥ (2s + 1) × 7` bytes, and `(P − floorPixels) × 7` bytes at the
// exact pixel floor.
type FloorFigures struct {
	Container
	FloorPixels    int // 3 × MinPixels (Mode 1) or MinPixels (Mode 2)
	RawSquare      int // ⌈√floorPixels⌉, the side before the barrier margin
	MaxPayload     int // largest payload that still fits the floor container
	Residue        int // (2s + 1) × 7 with s = Side − 1
	ResidueAtFloor int // (P − FloorPixels) × 7
}

// SizeRow is one data-size row: the container geometry at a payload of
// n bytes under a 1024-bit key, Mode 1.
type SizeRow struct {
	Label string
	N     int
	Container
	Residue int // (2s + 1) × 7 with s = Side − 1
}

// Figures holds every computed figure. Measured values come from the
// public Encrypt API; formula values implement the documented formula
// once, with the source section named at the computation site.
type Figures struct {
	NonceBits   int
	NonceBytes  int
	BarrierFill int
	Prefix      int // stream prefix bytes, derived from the measured wire
	HeaderSize  int // N + 4 at the default nonce width

	// HeaderSizes maps nonce width in bits to the chunk header size N + 4,
	// which is also the per-pixel absorb-buffer shape the kernels name.
	HeaderSizes map[int]int

	MinPixels      map[int]int // CCA floor ⌈keyBits / log₂ 7⌉, from the library
	ThresholdNoCCA map[int]int // ⌈keyBits / log₂ 56⌉ (Proof 9)

	Floor map[int]map[int]FloorFigures // [keyBits][mode]

	// Theoretical single-region floor at each key size: `s = ⌈√MinPixels⌉ − 1`,
	// container `(s+1)²` (SCIENCE.md § 2.9, § 3.4). Not a shipped shape.
	Theoretical map[int]FloorFigures

	// MTU512 is the 512-bit-key Mode 2 container at a 1460-byte payload.
	MTU512 Container

	Sizes []SizeRow // at 1024-bit, Mode 1

	// Expansion range (wire / payload) over the payload interval
	// [expansionFrom, MaxMessage] at 1024-bit, Mode 1; see expansionRange.
	ExpansionMax    float64
	ExpansionMaxAt  int     // payload at which ExpansionMax occurs
	ExpansionMin    float64 // lower bound on the interval minimum
	ExpansionMinEnd float64 // ratio at MaxMessage, an upper bound on it

	MaxMessage       int // largest payload a Single Message accepts
	DefaultChunkSize int

	// Rank Barrier mask-space constants (Proof 11 / Proof 12).
	A, B, AB     *big.Int
	Log2A, Log2B float64
	Log2AB       float64
	GCD          *big.Int
	GCDFactors   string
	Log2GCD      float64
	Preimages    *big.Int // ⌊2^128 / (A · B)⌋
	Log2Preimage float64
	MaxChunks    int     // ⌈(4 + MaxMessage) × 8 / 48⌉
	Log2Chunks   float64 // log₂ MaxChunks
	AccumBias    float64 // Log2Chunks − Log2Preimage
	SampleBudget float64 // 2 × Log2Preimage
	Log2Messages float64 // SampleBudget − Log2Chunks

	// Wrapper nonce sizes per outer cipher, measured as the wire delta
	// of wrapper.Wrap over the raw wire.
	WrapperNonce map[string]int
}

// Compute measures and derives every figure at the compiled-in defaults.
func Compute() (*Figures, error) {
	f := &Figures{
		NonceBits:        itb.DefaultNonceBits,
		NonceBytes:       itb.DefaultNonceBits / 8,
		BarrierFill:      itb.DefaultBarrierFill,
		HeaderSizes:      map[int]int{},
		MinPixels:        map[int]int{},
		ThresholdNoCCA:   map[int]int{},
		Floor:            map[int]map[int]FloorFigures{},
		Theoretical:      map[int]FloorFigures{},
		DefaultChunkSize: itb.DefaultChunkSize,
		WrapperNonce:     map[string]int{},
	}

	hashFn, batchFn, _, err := hashes.Make512Pair(innerHash)
	if err != nil {
		return nil, err
	}
	for _, k := range keySizes {
		seeds, err := newSeeds(k, hashFn, batchFn)
		if err != nil {
			return nil, err
		}
		f.MinPixels[k] = seeds[0].MinPixels()
		// Proof 9: ambiguity dominance without CCA at `56^P > 2^k`, i.e.
		// `P > k / log₂ 56`; the smallest integer satisfying it.
		f.ThresholdNoCCA[k] = int(math.Ceil(float64(k) / math.Log2(56)))

		f.Floor[k] = map[int]FloorFigures{}
		for _, mode := range modes {
			ff, err := measureFloor(f, seeds, mode)
			if err != nil {
				return nil, fmt.Errorf("key %d mode %d: %w", k, mode, err)
			}
			f.Floor[k][mode] = ff
		}
		f.Theoretical[k] = theoreticalFloor(f.MinPixels[k])

		if k == 512 {
			c, err := measure(f, seeds, 2, 1460)
			if err != nil {
				return nil, err
			}
			f.MTU512 = c
		}
		if k == 1024 {
			for _, ps := range payloadSizes {
				c, err := measure(f, seeds, 1, ps.n)
				if err != nil {
					return nil, fmt.Errorf("payload %s: %w", ps.label, err)
				}
				f.Sizes = append(f.Sizes, SizeRow{Label: ps.label, N: ps.n, Container: c, Residue: (2*(c.Side-1) + 1) * itb.DataBitsPerChannel})
			}
			// The largest accepted payload: the 64 MiB row above encrypts,
			// one byte more must be refused by the size guard.
			if _, err := encrypt(seeds, 1, f.NonceBits, make([]byte, 64<<20+1)); err == nil {
				return nil, errors.New("a 64 MiB + 1 byte payload was accepted; the message size limit moved")
			}
			f.MaxMessage = 64 << 20
			if err := f.expansionRange(seeds, size64MiB(f.Sizes)); err != nil {
				return nil, fmt.Errorf("expansion range: %w", err)
			}
			// Chunk header per nonce width, read off the wire.
			for bits := 128; bits <= 512; bits *= 2 {
				h, err := headerAt(f, seeds, bits)
				if err != nil {
					return nil, fmt.Errorf("header at %d-bit nonce: %w", bits, err)
				}
				f.HeaderSizes[bits] = h
			}
		}
	}

	f.HeaderSize = f.HeaderSizes[f.NonceBits]

	f.rankBarrier()

	if err := f.wrapperNonces(); err != nil {
		return nil, err
	}
	return f, nil
}

// newSeeds draws the 8-seed constellation at the given key width.
func newSeeds(bits int, h itb.HashFunc512, b itb.BatchHashFunc512) ([8]*itb.Seed512, error) {
	var out [8]*itb.Seed512
	for i := range out {
		s, err := itb.NewSeed512(bits, h)
		if err != nil {
			return out, err
		}
		s.BatchHash = b
		out[i] = s
	}
	return out, nil
}

func encrypt(s [8]*itb.Seed512, mode, nonceBits int, data []byte) ([]byte, error) {
	cfg := &itb.Config{Mode: mode, NonceBits: nonceBits}
	return itb.Encrypt3x512Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], data)
}

// measure encrypts n bytes and reads the container geometry back from
// the wire. The header offset is not assumed: the one offset p at which
// `p + N + 4 + 8·W·H` equals the wire length is the stream prefix size,
// so a layout change surfaces here as an error rather than as a wrong
// figure.
func measure(f *Figures, s [8]*itb.Seed512, mode, n int) (Container, error) {
	wire, err := encrypt(s, mode, f.NonceBits, make([]byte, n))
	if err != nil {
		return Container{}, err
	}
	N := f.NonceBytes
	found := -1
	var side int
	for p := 0; p+N+4 <= len(wire); p++ {
		w := int(binary.BigEndian.Uint16(wire[p+N:]))
		h := int(binary.BigEndian.Uint16(wire[p+N+2:]))
		if w == 0 || w != h || p+N+4+w*h*itb.Channels != len(wire) {
			continue
		}
		if found >= 0 {
			return Container{}, fmt.Errorf("ambiguous header offset (%d and %d) in a %d-byte wire", found, p, len(wire))
		}
		found, side = p, w
	}
	if found < 0 {
		return Container{}, fmt.Errorf("no header offset satisfies the wire identity in a %d-byte wire", len(wire))
	}
	if f.Prefix == 0 {
		f.Prefix = found
	} else if f.Prefix != found {
		return Container{}, fmt.Errorf("prefix size %d differs from %d measured on another wire", found, f.Prefix)
	}
	return Container{Side: side, P: side * side, Wire: len(wire), Nonce: N}, nil
}

// measureFloor measures the floor container and bisects for the largest
// payload that still fits it (the wire length is non-decreasing in the
// payload length, so the fit predicate is monotone).
func measureFloor(f *Figures, s [8]*itb.Seed512, mode int) (FloorFigures, error) {
	base, err := measure(f, s, mode, 16)
	if err != nil {
		return FloorFigures{}, err
	}
	lo, hi := 16, 64<<10
	for lo < hi {
		mid := (lo + hi + 1) / 2
		c, err := measure(f, s, mode, mid)
		if err != nil {
			return FloorFigures{}, err
		}
		if c.Side == base.Side {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	minPx := s[0].MinPixels()
	floorPx := minPx
	if mode == 1 {
		floorPx = 3 * minPx
	}
	ff := FloorFigures{
		Container:      base,
		FloorPixels:    floorPx,
		RawSquare:      int(math.Ceil(math.Sqrt(float64(floorPx)))),
		MaxPayload:     lo,
		Residue:        (2*(base.Side-1) + 1) * itb.DataBitsPerChannel,
		ResidueAtFloor: (base.P - floorPx) * itb.DataBitsPerChannel,
	}
	if ff.RawSquare+f.BarrierFill != base.Side {
		return ff, fmt.Errorf("measured side %d is not ⌈√%d⌉ + %d", base.Side, floorPx, f.BarrierFill)
	}
	return ff, nil
}

// expansionFrom is the lower end of the payload interval over which the
// documentation states the bulk expansion range ("~10 KB").
const expansionFrom = 10000

func size64MiB(rows []SizeRow) Container {
	for _, r := range rows {
		if r.N == 64<<20 {
			return r.Container
		}
	}
	return Container{}
}

// expansionRange computes the wire / payload expansion range over the
// payload interval [expansionFrom, MaxMessage] at a 1024-bit key under
// Mode 1. The wire is constant across the payloads that share one
// container side, so within one side band the ratio peaks at the band's
// first payload and bottoms at its last; band-start and band-end ratios
// both fall as the side grows, as the data-size rows show.
//
// Maximum: expansionFrom itself and the band starts above it, each
// located by bisection on the measured side, walked until a band-start
// ratio falls a full published unit (0.01) below the running maximum.
//
// Minimum: the ratio at MaxMessage, and the band just below the one
// holding MaxMessage. That band's last payload is below MaxMessage, so
// its ratio is at least wire(side − 1) / MaxMessage, with wire(side − 1)
// from the wire identity measure establishes. The interval minimum lies
// between that bound (ExpansionMin) and the endpoint ratio
// (ExpansionMinEnd).
func (f *Figures) expansionRange(s [8]*itb.Seed512, top Container) error {
	c, err := measure(f, s, 1, expansionFrom)
	if err != nil {
		return err
	}
	f.ExpansionMax, f.ExpansionMaxAt = float64(c.Wire)/expansionFrom, expansionFrom
	n, side := expansionFrom, c.Side
	for {
		start, sc, err := nextBand(f, s, n, side)
		if err != nil {
			return err
		}
		r := float64(sc.Wire) / float64(start)
		if r > f.ExpansionMax {
			f.ExpansionMax, f.ExpansionMaxAt = r, start
		}
		if r < f.ExpansionMax-0.01 {
			break
		}
		if start >= f.MaxMessage {
			return errors.New("band walk reached the message size limit")
		}
		n, side = start, sc.Side
	}
	f.ExpansionMinEnd = float64(top.Wire) / float64(f.MaxMessage)
	below := f.Prefix + top.Nonce + 4 + (top.Side-1)*(top.Side-1)*itb.Channels
	f.ExpansionMin = math.Min(f.ExpansionMinEnd, float64(below)/float64(f.MaxMessage))
	return nil
}

// nextBand returns the first payload above n whose Mode 1 container side
// exceeds side, with its measured container: a doubling search for an
// upper bracket, then bisection.
func nextBand(f *Figures, s [8]*itb.Seed512, n, side int) (int, Container, error) {
	lo, step := n, 64
	var hc Container
	hi := lo + step
	for {
		c, err := measure(f, s, 1, hi)
		if err != nil {
			return 0, Container{}, err
		}
		if c.Side > side {
			hc = c
			break
		}
		lo, step = hi, step*2
		hi = lo + step
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		c, err := measure(f, s, 1, mid)
		if err != nil {
			return 0, Container{}, err
		}
		if c.Side > side {
			hi, hc = mid, c
		} else {
			lo = mid
		}
	}
	return hi, hc, nil
}

// headerAt encrypts under the given nonce width and reads the chunk
// header size off the wire: past the measured prefix, the one offset q
// at which W = H and `q + 4 + 8·W·H` equals the wire length is the end
// of the main nonce, so the header is `q + 4 − prefix` bytes.
func headerAt(f *Figures, s [8]*itb.Seed512, bits int) (int, error) {
	wire, err := encrypt(s, 1, bits, make([]byte, 16))
	if err != nil {
		return 0, err
	}
	found := -1
	for q := f.Prefix; q+4 <= len(wire); q++ {
		w := int(binary.BigEndian.Uint16(wire[q:]))
		h := int(binary.BigEndian.Uint16(wire[q+2:]))
		if w == 0 || w != h || q+4+w*h*itb.Channels != len(wire) {
			continue
		}
		if found >= 0 {
			return 0, fmt.Errorf("ambiguous header end (%d and %d)", found, q)
		}
		found = q
	}
	if found < 0 {
		return 0, errors.New("no header end satisfies the wire identity")
	}
	return found + 4 - f.Prefix, nil
}

// theoreticalFloor is the single-region floor the documentation contrasts
// the shipped modes with: `s = ⌈√MinPixels⌉ − 1`, container `(s+1)²`.
func theoreticalFloor(minPx int) FloorFigures {
	side := int(math.Ceil(math.Sqrt(float64(minPx))))
	s := side - 1
	return FloorFigures{
		Container:      Container{Side: side, P: side * side},
		FloorPixels:    minPx,
		RawSquare:      side,
		Residue:        (2*s + 1) * itb.DataBitsPerChannel,
		ResidueAtFloor: (side*side - minPx) * itb.DataBitsPerChannel,
	}
}

// rankBarrier derives the Rank Barrier mask-space constants (Proof 11,
// Proof 12): `A = C(48, 16)`, `B = C(32, 16)`, `|Ω_chunk| = A · B`, the
// gcd anti-collapse trap, the PRF-preimage count per mask triple
// `⌊2^128 / (A · B)⌋`, and the bias cascade over a maximum-size message
// (ITB.md § 12): per-chunk bias `2^-log₂(preimages)`, accumulated over
// `⌈(4 + MaxMessage) × 8 / 48⌉` chunks, detectable after `bias^-2`
// chunk samples.
func (f *Figures) rankBarrier() {
	f.A = new(big.Int).Binomial(48, 16)
	f.B = new(big.Int).Binomial(32, 16)
	f.AB = new(big.Int).Mul(f.A, f.B)
	f.Log2A = log2Big(f.A)
	f.Log2B = log2Big(f.B)
	f.Log2AB = log2Big(f.AB)
	f.GCD = new(big.Int).GCD(nil, nil, f.A, f.B)
	f.GCDFactors = factorise(f.GCD.Int64())
	f.Log2GCD = log2Big(f.GCD)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	f.Preimages = new(big.Int).Quo(two128, f.AB)
	f.Log2Preimage = log2Big(f.Preimages)
	f.MaxChunks = ((4+f.MaxMessage)*8 + 47) / 48
	f.Log2Chunks = math.Log2(float64(f.MaxChunks))
	f.AccumBias = f.Log2Chunks - f.Log2Preimage
	f.SampleBudget = 2 * f.Log2Preimage
	f.Log2Messages = f.SampleBudget - f.Log2Chunks
}

// wrapperNonces measures the outer-cipher nonce each wrapper cipher
// prepends, as the wire delta of Wrap over the input.
func (f *Figures) wrapperNonces() error {
	blob := make([]byte, 64)
	for _, name := range wrapper.CipherNames {
		ks, err := wrapper.KeySize(name)
		if err != nil {
			return err
		}
		key := make([]byte, ks)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		out, err := wrapper.Wrap(name, key, blob)
		if err != nil {
			return fmt.Errorf("wrapper %s: %w", name, err)
		}
		f.WrapperNonce[name] = len(out) - len(blob)
	}
	return nil
}

func log2Big(x *big.Int) float64 {
	v, _ := new(big.Float).SetInt(x).Float64()
	return math.Log2(v)
}

// factorise renders n as a product of prime powers in the documentation's
// notation, e.g. "3² · 17 · 19 · 23".
func factorise(n int64) string {
	sup := []rune("⁰¹²³⁴⁵⁶⁷⁸⁹")
	out := ""
	for p := int64(2); p*p <= n; p++ {
		e := 0
		for n%p == 0 {
			n /= p
			e++
		}
		if e == 0 {
			continue
		}
		if out != "" {
			out += " · "
		}
		out += fmt.Sprint(p)
		if e > 1 {
			out += string(sup[e])
		}
	}
	if n > 1 {
		if out != "" {
			out += " · "
		}
		out += fmt.Sprint(n)
	}
	return out
}

// Exponent helpers — every ambiguity figure is a power of two whose
// exponent the documentation rounds to the nearest integer.

// log2Pow returns the exponent of `base^P` as a power of two, rounded.
func log2Pow(base float64, P int) int {
	return int(math.Round(float64(P) * math.Log2(base)))
}

// noiseBarrier is the exponent of the noise barrier `2^(Channels × P)`
// (Proof 5).
func noiseBarrier(P int) int { return itb.Channels * P }

// configMap is the exponent of the per-pixel configuration map space
// `2^((NoiseConfigBits + DataConfigBits) × P)` (SCIENCE.md § 3.4).
func configMap(P int) int { return (itb.NoiseConfigBits + itb.DataConfigBits) * P }

// bruteForce returns the log₂ work factor `P × 2^(m × keyBits)` and the
// Grover bound `√P × 2^(m × keyBits / 2)` for the search of m seeds
// (SECURITY.md § 3 notes [5] and [6]).
func bruteForce(P, keyBits, m int) (classical, grover float64) {
	lp := math.Log2(float64(P))
	return lp + float64(m*keyBits), lp/2 + float64(m*keyBits)/2
}
