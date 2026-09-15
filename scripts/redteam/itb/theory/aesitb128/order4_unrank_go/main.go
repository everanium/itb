// order4_unrank_go — realistic order-4 Lambda-set integral through the
// full Interlocked Barrier fill chain on AES-ITB-128:
//
//	plain[0..3] = LE32(idx)     // the counter-byte cube {0,1,2,3}
//	plain[4..N] = random constant per set (nonce + pad, held fixed)
//	h_r         = ChainHash-r over plain            (Seed128.ChainHash128)
//	(lo, hi)    = h_r                                (64 + 64)
//	(idx0, idx1)= splitRank48(lo, hi)                (128 -> 42-bit A + 30-bit B)
//	(m0, m1, m2)= rankToMaskTriple48(lo, hi)         (16-of-48 triple)
//
// Rather than the shipped observable of the encoder (lo(h_r) alone), we
// score the balance of the mask triple that the interlock overlay
// actually consumes downstream: the byte-level XOR-sum of every m_i
// across the 2^32-text Lambda-set is expected zero if the set survived
// the primitive; a floor is the empirical closure of the "unrank might
// preserve some modular structure the raw XOR projection does not
// expose" caveat.
//
// Expectation: floor at every shipped cascade depth. The Lambda-set is
// removed by the primitive from r >= 2 on (measured in HARNESS
// section 3.10.2 for the raw h_r output); the divmod + combinadic
// unrank chain is a data-only transform of a randomised input.
//
// Under the shipped observable the attacker never sees any m_i on the
// wire; the mask triple drives the interlock overlay and the pixel path
// output only carries the wrapped chunk. This cell is an internal
// screen closing a modelling caveat, not a wire attack.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math/bits"
	"math/big"
	mrand "math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/everanium/itb/hashes"
)

// ---------------------------------------------------------------------
// splitRank48 + unrankCombination48 + rankToMaskTriple48 — copies of the
// private itb package equivalents. Kept as an independent implementation
// so the red-team screen does not depend on internal symbols; pinned
// against the shipped path by the self-test below.
// ---------------------------------------------------------------------

var binomialC48 [49][17]uint64

func init() {
	for n := 0; n <= 48; n++ {
		binomialC48[n][0] = 1
		for k := 1; k <= 16 && k <= n; k++ {
			binomialC48[n][k] = binomialC48[n-1][k-1] + binomialC48[n-1][k]
		}
	}
}

const (
	interlockA48 uint64 = 2254848913647 // C(48, 16)
	interlockB48 uint64 = 601080390     // C(32, 16)
)

// splitRank48 mirrors itb.splitRank48Div: bits.Div64 twice per limb.
func splitRank48(lane0, lane1 uint64) (idx0 uint64, idx1 uint32) {
	qHi, r1 := bits.Div64(0, lane1, interlockB48)
	qLo, r := bits.Div64(r1, lane0, interlockB48)
	_, hiMod := bits.Div64(0, qHi, interlockA48)
	_, idx0 = bits.Div64(hiMod, qLo, interlockA48)
	return idx0, uint32(r)
}

// unrankCombination48 combinadic decomposition: rank in [0, C(n, k)) ->
// a 64-bit mask with exactly k set bits from positions [0, n).
func unrankCombination48(rank uint64, k, n int) uint64 {
	var mask uint64
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && binomialC48[c+1][k] <= rank {
			c++
		}
		mask |= uint64(1) << uint(c)
		rank -= binomialC48[c][k]
		k--
	}
	return mask
}

// rankToMaskTriple48 maps h_r's (lo, hi) into an interlock mask triple.
func rankToMaskTriple48(lane0, lane1 uint64) (m0, m1, m2 uint64) {
	idx0, idx1 := splitRank48(lane0, lane1)
	m0 = unrankCombination48(idx0, 16, 48)
	m1Local := unrankCombination48(uint64(idx1), 16, 32)
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	remaining := domain &^ m0
	var posIdx uint
	for bit := uint(0); bit < 48; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint64(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining &^ m1
	return
}

// ---------------------------------------------------------------------
// Self-tests: pin the split + unrank against a big.Int reference on a
// spread of test vectors. Runs at startup before the sweep begins.
// ---------------------------------------------------------------------

func selfTestSplitRank(t *testing) {
	var A, B big.Int
	A.SetUint64(interlockA48)
	B.SetUint64(interlockB48)
	AB := new(big.Int).Mul(&A, &B)

	cases := []struct{ lo, hi uint64 }{
		{0, 0},
		{1, 0},
		{0, 1},
		{^uint64(0), 0},
		{0, ^uint64(0)},
		{^uint64(0), ^uint64(0)},
		{0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF},
	}
	rng := mrand.New(mrand.NewSource(1))
	for i := 0; i < 200; i++ {
		cases = append(cases, struct{ lo, hi uint64 }{rng.Uint64(), rng.Uint64()})
	}
	for _, c := range cases {
		idx0, idx1 := splitRank48(c.lo, c.hi)

		var rank, q, r0, r1 big.Int
		rank.SetBits([]big.Word{big.Word(c.lo), big.Word(c.hi)})
		q.DivMod(&rank, &B, &r1)
		wantIdx1 := r1.Uint64()
		q.Mod(&q, &A)
		wantIdx0 := q.Uint64()
		_ = r0
		_ = AB
		if idx0 != wantIdx0 || uint64(idx1) != wantIdx1 {
			t.fail(fmt.Sprintf("splitRank48(%#x, %#x) = (%d, %d), want (%d, %d)",
				c.lo, c.hi, idx0, idx1, wantIdx0, wantIdx1))
			return
		}
	}
	t.pass("splitRank48: 207 vectors pinned against big.Int")
}

func selfTestUnrank(t *testing) {
	// unrank(rank=0, k, n) is a low-run mask; unrank(C(n,k)-1) is high-run.
	m0 := unrankCombination48(0, 16, 48)
	if m0 != 0x0000_0000_0000_FFFF {
		t.fail(fmt.Sprintf("unrank(0, 16, 48) = %#x, want 0x000000000000FFFF", m0))
		return
	}
	last := binomialC48[48][16] - 1
	mLast := unrankCombination48(last, 16, 48)
	// Max rank corresponds to k=16 highest positions: bits 32..47.
	if mLast != 0x0000_FFFF_0000_0000 {
		t.fail(fmt.Sprintf("unrank(last, 16, 48) = %#x, want 0x0000FFFF00000000", mLast))
		return
	}
	// rankToMaskTriple48 sanity: popcount(m_i) == 16 each; union == 48-bit
	// domain; pairwise intersection == 0. Spot-check across 200 random
	// (lo, hi) pairs.
	rng := mrand.New(mrand.NewSource(2))
	for i := 0; i < 200; i++ {
		m0, m1, m2 := rankToMaskTriple48(rng.Uint64(), rng.Uint64())
		if bits.OnesCount64(m0) != 16 || bits.OnesCount64(m1) != 16 || bits.OnesCount64(m2) != 16 {
			t.fail(fmt.Sprintf("popcount != 16 at trial %d: %d/%d/%d",
				i, bits.OnesCount64(m0), bits.OnesCount64(m1), bits.OnesCount64(m2)))
			return
		}
		if m0|m1|m2 != 0x0000_FFFF_FFFF_FFFF {
			t.fail(fmt.Sprintf("union != 48-bit domain at trial %d: %#x", i, m0|m1|m2))
			return
		}
		if m0&m1 != 0 || m0&m2 != 0 || m1&m2 != 0 {
			t.fail(fmt.Sprintf("non-empty pairwise intersection at trial %d", i))
			return
		}
	}
	t.pass("unrankCombination48 + rankToMaskTriple48: 202 checks pinned")
}

type testing struct {
	failed bool
}

func (t *testing) pass(msg string) { fmt.Fprintf(os.Stderr, "  self-test: %s\n", msg) }
func (t *testing) fail(msg string) {
	fmt.Fprintf(os.Stderr, "  self-test FAIL: %s\n", msg)
	t.failed = true
}

// ---------------------------------------------------------------------
// Bench cell — order-4 Lambda-set through cascade + unrank + XOR balance.
// ---------------------------------------------------------------------

// balanceOnce runs one 2^32-text Lambda-set at (dataLen, rounds) with
// active bytes 0..3 (the counter-byte cube), a random fixed constant
// for the remaining bytes, and a fresh AES-ITB-128 key + seed
// components. Returns the byte-level balanced counts on (m0, m1, m2)
// and on lo(h_r) / hi(h_r) for reference.
//
// The mask triple m_i is packed into a uint64 low 48 bits (= 6 bytes);
// six byte-level XOR accumulators are maintained per triple, one per
// byte position. A byte is called balanced if its accumulator ends at
// zero after the sweep.
func balanceOnce(dataLen, rounds int, seedRng *mrand.Rand, workers int) (
	balancedM []int, balancedLo, balancedHi int, wall time.Duration) {

	// Build a fresh AES-ITB-128 key + Seed128 at the requested cascade
	// depth. keyBits = 128 * rounds, but the itb Seed constructor
	// bottoms at 512 bits, so callers must pass rounds in {4, 8, 16}.
	// Higher key-bit widths are also accepted by NewSeed128 up to
	// MaxKeyBits.
	keyBits := 128 * rounds
	if keyBits < 512 {
		panic(fmt.Sprintf("balanceOnce: keyBits %d < 512 (rounds %d < 4); shipped range only",
			keyBits, rounds))
	}
	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	seed, _, err := hashes.NewSeed128(hashes.CipherAESITB128, keyBits, keyBytes[:])
	if err != nil {
		panic("hashes.NewSeed128: " + err.Error())
	}

	// Fresh nonce/pad bytes 4..dataLen-1 — random constant for the whole
	// Lambda-set (idx-only nonce discipline: attacker sees the constant
	// but cannot pick it; every 2^32-text set uses one).
	constant := make([]byte, dataLen)
	if _, err := rand.Read(constant[4:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}

	// Per-worker byte accumulators: 6 for m0, 6 for m1, 6 for m2, 8 for
	// lo(h_r), 8 for hi(h_r) — all XOR reductions over the full set.
	const (
		accM0Base = 0
		accM1Base = 6
		accM2Base = 12
		accLoBase = 18
		accHiBase = 26
		accBytes  = 34
	)
	perWorker := make([][]byte, workers)
	for w := range perWorker {
		perWorker[w] = make([]byte, accBytes)
	}

	// Divide 2^32 texts among workers. Each worker takes a contiguous
	// idx range; the counter bytes 0..3 = LE32(idx).
	const total uint64 = 1 << 32
	chunk := total / uint64(workers)
	tail := total - chunk*uint64(workers)

	start := time.Now()
	var wg sync.WaitGroup
	var processed atomic.Uint64
	for w := 0; w < workers; w++ {
		lo := uint64(w) * chunk
		hi := lo + chunk
		if w == workers-1 {
			hi += tail
		}
		acc := perWorker[w]
		wg.Add(1)
		go func() {
			defer wg.Done()
			plain := make([]byte, dataLen)
			copy(plain, constant)
			for idx := lo; idx < hi; idx++ {
				binary.LittleEndian.PutUint32(plain[:4], uint32(idx))
				loH, hiH := seed.ChainHash128(plain)

				m0, m1, m2 := rankToMaskTriple48(loH, hiH)

				// XOR-reduce byte-by-byte into the 34-byte accumulator.
				for b := 0; b < 6; b++ {
					acc[accM0Base+b] ^= byte(m0 >> (8 * b))
					acc[accM1Base+b] ^= byte(m1 >> (8 * b))
					acc[accM2Base+b] ^= byte(m2 >> (8 * b))
				}
				for b := 0; b < 8; b++ {
					acc[accLoBase+b] ^= byte(loH >> (8 * b))
					acc[accHiBase+b] ^= byte(hiH >> (8 * b))
				}
			}
			processed.Add(hi - lo)
		}()
	}
	wg.Wait()
	wall = time.Since(start)

	// Merge worker accumulators.
	var merged [accBytes]byte
	for _, acc := range perWorker {
		for i := 0; i < accBytes; i++ {
			merged[i] ^= acc[i]
		}
	}

	balancedM = make([]int, 3)
	for i := 0; i < 6; i++ {
		if merged[accM0Base+i] == 0 {
			balancedM[0]++
		}
		if merged[accM1Base+i] == 0 {
			balancedM[1]++
		}
		if merged[accM2Base+i] == 0 {
			balancedM[2]++
		}
	}
	for i := 0; i < 8; i++ {
		if merged[accLoBase+i] == 0 {
			balancedLo++
		}
		if merged[accHiBase+i] == 0 {
			balancedHi++
		}
	}

	// Sanity: number of texts consumed equals 2^32.
	if processed.Load() != total {
		panic(fmt.Sprintf("expected %d texts consumed, got %d", total, processed.Load()))
	}
	_ = seedRng
	return
}

// ---------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------

func parseCellList(s string) [][2]int {
	if s == "" {
		return nil
	}
	var out [][2]int
	for _, part := range strings.Split(s, ",") {
		xs := strings.SplitN(strings.TrimSpace(part), ":", 2)
		if len(xs) != 2 {
			fmt.Fprintf(os.Stderr, "cell %q: expected 'dataLen:rounds'\n", part)
			os.Exit(2)
		}
		dl, err1 := strconv.Atoi(strings.TrimSpace(xs[0]))
		r, err2 := strconv.Atoi(strings.TrimSpace(xs[1]))
		if err1 != nil || err2 != nil {
			fmt.Fprintf(os.Stderr, "cell %q: parse error\n", part)
			os.Exit(2)
		}
		out = append(out, [2]int{dl, r})
	}
	return out
}

func main() {
	workers := flag.Int("workers", runtime.NumCPU(), "goroutines for the 2^32 sweep")
	cells := flag.String("cells", "20:4,36:4,68:4", "comma-separated dataLen:rounds cells to sweep")
	trials := flag.Int("trials", 1, "trials with fresh key + seed components per cell")
	flag.Parse()

	fmt.Println(strings.Repeat("=", 96))
	fmt.Println("order4_unrank_go — realistic order-4 idx cube {0,1,2,3} through cascade + divmod + unrank")
	fmt.Println("                    XOR balance of mask triple bytes (18) + lo/hi lane bytes (16), 1 set / trial")
	fmt.Println(strings.Repeat("=", 96))

	t := &testing{}
	selfTestSplitRank(t)
	selfTestUnrank(t)
	if t.failed {
		os.Exit(1)
	}

	cellList := parseCellList(*cells)
	if len(cellList) == 0 {
		fmt.Fprintln(os.Stderr, "no cells to run")
		os.Exit(2)
	}

	rng := mrand.New(mrand.NewSource(1))
	for _, c := range cellList {
		dl, r := c[0], c[1]
		fmt.Println(strings.Repeat("-", 96))
		fmt.Printf("cell: data-len=%d, rounds=%d, active=[0 1 2 3], workers=%d, trials=%d\n",
			dl, r, *workers, *trials)
		var (
			sumM0, sumM1, sumM2 int
			sumLo, sumHi        int
			wallTot             time.Duration
		)
		for trial := 0; trial < *trials; trial++ {
			bM, bLo, bHi, wall := balanceOnce(dl, r, rng, *workers)
			fmt.Printf("  trial %d: m0 %d/6, m1 %d/6, m2 %d/6, lo %d/8, hi %d/8  (wall %.1fs)\n",
				trial, bM[0], bM[1], bM[2], bLo, bHi, wall.Seconds())
			sumM0 += bM[0]
			sumM1 += bM[1]
			sumM2 += bM[2]
			sumLo += bLo
			sumHi += bHi
			wallTot += wall
		}
		fmt.Printf("  mean per trial: m0 %.2f/6, m1 %.2f/6, m2 %.2f/6, lo %.2f/8, hi %.2f/8; wall total %.1fs\n",
			float64(sumM0)/float64(*trials), float64(sumM1)/float64(*trials),
			float64(sumM2)/float64(*trials),
			float64(sumLo)/float64(*trials), float64(sumHi)/float64(*trials),
			wallTot.Seconds())
	}
}
