package triple

// harness_wire_test.go — construction-level wire-distinguishability harness
// driven through the Triple facade.
//
// These are attacker-realistic wire probes: every statistic is computed from
// bytes an attacker holding the ciphertext already has. No seed, key, or
// plaintext is consulted to steer any measurement.
//
// Layer attribution is the central finding these probes lock down. Two layers
// are toggled independently:
//
//   - itb Triple + 48-bit Interlocked Barrier (always on). Taken alone, its
//     wire is a COBS-framed pixel container whose byte histogram carries a
//     characteristic, publicly-explained signature (an over-representation of
//     the COBS terminator 0x00 and one companion value), not a uniform-random
//     byte law. Entropy stays ≈ 8 bits/byte and the wire is incompressible;
//     the signature is a low-mass, two-value bias that a byte-histogram
//     chi-square detects but that carries no plaintext or key channel.
//   - the outer-cipher wrapper (format-deniability layer). Engaging it whitens
//     the container signature to the finite-sample uniform floor.
//
// The mode-ambiguity claim these probes test is that the AEAD and Non-AEAD
// profiles share one identical container law, so a two-sample test between
// their wire pools cannot separate them — with or without the wrapper.
//
// Statistical loops are gated behind ITB_HARNESS_FULL=1 so the committed suite
// stays fast; the smoke path exercises every code path on a small sample. Set
// ITB_HARNESS_FULL=1 to reproduce the sample sizes recorded in the REDTEAM.md
// creative-probes section.

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"math"
	"os"
	"testing"
)

func harnessFull() bool { return os.Getenv("ITB_HARNESS_FULL") == "1" }

func harnessN(full, smoke int) int {
	if harnessFull() {
		return full
	}
	return smoke
}

// layerOpts returns Opts with parallax forced off and the wrapper set as
// requested, so the measured wire is the barrier-only container (wrapper=false)
// or the format-deniability-wrapped wire (wrapper=true).
func layerOpts(wrapper bool) Opts {
	o := testOpts()
	o.WithParallax = boolPtrHelper(false)
	o.WithWrapper = boolPtrHelper(wrapper)
	return o
}

// --- statistics helpers (attacker-visible byte statistics only) ---

func shannonEntropy(hist *[256]int64, total int64) float64 {
	if total == 0 {
		return 0
	}
	var h float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

func chiSquareUniform(hist *[256]int64, total int64) float64 {
	exp := float64(total) / 256.0
	if exp == 0 {
		return 0
	}
	var c float64
	for _, o := range hist {
		d := float64(o) - exp
		c += d * d / exp
	}
	return c
}

// chiSquareHomogeneity is the two-sample chi-square between two 256-bin byte
// histograms (test of homogeneity — are the two pools drawn from one byte
// law?). df = 255. Two pools carrying the SAME container signature cancel it
// in this statistic and land in-band; a mode-separating artefact would not.
func chiSquareHomogeneity(a, b *[256]int64, na, nb int64) float64 {
	if na == 0 || nb == 0 {
		return 0
	}
	kA := math.Sqrt(float64(nb) / float64(na))
	kB := math.Sqrt(float64(na) / float64(nb))
	var c float64
	for i := 0; i < 256; i++ {
		oa, ob := float64(a[i]), float64(b[i])
		if oa+ob == 0 {
			continue
		}
		d := kA*oa - kB*ob
		c += d * d / (oa + ob)
	}
	return c
}

func lzRatio(t *testing.T, data []byte) float64 {
	t.Helper()
	if len(data) == 0 {
		return 0
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return float64(buf.Len()) / float64(len(data))
}

// zeroDevPct returns the percent over/under-representation of byte value 0x00
// against the uniform expectation — the container-signature witness.
func zeroDevPct(hist *[256]int64, total int64) float64 {
	if total == 0 {
		return 0
	}
	exp := float64(total) / 256.0
	return (float64(hist[0]) - exp) / exp * 100.0
}

// encPool encrypts n random-plaintext messages of the given size under a
// profile at the requested wrapper posture, returning the pooled wire bytes
// (capped for the LZ pass), a byte histogram, and the total byte count.
func encPool(t *testing.T, profile string, wrapper bool, n, plainSize int) ([]byte, *[256]int64, int64) {
	t.Helper()
	pipe, _, err := Init(profile, layerOpts(wrapper))
	if err != nil {
		t.Fatalf("Init(%s): %v", profile, err)
	}
	defer pipe.Close()

	var pool []byte
	var hist [256]int64
	var total int64
	plain := make([]byte, plainSize)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("rand: %v", err)
		}
		wire, err := pipe.EncryptMessage(plain)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		for _, b := range wire {
			hist[b]++
		}
		total += int64(len(wire))
		if len(pool) < 1<<22 {
			pool = append(pool, wire...)
		}
	}
	return pool, &hist, total
}

// ============================================================================
// Probe C1 — cross-profile wire distinguishability (mode ambiguity) +
//            outer-cipher format deniability
// ============================================================================

// TestHarnessC1CrossProfileWireDistinguishability establishes three things at
// once:
//
//   - Positive control: the barrier-only wire (wrapper off) carries a
//     container byte-signature — its byte chi-square is far above the uniform
//     band. This proves the probe is actually sensitive; a trivially-passing
//     probe would be worthless.
//   - Mode ambiguity: the AEAD-vs-Non-AEAD two-sample homogeneity chi-square is
//     in-band, wrapper off AND wrapper on. The modes share one container law;
//     the wire does not betray whether a MAC is present.
//   - Format deniability: engaging the outer-cipher wrapper pulls each mode's
//     byte chi-square back into the uniform band — the wrapper is the layer
//     that delivers wire-level indistinguishability from random.
//
// Entropy stays ≈ 8 bits/byte and the wire is incompressible in every posture:
// the container signature is a low-mass two-value bias, not a structural leak.
func TestHarnessC1CrossProfileWireDistinguishability(t *testing.T) {
	n := harnessN(8_000, 300)
	const plainSize = 256

	_, aeadOffH, aeadOffN := encPool(t, ProfileStreamingAEADTripleMACV1, false, n, plainSize)
	poolNoMACoff, nomacOffH, nomacOffN := encPool(t, ProfileStreamingNoAEADTripleV1, false, n, plainSize)
	poolAEADon, aeadOnH, aeadOnN := encPool(t, ProfileStreamingAEADTripleMACV1, true, n, plainSize)
	_, nomacOnH, nomacOnN := encPool(t, ProfileStreamingNoAEADTripleV1, true, n, plainSize)

	chiAEADoff := chiSquareUniform(aeadOffH, aeadOffN)
	chiNoMACoff := chiSquareUniform(nomacOffH, nomacOffN)
	chiAEADon := chiSquareUniform(aeadOnH, aeadOnN)
	chiNoMACon := chiSquareUniform(nomacOnH, nomacOnN)

	homogOff := chiSquareHomogeneity(aeadOffH, nomacOffH, aeadOffN, nomacOffN)
	homogOn := chiSquareHomogeneity(aeadOnH, nomacOnH, aeadOnN, nomacOnN)

	entNoMACoff := shannonEntropy(nomacOffH, nomacOffN)
	entAEADon := shannonEntropy(aeadOnH, aeadOnN)
	lzNoMACoff := lzRatio(t, poolNoMACoff)
	lzAEADon := lzRatio(t, poolAEADon)

	t.Logf("C1 barrier-only (wrapper off): chi2 AEAD=%.1f NoMAC=%.1f | 0x00dev AEAD=%.2f%% NoMAC=%.2f%% | entropy(NoMAC)=%.5f lz(NoMAC)=%.4f",
		chiAEADoff, chiNoMACoff, zeroDevPct(aeadOffH, aeadOffN), zeroDevPct(nomacOffH, nomacOffN), entNoMACoff, lzNoMACoff)
	t.Logf("C1 wrapped   (wrapper on):  chi2 AEAD=%.1f NoMAC=%.1f | 0x00dev AEAD=%.2f%% NoMAC=%.2f%% | entropy(AEAD)=%.5f lz(AEAD)=%.4f",
		chiAEADon, chiNoMACon, zeroDevPct(aeadOnH, aeadOnN), zeroDevPct(nomacOnH, nomacOnN), entAEADon, lzAEADon)
	t.Logf("C1 mode homogeneity AEAD-vs-NoMAC: wrapper-off=%.1f wrapper-on=%.1f (df=255, in-band ⇒ modes indistinguishable)",
		homogOff, homogOn)

	// Entropy + incompressibility hold in every posture.
	if entNoMACoff < 7.998 || entAEADon < 7.998 {
		t.Errorf("C1: pooled entropy below 7.998 (NoMAC-off=%.5f AEAD-on=%.5f)", entNoMACoff, entAEADon)
	}
	if lzNoMACoff < 0.99 || lzAEADon < 0.99 {
		t.Errorf("C1: pool compressible (NoMAC-off lz=%.4f AEAD-on lz=%.4f)", lzNoMACoff, lzAEADon)
	}
	// Positive control (N-independent): the barrier-only container signature
	// is present — 0x00 is over-represented by several percent — and the
	// wrapper removes it. Guards against a probe that trivially passes.
	zBarrier := zeroDevPct(nomacOffH, nomacOffN)
	zWrapped := zeroDevPct(nomacOnH, nomacOnN)
	if zBarrier < 2.0 {
		t.Errorf("C1: barrier-only 0x00 over-representation %.2f%% < 2%% — probe may be insensitive", zBarrier)
	}
	if math.Abs(zWrapped) > 2.0 {
		t.Errorf("C1: wrapped 0x00 deviation %.2f%% exceeds ±2%% — wrapper not whitening the terminator signature", zWrapped)
	}
	// Mode ambiguity: two-sample homogeneity in-band both postures. Generous
	// upper bound (5-sigma band top is 368) to stay non-flaky at smoke N.
	const homogMax = 520
	if homogOff > homogMax {
		t.Errorf("C1: wrapper-off mode homogeneity chi2=%.1f > %d — modes distinguishable", homogOff, homogMax)
	}
	if homogOn > homogMax {
		t.Errorf("C1: wrapper-on mode homogeneity chi2=%.1f > %d — modes distinguishable", homogOn, homogMax)
	}
	// Format deniability: wrapper whitens each mode into the uniform band.
	if chiAEADon > homogMax || chiNoMACon > homogMax {
		t.Errorf("C1: wrapped byte chi2 above band (AEAD-on=%.1f NoMAC-on=%.1f) — wrapper not whitening", chiAEADon, chiNoMACon)
	}
}

// ============================================================================
// Probe C3 — tail-fill CSPRNG residue: container signature is size-stable
// ============================================================================

// TestHarnessC3TailFillResidue drives small container-floor-dominated
// plaintexts through the barrier-only wire and confirms the container
// signature is size-stable: the 0x00 over-representation and the byte
// chi-square do not vary with plaintext size (beyond the length the wire
// already reveals), so a size-dependent fill artefact is ruled out. Entropy
// stays ≈ 8 and the wire stays incompressible at every size.
func TestHarnessC3TailFillResidue(t *testing.T) {
	n := harnessN(8_000, 400)
	sizes := []int{1, 6, 32, 4096}

	var zeroDevs []float64
	var minTotal int64
	for _, sz := range sizes {
		sz := sz
		pool, hist, total := encPool(t, ProfileStreamingNoAEADTripleV1, false, n, sz)
		ent := shannonEntropy(hist, total)
		chi := chiSquareUniform(hist, total)
		lz := lzRatio(t, pool)
		zdev := zeroDevPct(hist, total)
		zeroDevs = append(zeroDevs, zdev)
		if minTotal == 0 || total < minTotal {
			minTotal = total
		}
		t.Logf("C3 size=%d: bytes=%d entropy=%.5f chi2=%.1f lz=%.4f 0x00dev=%+.2f%%", sz, total, ent, chi, lz, zdev)
		if ent < 7.998 {
			t.Errorf("C3 size=%d: entropy=%.5f < 7.998", sz, ent)
		}
		if lz < 0.99 {
			t.Errorf("C3 size=%d: compressible lz=%.4f", sz, lz)
		}
	}
	// Size-stability: every size must show the same container terminator
	// signature within a tight spread — no size-dependent fill anomaly.
	// The bound is derived from the sampling floor, not fixed: each
	// per-size 0x00 deviation is a binomial sample around the common
	// signature with sigma = 100*sqrt(255/total) percent (~0.80% at
	// smoke N, ~0.18% at full N). The spread statistic below is the
	// range of the four per-size samples, and the range of four iid
	// normals exceeds 6.5 sigma with probability < 1e-4 per run (upper
	// quantiles of the four-sample range distribution: q0.999 = 5.31
	// sigma, q0.9999 = 6.08 sigma) — so 6.5 sigma keeps the assertion
	// non-flaky at smoke N while a genuine size-dependent fill artefact
	// shifts the per-size means and lands far above the bound.
	rangeMax := 6.5 * 100 * math.Sqrt(255/float64(minTotal))
	minZ, maxZ := zeroDevs[0], zeroDevs[0]
	for _, z := range zeroDevs {
		if z < minZ {
			minZ = z
		}
		if z > maxZ {
			maxZ = z
		}
	}
	t.Logf("C3 size-stability: 0x00dev range [%.2f%%, %.2f%%] across sizes %v (bound %.2f%%)", minZ, maxZ, sizes, rangeMax)
	if maxZ-minZ > rangeMax {
		t.Errorf("C3: 0x00 signature varies %.2f%% across plaintext sizes (>%.2f%%) — size-dependent fill artefact", maxZ-minZ, rangeMax)
	}
}

// ============================================================================
// Probe C4a — cross-position (cross-snake) wire correlation
// ============================================================================

// TestHarnessC4aWireColumnCorrelation collects N wires of a fixed-size random
// plaintext, aligns them column-wise, and measures the maximum absolute
// Pearson correlation between wire byte-columns at short lags spanning the
// 6-byte chunk period. Under 3-snake independence the columns carry no linear
// cross-structure beyond the sampling floor — the marginal container signature
// is a per-byte-value bias, not an inter-column coupling.
func TestHarnessC4aWireColumnCorrelation(t *testing.T) {
	n := harnessN(30_000, 800)
	const plainSize = 300

	pipe, _, err := Init(ProfileStreamingNoAEADTripleV1, layerOpts(false))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	plain := make([]byte, plainSize)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}

	minLen := 0
	wires := make([][]byte, n)
	for i := 0; i < n; i++ {
		w, err := pipe.EncryptMessage(plain)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		wires[i] = w
		if i == 0 || len(w) < minLen {
			minLen = len(w)
		}
	}
	start := 8
	if start >= minLen {
		start = 0
	}
	end := minLen
	if end-start > 128 {
		end = start + 128
	}
	col := func(j int) []float64 {
		out := make([]float64, n)
		for i := 0; i < n; i++ {
			out[i] = float64(wires[i][j])
		}
		return out
	}
	pearson := func(x, y []float64) float64 {
		var sx, sy, sxx, syy, sxy float64
		nf := float64(len(x))
		for i := range x {
			sx += x[i]
			sy += y[i]
			sxx += x[i] * x[i]
			syy += y[i] * y[i]
			sxy += x[i] * y[i]
		}
		cov := sxy - sx*sy/nf
		vx := sxx - sx*sx/nf
		vy := syy - sy*sy/nf
		if vx <= 0 || vy <= 0 {
			return 0
		}
		return cov / math.Sqrt(vx*vy)
	}
	maxR := 0.0
	for j := start; j < end; j++ {
		cj := col(j)
		for lag := 1; lag <= 6 && j+lag < end; lag++ {
			r := math.Abs(pearson(cj, col(j+lag)))
			if r > maxR {
				maxR = r
			}
		}
	}
	floor := 1.0 / math.Sqrt(float64(n))
	t.Logf("C4a wire column corr: n=%d cols[%d,%d) max|r|=%.5f floor≈%.5f", n, start, end, maxR, floor)
	if maxR > 8*floor {
		t.Errorf("C4a: wire column |r|=%.5f exceeds 8x sampling floor %.5f", maxR, 8*floor)
	}
}

// ============================================================================
// Probe C5 — cumulative bit-balance: container bias vs wrapped floor
// ============================================================================

// TestHarnessC5CumulativeBitBalance pools the bytes of many large-payload wires
// and measures per-bit-position balance. The barrier-only wire carries a small
// container-attributable bit bias (the 0x00 / companion-value signature tilts a
// few bit positions off 0.5); engaging the wrapper pulls every bit position to
// the sampling floor. The architectural per-message bias (~2^-34.4) is far
// below the sqrt(1/N) detection floor at any attainable N, so no cumulative
// bias intrinsic to the barrier math is measurable — the residual bias seen
// wrapper-off is the container framing, which the wrapper removes.
func TestHarnessC5CumulativeBitBalance(t *testing.T) {
	n := harnessN(4_000, 100)
	const plainSize = 4096

	measure := func(wrapper bool) (maxZ, maxDev, floor float64, totalBytes int64) {
		pipe, _, err := Init(ProfileStreamingNoAEADTripleV1, layerOpts(wrapper))
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		defer pipe.Close()
		var ones [8]int64
		plain := make([]byte, plainSize)
		for i := 0; i < n; i++ {
			if _, err := rand.Read(plain); err != nil {
				t.Fatalf("rand: %v", err)
			}
			w, err := pipe.EncryptMessage(plain)
			if err != nil {
				t.Fatalf("EncryptMessage: %v", err)
			}
			for _, b := range w {
				for bit := 0; bit < 8; bit++ {
					ones[bit] += int64((b >> uint(bit)) & 1)
				}
			}
			totalBytes += int64(len(w))
		}
		exp := float64(totalBytes) * 0.5
		sd := math.Sqrt(float64(totalBytes) * 0.25)
		for bit := 0; bit < 8; bit++ {
			dev := math.Abs(float64(ones[bit])/float64(totalBytes) - 0.5)
			z := math.Abs(float64(ones[bit])-exp) / sd
			if z > maxZ {
				maxZ = z
			}
			if dev > maxDev {
				maxDev = dev
			}
		}
		floor = 1.0 / math.Sqrt(float64(totalBytes))
		return
	}

	offZ, offDev, offFloor, offBytes := measure(false)
	onZ, onDev, onFloor, onBytes := measure(true)
	archPerMsg := math.Pow(2, -34.4)
	t.Logf("C5 barrier-only: bytes=%d maxZ=%.2f max|dev|=%.3e floor≈%.3e (container bit bias)", offBytes, offZ, offDev, offFloor)
	t.Logf("C5 wrapped:      bytes=%d maxZ=%.2f max|dev|=%.3e floor≈%.3e arch-per-msg-bias≈%.3e", onBytes, onZ, onDev, onFloor, archPerMsg)

	// Wrapped wire must sit at the sampling floor.
	if onZ > 6.0 {
		t.Errorf("C5: wrapped per-bit balance deviates %.2f sigma (>6) — wrapper not whitening", onZ)
	}
}

// ============================================================================
// Probe C6 — nonce-freshness ⇒ per-message wire divergence (ambiguity witness)
// ============================================================================

// TestHarnessC6NonceFreshnessDivergence encrypts the SAME plaintext under the
// SAME session repeatedly and confirms every wire is distinct with ~50% mean
// pairwise Hamming distance — a fixed plaintext maps to a large observed-
// ciphertext orbit, empirically corroborating the fresh-nonce under-
// determination without brute-forcing the preimage count.
func TestHarnessC6NonceFreshnessDivergence(t *testing.T) {
	n := harnessN(10_000, 500)
	const plainSize = 256

	pipe, _, err := Init(ProfileStreamingNoAEADTripleV1, layerOpts(false))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	plain := make([]byte, plainSize)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}

	seen := make(map[string]struct{}, n)
	wires := make([][]byte, n)
	minLen := 0
	for i := 0; i < n; i++ {
		w, err := pipe.EncryptMessage(plain)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		seen[string(w)] = struct{}{}
		wires[i] = w
		if i == 0 || len(w) < minLen {
			minLen = len(w)
		}
	}
	if len(seen) != n {
		t.Errorf("C6: %d distinct wires out of %d — collision under fresh nonce", len(seen), n)
	}

	start := 8
	if start >= minLen {
		start = 0
	}
	pairs := 2000
	if pairs > n*(n-1)/2 {
		pairs = n * (n - 1) / 2
	}
	bodyBits := (minLen - start) * 8
	var hammingSum float64
	for k := 0; k < pairs; k++ {
		ai := k % n
		bi := (k*7 + 3) % n
		if ai == bi {
			bi = (bi + 1) % n
		}
		a, b := wires[ai], wires[bi]
		var d int
		for j := start; j < minLen; j++ {
			d += popcount8(a[j] ^ b[j])
		}
		hammingSum += float64(d) / float64(bodyBits)
	}
	meanHam := hammingSum / float64(pairs)
	t.Logf("C6 nonce freshness: n=%d distinct=%d meanPairwiseHamming=%.4f (ideal 0.5) bodyBits=%d", n, len(seen), meanHam, bodyBits)
	if meanHam < 0.45 || meanHam > 0.55 {
		t.Errorf("C6: mean pairwise Hamming %.4f outside [0.45,0.55]", meanHam)
	}
}

func popcount8(b byte) int {
	c := 0
	for b != 0 {
		c += int(b & 1)
		b >>= 1
	}
	return c
}
