package drbg

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

// TestFillNonZero fills a 1MB buffer with the selected tier and checks
// the output is not obviously biased. Not a statistical test suite;
// guards against a total no-op or seed-passthrough bug in the fill
// path.
func TestFillNonZero(t *testing.T) {
	const size = 1 << 20
	buf := make([]byte, size)
	if err := Fill(buf); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	var zeros, sameByteHi int
	var hist [256]int
	for _, b := range buf {
		if b == 0 {
			zeros++
		}
		hist[b]++
	}
	for _, c := range hist {
		if c > sameByteHi {
			sameByteHi = c
		}
	}
	expected := size / 256
	if sameByteHi > 2*expected {
		t.Errorf("histogram skew: max=%d expected~%d", sameByteHi, expected)
	}
	if zeros > size/64 {
		t.Errorf("too many zero bytes: %d/%d", zeros, size)
	}
}

// TestStatisticalSmoke runs a coarse bit-balance and byte-histogram
// smoke over a 1 MB sample from each tier worker directly. Not a
// substitute for NIST STS — enough to catch a fill worker that ships
// an obvious keystream bias (all-zeroes, seed passthrough, stuck bit).
// Population count within ±0.5 % of half the sample bits, and no
// single byte value exceeding 2× the uniform expectation.
func TestStatisticalSmoke(t *testing.T) {
	const size = 1 << 20
	const bits = size * 8
	const halfBits = bits / 2
	tol := halfBits / 200 // 0.5 %
	cases := []struct {
		name string
		fn   func([]byte) error
	}{
		{"aes-ctr", fillAesCTR},
		{"chacha20", fillChaCha20},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, size)
			if err := c.fn(buf); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			var popcount int
			var hist [256]int
			for _, b := range buf {
				hist[b]++
				popcount += onesInByte(b)
			}
			if diff := abs(popcount - halfBits); diff > tol {
				t.Errorf("%s: population count %d off half=%d by %d (tol %d)",
					c.name, popcount, halfBits, diff, tol)
			}
			expected := size / 256
			for v, c2 := range hist {
				if c2 > 2*expected {
					t.Errorf("%s: byte value %d occurs %d times (expected ~%d)",
						c.name, v, c2, expected)
				}
			}
		})
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func onesInByte(b byte) int {
	// Small local popcount so the test does not depend on math/bits.
	n := 0
	for b != 0 {
		n += int(b & 1)
		b >>= 1
	}
	return n
}

// TestFillEmpty confirms zero-length calls short-circuit without error.
func TestFillEmpty(t *testing.T) {
	if err := Fill(nil); err != nil {
		t.Fatalf("Fill(nil): %v", err)
	}
	if err := Fill([]byte{}); err != nil {
		t.Fatalf("Fill(empty): %v", err)
	}
}

// TestFillDistinctPerCall confirms two consecutive Fill calls on the
// same buffer produce different outputs (fresh per-call seed). A
// non-zero probability of collision exists but is negligible at 4KB.
func TestFillDistinctPerCall(t *testing.T) {
	const size = 4096
	a := make([]byte, size)
	b := make([]byte, size)
	if err := Fill(a); err != nil {
		t.Fatalf("Fill(a): %v", err)
	}
	if err := Fill(b); err != nil {
		t.Fatalf("Fill(b): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("two Fill calls produced identical %d-byte output", size)
	}
}

// TestSelectedTierIsSupported confirms the auto-selected tier is one of
// the two known names.
func TestSelectedTierIsSupported(t *testing.T) {
	got := SelectedTier()
	switch got {
	case "aes", "chacha":
	default:
		t.Fatalf("SelectedTier() = %q, want aes or chacha", got)
	}
}

// TestBothTiersDirect exercises both tier workers directly, regardless
// of the auto-selected tier, so the fallback path is covered on hosts
// that would ordinarily pick AES-CTR.
func TestBothTiersDirect(t *testing.T) {
	const size = 4096
	buf := make([]byte, size)
	if err := fillAesCTR(buf); err != nil {
		t.Fatalf("fillAesCTR: %v", err)
	}
	if isAllZero(buf) {
		t.Fatal("fillAesCTR left buffer all-zero")
	}
	buf2 := make([]byte, size)
	if err := fillChaCha20(buf2); err != nil {
		t.Fatalf("fillChaCha20: %v", err)
	}
	if isAllZero(buf2) {
		t.Fatal("fillChaCha20 left buffer all-zero")
	}
	if bytes.Equal(buf, buf2) {
		t.Fatal("AES-CTR and ChaCha20 produced identical output")
	}
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// TestPickTierForce covers the env-override branches without touching
// package state (calls pickTier directly with each token via env).
func TestPickTierForce(t *testing.T) {
	t.Setenv("ITB_DRBG_TIER", "chacha")
	fn, name := pickTier()
	if name != "chacha" {
		t.Errorf("forced chacha: got tier %q", name)
	}
	if fn == nil {
		t.Fatal("forced chacha: nil fillFn")
	}

	t.Setenv("ITB_DRBG_TIER", "aes")
	fn, name = pickTier()
	if hostHasAES() {
		if name != "aes" {
			t.Errorf("forced aes on AES host: got tier %q", name)
		}
	} else {
		// forced aes on non-AES host: falls back to auto (chacha)
		if name != "chacha" {
			t.Errorf("forced aes on non-AES host: got tier %q (want chacha auto)", name)
		}
	}
	if fn == nil {
		t.Fatal("forced aes: nil fillFn")
	}

	t.Setenv("ITB_DRBG_TIER", "bogus")
	fn, name = pickTier()
	if fn == nil || name == "" {
		t.Fatalf("bogus token: got tier %q, fn=%v", name, fn)
	}

	t.Setenv("ITB_DRBG_TIER", "")
	fn, name = pickTier()
	if fn == nil || name == "" {
		t.Fatalf("empty token: got tier %q, fn=%v", name, fn)
	}
}

// TestParallelFillRaces stresses concurrent Fill calls against the
// go-race detector. No shared mutable state exists in the package, so
// this should be clean.
func TestParallelFillRaces(t *testing.T) {
	const workers = 8
	const iters = 32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for j := 0; j < iters; j++ {
				if err := Fill(buf); err != nil {
					t.Errorf("Fill: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// benchSizes covers the ITB CSPRNG-fill operating range: from the
// sub-MB seed-setup-amortization slice through the 73 MB container
// ceiling produced by a 64 MB plaintext (1.14× 8:7 expansion). Larger
// sizes are out of scope for the encrypt path.
var benchSizes = []int{
	64 << 10,  // 64 KB
	512 << 10, // 512 KB
	1 << 20,   // 1 MB
	4 << 20,   // 4 MB
	16 << 20,  // 16 MB
	64 << 20,  // 64 MB
	73 << 20,  // 73 MB — container ceiling for 64 MB plaintext
}

// BenchmarkFillProduction mirrors the container-fill shape at production
// sizes: 3 goroutines each filling a third of the buffer with a fresh
// per-goroutine DRBG via the auto-selected tier. Pins the aggregate
// throughput floor for regression watch.
func BenchmarkFillProduction(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				third := size / 3
				var wg sync.WaitGroup
				wg.Add(3)
				go func() { _ = Fill(buf[0:third]); wg.Done() }()
				go func() { _ = Fill(buf[third : 2*third]); wg.Done() }()
				go func() { _ = Fill(buf[2*third : size]); wg.Done() }()
				wg.Wait()
			}
		})
	}
}

// BenchmarkDRBGAESCTR times the AES-CTR fill worker directly on a
// single goroutine at every container-relevant size. Independent of
// SelectedTier — always exercises the AES-CTR path.
func BenchmarkDRBGAESCTR(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := fillAesCTR(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDRBGChaCha20 times the ChaCha20 fallback fill worker directly
// on a single goroutine at every container-relevant size. Independent
// of SelectedTier — always exercises the ChaCha20 path.
func BenchmarkDRBGChaCha20(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := fillChaCha20(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStdlibCryptoRand times the baseline crypto/rand.Read (Go
// vDSO vgetrandom on Linux 1.24+) at every container-relevant size.
// This is the reference this package aims to accelerate; the AES-CTR /
// ChaCha20 tiers are compared against these numbers in RESULTS.md.
func BenchmarkStdlibCryptoRand(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := rand.Read(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDRBGAESCTRParallel3 times the AES-CTR fill worker under the
// container-fill three-goroutine shape at every container-relevant size.
// Reports aggregate MB/s.
func BenchmarkDRBGAESCTRParallel3(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				third := size / 3
				var wg sync.WaitGroup
				wg.Add(3)
				go func() { _ = fillAesCTR(buf[0:third]); wg.Done() }()
				go func() { _ = fillAesCTR(buf[third : 2*third]); wg.Done() }()
				go func() { _ = fillAesCTR(buf[2*third : size]); wg.Done() }()
				wg.Wait()
			}
		})
	}
}

// BenchmarkDRBGChaCha20Parallel3 times the ChaCha20 fill worker under
// the container-fill three-goroutine shape at every container-relevant
// size. Reports aggregate MB/s.
func BenchmarkDRBGChaCha20Parallel3(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				third := size / 3
				var wg sync.WaitGroup
				wg.Add(3)
				go func() { _ = fillChaCha20(buf[0:third]); wg.Done() }()
				go func() { _ = fillChaCha20(buf[third : 2*third]); wg.Done() }()
				go func() { _ = fillChaCha20(buf[2*third : size]); wg.Done() }()
				wg.Wait()
			}
		})
	}
}

// BenchmarkStdlibCryptoRandParallel3 times the baseline crypto/rand.Read
// under the container-fill three-goroutine shape at every
// container-relevant size. Aggregate MB/s reference point for the DRBG
// tiers.
func BenchmarkStdlibCryptoRandParallel3(b *testing.B) {
	for _, size := range benchSizes {
		size := size
		buf := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				third := size / 3
				var wg sync.WaitGroup
				wg.Add(3)
				go func() { _, _ = rand.Read(buf[0:third]); wg.Done() }()
				go func() { _, _ = rand.Read(buf[third : 2*third]); wg.Done() }()
				go func() { _, _ = rand.Read(buf[2*third : size]); wg.Done() }()
				wg.Wait()
			}
		})
	}
}

func sizeName(n int) string {
	switch {
	case n%(1<<20) == 0:
		return itoa(n>>20) + "MB"
	case n%(1<<10) == 0:
		return itoa(n>>10) + "KB"
	default:
		return itoa(n) + "B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}
