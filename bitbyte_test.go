package itb

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

// equivalenceSizes covers every (4 + len(data)) mod 3 residue class,
// every full-chunk count from 0 to several, and several large sizes
// where the parallel path actually spawns multiple workers.
var equivalenceSizes = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9,
	20, 21, 22, 23, 24, 25, 26, 27, 28,
	100, 255, 256, 257,
	1023, 1024, 1025,
	4095, 4096, 4097,
	65535, 65536, 65537,
	1 << 20,
}

// TestMain honours the ITB_BITSOUP environment variable. When set to a
// non-zero value before `go test` is invoked, the entire test suite runs
// in bit-soup mode (SetBitSoup(1) called before any test or benchmark).
// Unset or "0" leaves the default byte-level Triple Ouroboros behaviour.
//
//	go test ./...                    # byte-level Triple Ouroboros (default)
//	ITB_BITSOUP=1 go test ./...      # bit-soup Triple Ouroboros
//	ITB_BITSOUP=1 go test -bench=.   # bit-soup benchmarks
//
// Works for every Triple Ouroboros test and benchmark in the package:
// plain Encrypt3x*, EncryptAuthenticated3x*, and EncryptStream3x* all
// route through splitForTriple / interleaveForTriple, which read the
// atomic mode flag at dispatch time. No duplicated test code required.
func TestMain(m *testing.M) {
	if v := os.Getenv("ITB_BITSOUP"); v != "" && v != "0" {
		SetBitSoup(1)
	}
	os.Exit(m.Run())
}

func TestParallelBitsoupSplitEquivalence(t *testing.T) {
	for _, n := range equivalenceSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		seqP0, seqP1, seqP2, seqBits := splitTripleBits(data)
		parP0, parP1, parP2, parBits := splitTripleBitsParallel(data)

		if seqBits != parBits {
			t.Fatalf("size=%d: totalBits mismatch seq=%d par=%d", n, seqBits, parBits)
		}
		if !bytes.Equal(seqP0, parP0) {
			t.Fatalf("size=%d: p0 mismatch\n  seq=%x\n  par=%x", n, seqP0, parP0)
		}
		if !bytes.Equal(seqP1, parP1) {
			t.Fatalf("size=%d: p1 mismatch\n  seq=%x\n  par=%x", n, seqP1, parP1)
		}
		if !bytes.Equal(seqP2, parP2) {
			t.Fatalf("size=%d: p2 mismatch\n  seq=%x\n  par=%x", n, seqP2, parP2)
		}
	}
}

func TestParallelBitsoupInterleaveEquivalence(t *testing.T) {
	for _, n := range equivalenceSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		p0, p1, p2, totalBits := splitTripleBits(data)
		seqOut := interleaveTripleBits(p0, p1, p2, totalBits)
		parOut := interleaveTripleBitsParallel(p0, p1, p2, totalBits)

		if !bytes.Equal(seqOut, parOut) {
			t.Fatalf("size=%d: interleave output mismatch\n  seq=%x\n  par=%x", n, seqOut, parOut)
		}
		if !bytes.Equal(seqOut, data) {
			t.Fatalf("size=%d: round-trip via sequential lost data\n  in=%x\n  out=%x", n, data, seqOut)
		}
	}
}

func TestParallelBitsoupRoundTrip(t *testing.T) {
	for _, n := range equivalenceSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		p0, p1, p2, totalBits := splitTripleBitsParallel(data)
		recovered := interleaveTripleBitsParallel(p0, p1, p2, totalBits)
		if !bytes.Equal(recovered, data) {
			t.Fatalf("size=%d: parallel round-trip lost data\n  in=%x\n  out=%x", n, data, recovered)
		}
	}
}

func TestParallelBitsoupCrossModeRoundTrip(t *testing.T) {
	for _, n := range equivalenceSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		p0, p1, p2, totalBits := splitTripleBits(data)
		recovered := interleaveTripleBitsParallel(p0, p1, p2, totalBits)
		if !bytes.Equal(recovered, data) {
			t.Fatalf("size=%d: seq-split → par-interleave lost data", n)
		}

		p0, p1, p2, totalBits = splitTripleBitsParallel(data)
		recovered = interleaveTripleBits(p0, p1, p2, totalBits)
		if !bytes.Equal(recovered, data) {
			t.Fatalf("size=%d: par-split → seq-interleave lost data", n)
		}
	}
}

func TestChunk24RoundTrip(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			for c := 0; c < 256; c++ {
				l0, l1, l2 := chunk24(byte(a), byte(b), byte(c))
				ra, rb, rc := unchunk24(l0, l1, l2)
				if ra != byte(a) || rb != byte(b) || rc != byte(c) {
					t.Fatalf("chunk24 round-trip failed for (%02x %02x %02x): got back (%02x %02x %02x)",
						a, b, c, ra, rb, rc)
				}
			}
		}
	}
}

func TestSplitForTripleParallelDispatchEquivalence(t *testing.T) {
	for _, n := range equivalenceSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		seqP0, seqP1, seqP2 := splitForTriple(data)
		parP0, parP1, parP2 := splitForTripleParallel(data)

		if !bytes.Equal(seqP0, parP0) || !bytes.Equal(seqP1, parP1) || !bytes.Equal(seqP2, parP2) {
			t.Fatalf("size=%d: splitForTriple vs splitForTripleParallel mismatch", n)
		}

		seqOut := interleaveForTriple(seqP0, seqP1, seqP2)
		parOut := interleaveForTripleParallel(parP0, parP1, parP2)
		if !bytes.Equal(seqOut, parOut) {
			t.Fatalf("size=%d: interleaveForTriple vs interleaveForTripleParallel mismatch", n)
		}
		if !bytes.Equal(parOut, data) {
			t.Fatalf("size=%d: parallel dispatch round-trip lost data", n)
		}
	}
}

func benchSplit(b *testing.B, sizeBytes int, fn func([]byte) (p0, p1, p2 []byte, totalBits int)) {
	data := make([]byte, sizeBytes)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.SetBytes(int64(sizeBytes))
	for i := 0; i < b.N; i++ {
		_, _, _, _ = fn(data)
	}
}

func benchInterleave(b *testing.B, sizeBytes int, fn func(p0, p1, p2 []byte, totalBits int) []byte) {
	data := make([]byte, sizeBytes)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	p0, p1, p2, totalBits := splitTripleBits(data)
	b.ResetTimer()
	b.SetBytes(int64(sizeBytes))
	for i := 0; i < b.N; i++ {
		_ = fn(p0, p1, p2, totalBits)
	}
}

func BenchmarkSplitSequential_4KB(b *testing.B)  { benchSplit(b, 4*1024, splitTripleBits) }
func BenchmarkSplitParallel_4KB(b *testing.B)    { benchSplit(b, 4*1024, splitTripleBitsParallel) }
func BenchmarkSplitSequential_64KB(b *testing.B) { benchSplit(b, 64*1024, splitTripleBits) }
func BenchmarkSplitParallel_64KB(b *testing.B)   { benchSplit(b, 64*1024, splitTripleBitsParallel) }
func BenchmarkSplitSequential_1MB(b *testing.B)  { benchSplit(b, 1024*1024, splitTripleBits) }
func BenchmarkSplitParallel_1MB(b *testing.B)    { benchSplit(b, 1024*1024, splitTripleBitsParallel) }
func BenchmarkSplitSequential_16MB(b *testing.B) { benchSplit(b, 16*1024*1024, splitTripleBits) }
func BenchmarkSplitParallel_16MB(b *testing.B)   { benchSplit(b, 16*1024*1024, splitTripleBitsParallel) }

func BenchmarkInterleaveSequential_4KB(b *testing.B) {
	benchInterleave(b, 4*1024, interleaveTripleBits)
}
func BenchmarkInterleaveParallel_4KB(b *testing.B) {
	benchInterleave(b, 4*1024, interleaveTripleBitsParallel)
}
func BenchmarkInterleaveSequential_64KB(b *testing.B) {
	benchInterleave(b, 64*1024, interleaveTripleBits)
}
func BenchmarkInterleaveParallel_64KB(b *testing.B) {
	benchInterleave(b, 64*1024, interleaveTripleBitsParallel)
}
func BenchmarkInterleaveSequential_1MB(b *testing.B) {
	benchInterleave(b, 1024*1024, interleaveTripleBits)
}
func BenchmarkInterleaveParallel_1MB(b *testing.B) {
	benchInterleave(b, 1024*1024, interleaveTripleBitsParallel)
}
func BenchmarkInterleaveSequential_16MB(b *testing.B) {
	benchInterleave(b, 16*1024*1024, interleaveTripleBits)
}
func BenchmarkInterleaveParallel_16MB(b *testing.B) {
	benchInterleave(b, 16*1024*1024, interleaveTripleBitsParallel)
}
