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
	if v := os.Getenv("ITB_LOCKSOUP"); v != "" && v != "0" {
		SetLockSoup(1)
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

// withLockSoup turns on SetBitSoup(1) + SetLockSoup(1) for the duration of
// the test or subtest, restoring both flags via t.Cleanup. Helper for
// LockSoup-specific tests below; preferred over manual defer because it
// composes cleanly with t.Run subtests.
func withLockSoup(t testing.TB) {
	t.Helper()
	prevBit := GetBitSoup()
	prevLock := GetLockSoup()
	SetBitSoup(1)
	SetLockSoup(1)
	t.Cleanup(func() {
		SetLockSoup(prevLock)
		SetBitSoup(prevBit)
	})
}

// fixedTestLockPRF returns a deterministic lockPRF that ignores both
// the buffer and the chunk index, always returning the same mask triple.
// Useful for unit-testing chunk24lock / unchunk24lock without depending
// on a Hash function or seed material.
func fixedTestLockPRF(m0, m1, m2 uint32) lockPRF {
	return func([]byte, uint64) (uint32, uint32, uint32) {
		return m0, m1, m2
	}
}

// TestLockSoup_chunk24lock_RoundTrip verifies chunk24lock and
// unchunk24lock are exact inverses across a sample of mask indices
// drawn from the full 33-bit mask space.
func TestLockSoup_chunk24lock_RoundTrip(t *testing.T) {
	// Sample from 0, end of mask space, and a spread of intermediate
	// indices generated deterministically from a fixed seed.
	indices := []uint64{
		0,
		1,
		maskSpaceProduct - 1,
		maskSpaceProduct / 2,
		12345,
		7654321,
		1 << 30,
		(1 << 33) - 1,
	}

	for _, idx := range indices {
		m0, m1, m2 := rankToMaskTriple(idx)
		for trial := 0; trial < 256; trial++ {
			a := byte(trial)
			b := byte(trial * 31)
			c := byte(trial*53 ^ 0xAA)
			l0, l1, l2 := chunk24lock(a, b, c, m0, m1, m2)
			a2, b2, c2 := unchunk24lock(l0, l1, l2, m0, m1, m2)
			if a != a2 || b != b2 || c != c2 {
				t.Fatalf("idx=%d trial=%d: chunk24lock/unchunk24lock not inverse: in=(%02x,%02x,%02x) out=(%02x,%02x,%02x)",
					idx, trial, a, b, c, a2, b2, c2)
			}
		}
	}
}

// TestLockSoup_MaskBalance verifies rankToMaskTriple invariants over a
// random sample of indices: each lane gets exactly 8 bits, no overlap,
// and the union covers all 24 input bit positions.
func TestLockSoup_MaskBalance(t *testing.T) {
	popcount := func(x uint32) int {
		n := 0
		for x != 0 {
			n += int(x & 1)
			x >>= 1
		}
		return n
	}

	rng := make([]byte, 8)
	for trial := 0; trial < 1000; trial++ {
		if _, err := rand.Read(rng); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		var idx uint64
		for i, b := range rng {
			idx |= uint64(b) << (8 * uint(i))
		}

		m0, m1, m2 := rankToMaskTriple(idx)

		if popcount(m0) != 8 || popcount(m1) != 8 || popcount(m2) != 8 {
			t.Fatalf("trial=%d: popcount mismatch: m0=%d m1=%d m2=%d (need 8 each)",
				trial, popcount(m0), popcount(m1), popcount(m2))
		}
		if (m0 & m1) != 0 || (m1 & m2) != 0 || (m0 & m2) != 0 {
			t.Fatalf("trial=%d: masks not disjoint: m0=%06x m1=%06x m2=%06x",
				trial, m0, m1, m2)
		}
		if (m0 | m1 | m2) != 0xFFFFFF {
			t.Fatalf("trial=%d: masks do not cover 24 bits: m0|m1|m2=%06x",
				trial, m0|m1|m2)
		}
	}
}

// TestLockSoup_DisabledIdentity verifies that SetLockSoup(0) makes
// splitForTripleParallelLocked / interleaveForTripleParallelLocked
// produce output bit-identical to the plain bit-soup path. The
// closure prf argument is built but ignored when LockSoup is off.
func TestLockSoup_DisabledIdentity(t *testing.T) {
	prevBit := GetBitSoup()
	prevLock := GetLockSoup()
	SetBitSoup(1)
	SetLockSoup(0)
	t.Cleanup(func() {
		SetLockSoup(prevLock)
		SetBitSoup(prevBit)
	})

	// Build a non-trivial closure to confirm it is not invoked when
	// LockSoup is off (would produce different masks if called).
	prf := fixedTestLockPRF(0xAAAAAA&0xFFFFFF, 0x555555&0xFFFFFF, 0)

	for _, n := range []int{1, 100, 1023, 1024, 1377, 65536} {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		// Reference: plain bit-soup path (the function body's branch
		// taken when isLockSoupEnabled() returns false).
		refP0, refP1, refP2 := splitForTripleParallel(data)

		// Subject under test: locked dispatcher with LockSoup off.
		gotP0, gotP1, gotP2 := splitForTripleParallelLocked(data, prf)

		if !bytes.Equal(refP0, gotP0) || !bytes.Equal(refP1, gotP1) || !bytes.Equal(refP2, gotP2) {
			t.Fatalf("size=%d: SetLockSoup(0) split not bit-identical to plain bit-soup", n)
		}

		refOut := interleaveForTripleParallel(refP0, refP1, refP2)
		gotOut := interleaveForTripleParallelLocked(gotP0, gotP1, gotP2, prf)
		if !bytes.Equal(refOut, gotOut) {
			t.Fatalf("size=%d: SetLockSoup(0) interleave not bit-identical to plain bit-soup", n)
		}
		if !bytes.Equal(data, gotOut) {
			t.Fatalf("size=%d: round-trip failed under SetLockSoup(0)", n)
		}
	}
}

// TestLockSoup_RejectsBitSoupOff verifies that setting SetLockSoup(1)
// without SetBitSoup(1) is a silent no-op — the locked dispatchers fall
// through to byte-level Triple, identical to default behaviour.
func TestLockSoup_RejectsBitSoupOff(t *testing.T) {
	prevBit := GetBitSoup()
	prevLock := GetLockSoup()
	SetBitSoup(0)
	SetLockSoup(1)
	t.Cleanup(func() {
		SetLockSoup(prevLock)
		SetBitSoup(prevBit)
	})

	prf := fixedTestLockPRF(0xFF, 0xFF00, 0xFF0000)

	for _, n := range []int{1, 64, 1024} {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		// Reference: byte-level Triple split (bit-soup off path).
		refP0, refP1, refP2 := splitTripleParallel(data)

		// Subject under test: locked dispatcher with bit-soup off ⇒
		// must take the byte-level branch regardless of LockSoup flag.
		gotP0, gotP1, gotP2 := splitForTripleParallelLocked(data, prf)

		if !bytes.Equal(refP0, gotP0) || !bytes.Equal(refP1, gotP1) || !bytes.Equal(refP2, gotP2) {
			t.Fatalf("size=%d: SetLockSoup(1)+SetBitSoup(0) did not fall through to byte-level Triple", n)
		}

		refOut := interleaveTripleParallel(refP0, refP1, refP2)
		gotOut := interleaveForTripleParallelLocked(gotP0, gotP1, gotP2, prf)
		if !bytes.Equal(refOut, gotOut) {
			t.Fatalf("size=%d: SetLockSoup(1)+SetBitSoup(0) interleave mismatch", n)
		}
		if !bytes.Equal(data, gotOut) {
			t.Fatalf("size=%d: round-trip failed under SetLockSoup(1)+SetBitSoup(0)", n)
		}
	}
}

// TestLockSoup_LockedRoundTrip verifies that splitForTripleParallelLocked
// and interleaveForTripleParallelLocked are exact inverses under
// SetLockSoup(1) with a real hash backed PRF.
func TestLockSoup_LockedRoundTrip(t *testing.T) {
	withLockSoup(t)

	noiseSeed, _, _, _, _, _, _ := makeSevenSeeds128(512, sipHash128)
	nonce := make([]byte, currentNonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	prf := buildLockPRF128(noiseSeed, nonce)

	for _, n := range []int{1, 24, 25, 100, 1023, 1024, 1377, 65536, 65537} {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		p0, p1, p2 := splitForTripleParallelLocked(data, prf)
		out := interleaveForTripleParallelLocked(p0, p1, p2, prf)

		if !bytes.Equal(data, out) {
			t.Fatalf("size=%d: round-trip failed under SetLockSoup(1)", n)
		}
	}
}
