//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// batchCase holds one random batch of n chunks: source bytes, mask
// triples and the expected lane bytes computed through the per-chunk
// BMI2 kernel plus the caller-side little-endian serialisation.
type batchCase struct {
	src        []byte
	masks      [][3]uint64
	p0, p1, p2 []byte
}

func newBatchCase(rng *rand.Rand, n int) batchCase {
	c := batchCase{
		src:   make([]byte, 6*n),
		masks: make([][3]uint64, n),
		p0:    make([]byte, 2*n),
		p1:    make([]byte, 2*n),
		p2:    make([]byte, 2*n),
	}
	rng.Read(c.src)
	for j := 0; j < n; j++ {
		m0, m1, m2 := randomTripleMask(rng)
		c.masks[j] = [3]uint64{m0, m1, m2}
		x := uint64(c.src[6*j]) | uint64(c.src[6*j+1])<<8 | uint64(c.src[6*j+2])<<16 |
			uint64(c.src[6*j+3])<<24 | uint64(c.src[6*j+4])<<32 | uint64(c.src[6*j+5])<<40
		l0, l1, l2 := Chunk48Lock(x, m0, m1, m2)
		binary.LittleEndian.PutUint16(c.p0[2*j:], uint16(l0))
		binary.LittleEndian.PutUint16(c.p1[2*j:], uint16(l1))
		binary.LittleEndian.PutUint16(c.p2[2*j:], uint16(l2))
	}
	return c
}

// TestChunk48LockBatchVsScalar compares the batched forward kernel
// against n per-chunk Chunk48Lock calls (themselves validated against
// the pure-Go reference by TestChunk48LockAsmVsSoft) on random source
// bytes and PRF-derived mask triples, for every batch width the parent
// package dispatches (1..16). Buffers are allocated at exactly 6n / 2n
// bytes so an out-of-window read or write faults or corrupts the
// comparison rather than passing silently.
func TestChunk48LockBatchVsScalar(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(11))
	const iters = 10000
	for iter := 0; iter < iters; iter++ {
		n := 1 + iter%16
		c := newBatchCase(rng, n)
		p0 := make([]byte, 2*n)
		p1 := make([]byte, 2*n)
		p2 := make([]byte, 2*n)
		Chunk48LockBatch(c.src, c.masks, p0, p1, p2)
		for j := 0; j < n; j++ {
			if p0[2*j] != c.p0[2*j] || p0[2*j+1] != c.p0[2*j+1] ||
				p1[2*j] != c.p1[2*j] || p1[2*j+1] != c.p1[2*j+1] ||
				p2[2*j] != c.p2[2*j] || p2[2*j+1] != c.p2[2*j+1] {
				t.Fatalf("iter=%d n=%d chunk=%d masks=%012x: batch=(%x,%x,%x) scalar=(%x,%x,%x)",
					iter, n, j, c.masks[j],
					p0[2*j:2*j+2], p1[2*j:2*j+2], p2[2*j:2*j+2],
					c.p0[2*j:2*j+2], c.p1[2*j:2*j+2], c.p2[2*j:2*j+2])
			}
		}
	}
}

// TestUnchunk48LockBatchVsScalar compares the batched inverse kernel
// against n per-chunk Unchunk48Lock calls plus the caller-side six-byte
// little-endian store, on random lane bytes (not only lane bytes that
// came out of the forward kernel) and PRF-derived mask triples, for
// every batch width 1..16 with exact-size buffers.
func TestUnchunk48LockBatchVsScalar(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(12))
	const iters = 10000
	for iter := 0; iter < iters; iter++ {
		n := 1 + iter%16
		masks := make([][3]uint64, n)
		p0 := make([]byte, 2*n)
		p1 := make([]byte, 2*n)
		p2 := make([]byte, 2*n)
		rng.Read(p0)
		rng.Read(p1)
		rng.Read(p2)
		want := make([]byte, 6*n)
		for j := 0; j < n; j++ {
			m0, m1, m2 := randomTripleMask(rng)
			masks[j] = [3]uint64{m0, m1, m2}
			l0 := uint64(binary.LittleEndian.Uint16(p0[2*j:]))
			l1 := uint64(binary.LittleEndian.Uint16(p1[2*j:]))
			l2 := uint64(binary.LittleEndian.Uint16(p2[2*j:]))
			x := Unchunk48Lock(l0, l1, l2, m0, m1, m2)
			for i := 0; i < 6; i++ {
				want[6*j+i] = byte(x >> (8 * i))
			}
		}
		got := make([]byte, 6*n)
		Unchunk48LockBatch(p0, p1, p2, masks, got)
		for j := 0; j < n; j++ {
			for i := 0; i < 6; i++ {
				if got[6*j+i] != want[6*j+i] {
					t.Fatalf("iter=%d n=%d chunk=%d masks=%012x: batch=%x scalar=%x",
						iter, n, j, masks[j], got[6*j:6*j+6], want[6*j:6*j+6])
				}
			}
		}
	}
}

// TestChunk48LockBatchRoundTrip applies the batched forward kernel then
// the batched inverse kernel; the recovered bytes must equal the source.
func TestChunk48LockBatchRoundTrip(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(13))
	const iters = 4000
	for iter := 0; iter < iters; iter++ {
		n := 1 + iter%16
		c := newBatchCase(rng, n)
		p0 := make([]byte, 2*n)
		p1 := make([]byte, 2*n)
		p2 := make([]byte, 2*n)
		Chunk48LockBatch(c.src, c.masks, p0, p1, p2)
		back := make([]byte, 6*n)
		Unchunk48LockBatch(p0, p1, p2, c.masks, back)
		for i := range back {
			if back[i] != c.src[i] {
				t.Fatalf("iter=%d n=%d: round-trip differs at byte %d: got %x want %x",
					iter, n, i, back, c.src)
			}
		}
	}
}

// TestChunk48LockBatchZero asserts an empty batch is a no-op on both
// kernels (no pointer dereference of an empty slice).
func TestChunk48LockBatchZero(t *testing.T) {
	Chunk48LockBatch(nil, nil, nil, nil, nil)
	Unchunk48LockBatch(nil, nil, nil, nil, nil)
}

// BenchmarkChunk48LockBatch16 measures the batched forward kernel over
// 16 chunks per call against 16 per-chunk Chunk48Lock calls with the
// same caller-side byte packing and lane serialisation the parent
// package performs. Reported per chunk.
func BenchmarkChunk48LockBatch16(b *testing.B) {
	if !HasBMI2 {
		b.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(21))
	c := newBatchCase(rng, 16)
	p0 := make([]byte, 32)
	p1 := make([]byte, 32)
	p2 := make([]byte, 32)
	b.Run("batch", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			Chunk48LockBatch(c.src, c.masks, p0, p1, p2)
		}
	})
	b.Run("scalar", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 16; j++ {
				x := uint64(c.src[6*j]) | uint64(c.src[6*j+1])<<8 | uint64(c.src[6*j+2])<<16 |
					uint64(c.src[6*j+3])<<24 | uint64(c.src[6*j+4])<<32 | uint64(c.src[6*j+5])<<40
				m := &c.masks[j]
				l0, l1, l2 := Chunk48Lock(x, m[0], m[1], m[2])
				binary.LittleEndian.PutUint16(p0[2*j:], uint16(l0))
				binary.LittleEndian.PutUint16(p1[2*j:], uint16(l1))
				binary.LittleEndian.PutUint16(p2[2*j:], uint16(l2))
			}
		}
	})
}

// BenchmarkUnchunk48LockBatch16 is the inverse-kernel counterpart of
// BenchmarkChunk48LockBatch16.
func BenchmarkUnchunk48LockBatch16(b *testing.B) {
	if !HasBMI2 {
		b.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(22))
	c := newBatchCase(rng, 16)
	dst := make([]byte, 96)
	b.Run("batch", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			Unchunk48LockBatch(c.p0, c.p1, c.p2, c.masks, dst)
		}
	})
	b.Run("scalar", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 16; j++ {
				l0 := uint64(binary.LittleEndian.Uint16(c.p0[2*j:]))
				l1 := uint64(binary.LittleEndian.Uint16(c.p1[2*j:]))
				l2 := uint64(binary.LittleEndian.Uint16(c.p2[2*j:]))
				m := &c.masks[j]
				x := Unchunk48Lock(l0, l1, l2, m[0], m[1], m[2])
				dst[6*j] = byte(x)
				dst[6*j+1] = byte(x >> 8)
				dst[6*j+2] = byte(x >> 16)
				dst[6*j+3] = byte(x >> 24)
				dst[6*j+4] = byte(x >> 32)
				dst[6*j+5] = byte(x >> 40)
			}
		}
	})
}
