//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// softPEXT48Ref / softPDEP48Ref are local pure-Go references for the
// batched entry points. Structurally identical to the parent package's
// softPEXT48 / softPDEP48 (48-position bit-serial walk), duplicated
// here so the tests stay self-contained.
func softPEXT48Ref(x, mask uint64) uint16 {
	var result, outBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		xb := (x >> i) & 1
		result |= (bit & xb) << outBit
		outBit += bit
	}
	return uint16(result)
}

func softPDEP48Ref(v uint16, mask uint64) uint64 {
	var result, inBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		vb := uint64(v>>inBit) & 1
		result |= (bit & vb) << i
		inBit += bit
	}
	return result
}

// randomTripleMask returns a valid (m0, m1, m2) mask triple through the
// scalar reference unrank.
func randomTripleMask(rng *rand.Rand) (m0, m1, m2 uint64) {
	return refTriple48(rng.Uint64()%neonA, uint32(rng.Uint64()%neonB))
}

// batchCase holds one random batch of n chunks: source bytes, mask
// triples and the expected lane bytes computed through the bit-serial
// reference plus the caller-side little-endian serialisation.
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
		binary.LittleEndian.PutUint16(c.p0[2*j:], softPEXT48Ref(x, m0))
		binary.LittleEndian.PutUint16(c.p1[2*j:], softPEXT48Ref(x, m1))
		binary.LittleEndian.PutUint16(c.p2[2*j:], softPEXT48Ref(x, m2))
	}
	return c
}

type lockBatchFn func(src []byte, masks [][3]uint64, p0, p1, p2 []byte)
type unlockBatchFn func(p0, p1, p2 []byte, masks [][3]uint64, dst []byte)

func sve2LockBatch(src []byte, masks [][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	chunk48LockBatchSVE2(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
}

func sve2UnlockBatch(p0, p1, p2 []byte, masks [][3]uint64, dst []byte) {
	n := len(masks)
	unchunk48LockBatchSVE2(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
}

// runLockBatchParity compares a batched forward arm against the
// bit-serial reference on random source bytes and PRF-derived mask
// triples, for every batch width the parent package dispatches (1..16).
// Buffers are allocated at exactly 6n / 2n bytes so an out-of-window
// read or write faults or corrupts the comparison rather than passing
// silently.
func runLockBatchParity(t *testing.T, name string, fn lockBatchFn, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	const iters = 10000
	for iter := 0; iter < iters; iter++ {
		n := 1 + iter%16
		c := newBatchCase(rng, n)
		p0 := make([]byte, 2*n)
		p1 := make([]byte, 2*n)
		p2 := make([]byte, 2*n)
		fn(c.src, c.masks, p0, p1, p2)
		for j := 0; j < n; j++ {
			if p0[2*j] != c.p0[2*j] || p0[2*j+1] != c.p0[2*j+1] ||
				p1[2*j] != c.p1[2*j] || p1[2*j+1] != c.p1[2*j+1] ||
				p2[2*j] != c.p2[2*j] || p2[2*j+1] != c.p2[2*j+1] {
				t.Fatalf("%s iter=%d n=%d chunk=%d masks=%012x: batch=(%x,%x,%x) ref=(%x,%x,%x)",
					name, iter, n, j, c.masks[j],
					p0[2*j:2*j+2], p1[2*j:2*j+2], p2[2*j:2*j+2],
					c.p0[2*j:2*j+2], c.p1[2*j:2*j+2], c.p2[2*j:2*j+2])
			}
		}
	}
}

// runUnlockBatchParity compares a batched inverse arm against the
// bit-serial reference plus the caller-side six-byte store, on random
// lane bytes (not only lane bytes that came out of the forward arm) and
// PRF-derived mask triples, for every batch width 1..16 with exact-size
// buffers.
func runUnlockBatchParity(t *testing.T, name string, fn unlockBatchFn, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
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
			x := softPDEP48Ref(binary.LittleEndian.Uint16(p0[2*j:]), m0) |
				softPDEP48Ref(binary.LittleEndian.Uint16(p1[2*j:]), m1) |
				softPDEP48Ref(binary.LittleEndian.Uint16(p2[2*j:]), m2)
			for i := 0; i < 6; i++ {
				want[6*j+i] = byte(x >> (8 * i))
			}
		}
		got := make([]byte, 6*n)
		fn(p0, p1, p2, masks, got)
		for j := 0; j < n; j++ {
			for i := 0; i < 6; i++ {
				if got[6*j+i] != want[6*j+i] {
					t.Fatalf("%s iter=%d n=%d chunk=%d masks=%012x: batch=%x ref=%x",
						name, iter, n, j, masks[j], got[6*j:6*j+6], want[6*j:6*j+6])
				}
			}
		}
	}
}

// runBatchRoundTrip applies a batched forward arm then the matching
// inverse arm; the recovered bytes must equal the source.
func runBatchRoundTrip(t *testing.T, name string, lock lockBatchFn, unlock unlockBatchFn, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	const iters = 4000
	for iter := 0; iter < iters; iter++ {
		n := 1 + iter%16
		c := newBatchCase(rng, n)
		p0 := make([]byte, 2*n)
		p1 := make([]byte, 2*n)
		p2 := make([]byte, 2*n)
		lock(c.src, c.masks, p0, p1, p2)
		back := make([]byte, 6*n)
		unlock(p0, p1, p2, c.masks, back)
		for i := range back {
			if back[i] != c.src[i] {
				t.Fatalf("%s iter=%d n=%d: round-trip differs at byte %d: got %x want %x",
					name, iter, n, i, back, c.src)
			}
		}
	}
}

func TestChunk48LockBatchGoVsSoft(t *testing.T) {
	runLockBatchParity(t, "go", chunk48LockBatchGo, 11)
}

func TestUnchunk48LockBatchGoVsSoft(t *testing.T) {
	runUnlockBatchParity(t, "go", unchunk48LockBatchGo, 12)
}

func TestChunk48LockBatchGoRoundTrip(t *testing.T) {
	runBatchRoundTrip(t, "go", chunk48LockBatchGo, unchunk48LockBatchGo, 13)
}

func TestChunk48LockBatchSVE2VsSoft(t *testing.T) {
	if !HasSVE2Interlock {
		t.Skip("SVE2 bit-permute kernel not available on this host")
	}
	runLockBatchParity(t, "sve2", sve2LockBatch, 14)
}

func TestUnchunk48LockBatchSVE2VsSoft(t *testing.T) {
	if !HasSVE2Interlock {
		t.Skip("SVE2 bit-permute kernel not available on this host")
	}
	runUnlockBatchParity(t, "sve2", sve2UnlockBatch, 15)
}

func TestChunk48LockBatchSVE2RoundTrip(t *testing.T) {
	if !HasSVE2Interlock {
		t.Skip("SVE2 bit-permute kernel not available on this host")
	}
	runBatchRoundTrip(t, "sve2", sve2LockBatch, sve2UnlockBatch, 16)
}

// TestChunk48LockBatchSVE2FixedVector pins the SVE2 kernel's operand
// order on a hand-checked pair: x and the masks are not symmetric under
// BEXT, so a swapped data / mask operand fails here loudly.
func TestChunk48LockBatchSVE2FixedVector(t *testing.T) {
	if !HasSVE2Interlock {
		t.Skip("SVE2 bit-permute kernel not available on this host")
	}
	// m0 = low 16 bits, m1 = middle 16, m2 = top 16 of the 48-bit domain.
	masks := [][3]uint64{
		{0x0000_0000_FFFF, 0x0000_FFFF_0000, 0xFFFF_0000_0000},
		{0xFFFF_0000_0000, 0x0000_0000_FFFF, 0x0000_FFFF_0000},
	}
	src := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	p0 := make([]byte, 4)
	p1 := make([]byte, 4)
	p2 := make([]byte, 4)
	sve2LockBatch(src, masks, p0, p1, p2)
	want0 := []byte{0x01, 0x02, 0x15, 0x16}
	want1 := []byte{0x03, 0x04, 0x11, 0x12}
	want2 := []byte{0x05, 0x06, 0x13, 0x14}
	if string(p0) != string(want0) || string(p1) != string(want1) || string(p2) != string(want2) {
		t.Fatalf("got p0=%x p1=%x p2=%x want %x %x %x", p0, p1, p2, want0, want1, want2)
	}
	back := make([]byte, 12)
	sve2UnlockBatch(p0, p1, p2, masks, back)
	if string(back) != string(src) {
		t.Fatalf("inverse: got %x want %x", back, src)
	}
}

// TestChunk48LockBatchDispatch exercises the exported entry points on
// whichever arm the host selects.
func TestChunk48LockBatchDispatch(t *testing.T) {
	runLockBatchParity(t, "dispatch", Chunk48LockBatch, 17)
	runUnlockBatchParity(t, "dispatch", Unchunk48LockBatch, 18)
	Chunk48LockBatch(nil, nil, nil, nil, nil)
	Unchunk48LockBatch(nil, nil, nil, nil, nil)
}

// BenchmarkChunk48LockBatch16 measures the batched forward arms over 16
// chunks per call against the per-chunk bit-serial loop with the same
// caller-side byte packing and lane serialisation the parent package
// performs. Reported per chunk.
func BenchmarkChunk48LockBatch16(b *testing.B) {
	rng := rand.New(rand.NewSource(21))
	c := newBatchCase(rng, 16)
	p0 := make([]byte, 32)
	p1 := make([]byte, 32)
	p2 := make([]byte, 32)
	if HasSVE2Interlock {
		b.Run("sve2", func(b *testing.B) {
			b.SetBytes(16 * 6)
			for i := 0; i < b.N; i++ {
				sve2LockBatch(c.src, c.masks, p0, p1, p2)
			}
		})
	}
	b.Run("go-batch", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			chunk48LockBatchGo(c.src, c.masks, p0, p1, p2)
		}
	})
	b.Run("soft-perchunk", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 16; j++ {
				x := uint64(c.src[6*j]) | uint64(c.src[6*j+1])<<8 | uint64(c.src[6*j+2])<<16 |
					uint64(c.src[6*j+3])<<24 | uint64(c.src[6*j+4])<<32 | uint64(c.src[6*j+5])<<40
				m := &c.masks[j]
				binary.LittleEndian.PutUint16(p0[2*j:], softPEXT48Ref(x, m[0]))
				binary.LittleEndian.PutUint16(p1[2*j:], softPEXT48Ref(x, m[1]))
				binary.LittleEndian.PutUint16(p2[2*j:], softPEXT48Ref(x, m[2]))
			}
		}
	})
}

// BenchmarkUnchunk48LockBatch16 is the inverse counterpart of
// BenchmarkChunk48LockBatch16.
func BenchmarkUnchunk48LockBatch16(b *testing.B) {
	rng := rand.New(rand.NewSource(22))
	c := newBatchCase(rng, 16)
	dst := make([]byte, 96)
	if HasSVE2Interlock {
		b.Run("sve2", func(b *testing.B) {
			b.SetBytes(16 * 6)
			for i := 0; i < b.N; i++ {
				sve2UnlockBatch(c.p0, c.p1, c.p2, c.masks, dst)
			}
		})
	}
	b.Run("go-batch", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			unchunk48LockBatchGo(c.p0, c.p1, c.p2, c.masks, dst)
		}
	})
	b.Run("soft-perchunk", func(b *testing.B) {
		b.SetBytes(16 * 6)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 16; j++ {
				m := &c.masks[j]
				x := softPDEP48Ref(binary.LittleEndian.Uint16(c.p0[2*j:]), m[0]) |
					softPDEP48Ref(binary.LittleEndian.Uint16(c.p1[2*j:]), m[1]) |
					softPDEP48Ref(binary.LittleEndian.Uint16(c.p2[2*j:]), m[2])
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
