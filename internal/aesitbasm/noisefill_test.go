package aesitbasm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// noiseRefBlock is the test-side definition of one filler block: the
// pure-Go reference over the software AES round, with the nonce in the
// data slot and the block index in the seed slot — the reference the
// folded schedule and every kernel tier are pinned to.
func noiseRefBlock(key *[16]byte, nonce *[32]byte, lo, hi uint64) [16]byte {
	a, b := ChainAbsorb(key, nonce[:], lo, hi)
	var out [16]byte
	binary.LittleEndian.PutUint64(out[:8], a)
	binary.LittleEndian.PutUint64(out[8:], b)
	return out
}

// noiseRefFill writes len(dst) reference filler bytes from (lo, hi).
func noiseRefFill(key *[16]byte, nonce *[32]byte, dst []byte, lo, hi uint64) {
	for len(dst) > 0 {
		b := noiseRefBlock(key, nonce, lo, hi)
		n := copy(dst, b[:])
		dst = dst[n:]
		lo++
		if lo == 0 {
			hi++
		}
	}
}

func randomNoiseKeyNonce(t *testing.T) (*[16]byte, *[32]byte) {
	t.Helper()
	var key [16]byte
	var nonce [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return &key, &nonce
}

// noiseLengths covers the empty fill, sub-block and off-by-one tails,
// and runs that straddle every tier's group width (8 / 16 blocks).
var noiseLengths = []int{0, 1, 15, 16, 17, 31, 33, 127, 128, 129, 255, 256, 257, 511, 512, 513, 4103, 65569}

// noiseStarts covers block 0, a carry inside byte 1 and byte 4 of the
// counter, a run that crosses the 64-bit wrap of lo, and a non-zero hi.
var noiseStarts = [][2]uint64{{0, 0}, {255, 0}, {1<<32 - 1, 0}, {^uint64(0) - 3, 0}, {^uint64(0) - 40, 7}, {0, 1}}

// TestNoiseScheduleMatchesReference pins the folded schedule evaluated by
// the Go single-block path to the pure-Go reference at every start.
func TestNoiseScheduleMatchesReference(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		key, nonce := randomNoiseKeyNonce(t)
		s := NewNoiseSchedule(key, nonce)
		for _, c := range noiseStarts {
			var got [16]byte
			noiseBlockHW(&s, &got, c[0], c[1])
			if want := noiseRefBlock(key, nonce, c[0], c[1]); got != want {
				t.Fatalf("trial %d ctr=%v: schedule %x, reference %x", trial, c, got, want)
			}
		}
	}
}

// TestNoiseFillMatchesReference pins NoiseFill — whichever tier the build
// and host select — to the pure-Go reference over every length and start,
// including the carry split and the partial tail.
func TestNoiseFillMatchesReference(t *testing.T) {
	for _, n := range noiseLengths {
		for _, c := range noiseStarts {
			key, nonce := randomNoiseKeyNonce(t)
			s := NewNoiseSchedule(key, nonce)
			want := make([]byte, n)
			noiseRefFill(key, nonce, want, c[0], c[1])
			got := make([]byte, n+32)
			for i := range got {
				got[i] = 0xA5
			}
			NoiseFill(&s, got[16:16+n], c[0], c[1])
			if !bytes.Equal(got[16:16+n], want) {
				t.Fatalf("n=%d ctr=%v: fill differs from reference", n, c)
			}
			for _, i := range []int{0, 15, 16 + n, 16 + n + 15} {
				if got[i] != 0xA5 {
					t.Fatalf("n=%d ctr=%v: byte outside dst at %d overwritten", n, c, i)
				}
			}
		}
	}
}

// TestNoiseFillGenericMatchesReference pins the Go single-block path on
// its own, so the fallback is covered on hosts whose auto-dispatch
// selects a kernel.
func TestNoiseFillGenericMatchesReference(t *testing.T) {
	for _, n := range []int{0, 1, 16, 17, 255, 256, 4103} {
		for _, c := range noiseStarts {
			key, nonce := randomNoiseKeyNonce(t)
			s := NewNoiseSchedule(key, nonce)
			want := make([]byte, n)
			noiseRefFill(key, nonce, want, c[0], c[1])
			got := make([]byte, n)
			noiseFillGeneric(&s, got, c[0], c[1])
			if !bytes.Equal(got, want) {
				t.Fatalf("n=%d ctr=%v: generic fill differs from reference", n, c)
			}
		}
	}
}

// TestNoiseFillBitSensitivity confirms every key and nonce bit changes
// the first block.
func TestNoiseFillBitSensitivity(t *testing.T) {
	key, nonce := randomNoiseKeyNonce(t)
	base := NewNoiseSchedule(key, nonce)
	var ref [16]byte
	noiseBlockHW(&base, &ref, 0, 0)
	for bit := 0; bit < 16*8; bit++ {
		k := *key
		k[bit/8] ^= 1 << (bit % 8)
		s := NewNoiseSchedule(&k, nonce)
		var out [16]byte
		noiseBlockHW(&s, &out, 0, 0)
		if out == ref {
			t.Fatalf("key bit %d does not affect block 0", bit)
		}
	}
	for bit := 0; bit < 32*8; bit++ {
		n := *nonce
		n[bit/8] ^= 1 << (bit % 8)
		s := NewNoiseSchedule(key, &n)
		var out [16]byte
		noiseBlockHW(&s, &out, 0, 0)
		if out == ref {
			t.Fatalf("nonce bit %d does not affect block 0", bit)
		}
	}
}

// TestNoiseFillAllocs pins the zero-allocation contract of NoiseFill.
func TestNoiseFillAllocs(t *testing.T) {
	key, nonce := randomNoiseKeyNonce(t)
	s := NewNoiseSchedule(key, nonce)
	dst := make([]byte, 4103)
	if n := testing.AllocsPerRun(20, func() { NoiseFill(&s, dst, 0, 0) }); n != 0 {
		t.Fatalf("NoiseFill allocates %v times per call", n)
	}
}
