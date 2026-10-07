package aesitb

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// noiseVector is one known-answer block of the filler under refKey and
// refNonce(32): block (lo, hi) equals HashGeneric(refKey, refNonce(32),
// lo, hi). The vectors were produced through the public HashGeneric and
// pin the counter placement (block index in the seed slot, nonce in the
// data slot) and the 128-bit little-endian counter layout.
type noiseVector struct {
	lo, hi uint64
	want   string
}

var noiseVectors = []noiseVector{
	{0, 0, "de74b114824defae82c8d9694ad4f638"},
	{1, 0, "876d291560d51e8cce40d233802d918f"},
	{2, 0, "aab81714c99c08718698880c914877e6"},
	{255, 0, "1ea0eafd6c3d3f0677d789fea3d4820a"},
	{256, 0, "4da8d030b0cc28c4529147f2140b7722"},
	{1<<32 - 1, 0, "39c0ab1f42637c163ee33182c73ae33d"},
	{1 << 32, 0, "9d06b1d6a4de79bf3d2db456c2443180"},
	{^uint64(0), 0, "f30deb030867dcd367d261bdc32b4010"},
	{0, 1, "6921ae55824a12a86a1b6b8978b99471"},
	{^uint64(0), ^uint64(0), "6acf3f5bf598c36a788db4713c3efd43"},
}

// Stream digests of the filler under refKey / refNonce(32) from block 0.
const (
	noiseFirst64     = "de74b114824defae82c8d9694ad4f638876d291560d51e8cce40d233802d918faab81714c99c08718698880c914877e6c1a2102f68af57d0d0d74c66f6f0a70a"
	noiseSHA256of64  = "963b4af83d8286d9362416dd591863e6db00535ee61c983e05cfb37b3c2b30a0"
	noiseSHA256of4K  = "afbd239ef4d6ba732d70612facf263df9609c0ba8ed6c05be120e62c155d2a83" // first 4103 bytes
	noiseSHA256of64K = "841159c3a446cf9a5332290cb687b9fa98fabbeb3916281e39cfa67c7e6678d8"
)

func refNonce32() *[32]byte {
	var n [32]byte
	copy(n[:], refNonce(32))
	return &n
}

// noiseRef writes len(dst) filler bytes from block 0 through the public
// HashGeneric — the definition the keyed filler is pinned to.
func noiseRef(key [16]byte, nonce []byte, dst []byte) {
	var lo, hi uint64
	for len(dst) > 0 {
		b := HashGeneric(key, nonce, lo, hi)
		n := copy(dst, b[:])
		dst = dst[n:]
		lo++
		if lo == 0 {
			hi++
		}
	}
}

// TestNoiseKAT pins the known-answer blocks to HashGeneric and the
// stream digests to the keyed filler.
func TestNoiseKAT(t *testing.T) {
	nonce := refNonce32()
	for _, v := range noiseVectors {
		got := HashGeneric(refKey, nonce[:], v.lo, v.hi)
		if hex.EncodeToString(got[:]) != v.want {
			t.Errorf("block (%d, %d): got %x, want %s", v.lo, v.hi, got, v.want)
		}
	}
	first := make([]byte, 64)
	fillNoiseKeyed(&refKey, nonce, first)
	if hex.EncodeToString(first) != noiseFirst64 {
		t.Fatalf("first 64 bytes: got %x", first)
	}
	for _, c := range []struct {
		n    int
		want string
	}{{64, noiseSHA256of64}, {4103, noiseSHA256of4K}, {1 << 16, noiseSHA256of64K}} {
		buf := make([]byte, c.n)
		fillNoiseKeyed(&refKey, nonce, buf)
		if got := hex.EncodeToString(sha256Sum(buf)); got != c.want {
			t.Errorf("sha256 of first %d bytes: got %s, want %s", c.n, got, c.want)
		}
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// TestNoiseEqualsHashGeneric pins the keyed filler to HashGeneric block
// by block under random keys and nonces at lengths that straddle every
// kernel group width and end in a partial block.
func TestNoiseEqualsHashGeneric(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 31, 33, 255, 256, 257, 4095, 4103, 65537} {
		var key [16]byte
		var nonce [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		want := make([]byte, n)
		noiseRef(key, nonce[:], want)
		got := make([]byte, n)
		for i := range got {
			got[i] = 0xA5 // overwrite semantics: the previous contents are ignored
		}
		fillNoiseKeyed(&key, &nonce, got)
		if !bytes.Equal(got, want) {
			t.Fatalf("n=%d: keyed filler differs from HashGeneric", n)
		}
	}
}

// TestFillNoiseFreshKey confirms two calls on equal-length buffers
// differ (a dropped key draw would repeat the output) and that neither
// equals the all-zero-key filler.
func TestFillNoiseFreshKey(t *testing.T) {
	a := make([]byte, 4096)
	b := make([]byte, 4096)
	if err := FillNoise(a); err != nil {
		t.Fatal(err)
	}
	if err := FillNoise(b); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two FillNoise calls produced identical output")
	}
	zero := make([]byte, 4096)
	fillNoiseKeyed(new([16]byte), new([32]byte), zero)
	if bytes.Equal(a, zero) || bytes.Equal(b, zero) {
		t.Fatal("FillNoise output equals the zero-key filler")
	}
	if err := FillNoise(nil); err != nil {
		t.Fatalf("FillNoise(nil): %v", err)
	}
}

// TestFillNoiseAllocs pins the zero-heap-allocation contract: the seed
// and the folded schedule live on the stack.
func TestFillNoiseAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation heap-allocates the stack seed")
	}
	dst := make([]byte, 4103)
	if n := testing.AllocsPerRun(20, func() { _ = FillNoise(dst) }); n != 0 {
		t.Fatalf("FillNoise allocates %v times per call", n)
	}
}
