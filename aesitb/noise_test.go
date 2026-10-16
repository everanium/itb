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
	{0, 0, "04a712ed4fb89ef505280c67c3da3c4c"},
	{1, 0, "f54f4d640b61bf55d1b36034cd183462"},
	{2, 0, "fcf7bae0c0b04bf06723b3b6e1f0c587"},
	{255, 0, "7958b60279a6ae873686dfb82858fa85"},
	{256, 0, "e147227fc7f8f4f30b344dea692c3359"},
	{1<<32 - 1, 0, "3c3cb305228cb0e05d671ce79aff9bad"},
	{1 << 32, 0, "ada84cd96fc1fd2ca3c1b831cf39aa7a"},
	{^uint64(0), 0, "f6aab7411f5153191ed9ffac35b132d9"},
	{0, 1, "57d809a12b99a77af64c85713b278226"},
	{^uint64(0), ^uint64(0), "ec5d695d5f45414c81081084801edcf5"},
}

// Stream digests of the filler under refKey / refNonce(32) from block 0.
const (
	noiseFirst64     = "04a712ed4fb89ef505280c67c3da3c4cf54f4d640b61bf55d1b36034cd183462fcf7bae0c0b04bf06723b3b6e1f0c58790bae52b8836700b12adc295b3648f02"
	noiseSHA256of64  = "71d6e7322e19020148109ed6c638fc88bffb973ad976be3a2abad5599b886eac"
	noiseSHA256of4K  = "508816bf187fdd45b0350dbe1dc51e050805dfc90cc20bc894c9038eb68c5ba8" // first 4103 bytes
	noiseSHA256of64K = "3478b173ae833dfa37e466afe2a248d63ae456d8d6cf8a372b0976666d288eb2"
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
