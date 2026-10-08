package hashes

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// Guards on the ChaCha20 closure's data path: the output is not affine
// in the data, and swapping two absorbed 24-byte chunks of a 68-byte
// input changes the output. keystreamXORHash is the negative control —
// a hash that absorbs its data by XOR with a keystream independent of
// its state has both properties, and the guards must reject it.

// keystreamXORHash absorbs data into a 32-byte accumulator —
// [LE64(len) | 24-byte window] — by XOR with successive 32-byte spans of
// the ChaCha20 keystream under fixedKey ^ seed. The keystream is
// independent of the accumulator, so the digest is affine in the data.
func keystreamXORHash(fixedKey [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	var key [32]byte
	copy(key[:], fixedKey[:])
	for i := 0; i < 4; i++ {
		off := i * 8
		binary.LittleEndian.PutUint64(key[off:], binary.LittleEndian.Uint64(key[off:])^seed[i])
	}
	var nonce [12]byte
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	const window = 24
	for off := 0; off == 0 || off < len(data); off += window {
		end := off + window
		if end > len(data) {
			end = len(data)
		}
		for i := off; i < end; i++ {
			state[8+i-off] ^= data[i]
		}
		c.XORKeyStream(state[:], state[:])
	}
	var out [4]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(state[8*i:])
	}
	return out
}

// affineInData reports whether h(d1) ^ h(d2) ^ h(d3) == h(d1 ^ d2 ^ d3)
// holds on random same-length inputs — the signature of a digest that
// is affine over GF(2) in its data — in every one of trials.
func affineInData(h func([]byte, [4]uint64) [4]uint64, n int, r *rand.Rand, trials int) bool {
	seed := [4]uint64{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()}
	for t := 0; t < trials; t++ {
		d := make([][]byte, 3)
		for i := range d {
			d[i] = make([]byte, n)
			r.Read(d[i])
		}
		x := make([]byte, n)
		for i := range x {
			x[i] = d[0][i] ^ d[1][i] ^ d[2][i]
		}
		o0, o1, o2, ox := h(d[0], seed), h(d[1], seed), h(d[2], seed), h(x, seed)
		for i := range ox {
			if o0[i]^o1[i]^o2[i] != ox[i] {
				return false
			}
		}
	}
	return true
}

// windowSwapCollides reports whether swapping the first two 24-byte
// windows of a random 68-byte input leaves the digest unchanged.
func windowSwapCollides(h func([]byte, [4]uint64) [4]uint64, r *rand.Rand) bool {
	seed := [4]uint64{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()}
	d := make([]byte, 68)
	r.Read(d)
	s := append([]byte(nil), d...)
	copy(s[0:24], d[24:48])
	copy(s[24:48], d[0:24])
	return !bytes.Equal(d, s) && h(d, seed) == h(s, seed)
}

func TestChaCha20NotAffineInData(t *testing.T) {
	r := rand.New(rand.NewSource(0x5EED))
	var fixedKey [32]byte
	r.Read(fixedKey[:])
	h := ChaCha20WithKey(fixedKey)
	ks := func(data []byte, seed [4]uint64) [4]uint64 { return keystreamXORHash(fixedKey, data, seed) }
	for _, n := range []int{13, 17, 20, 33, 36, 65, 68} {
		if affineInData(h, n, r, 8) {
			t.Errorf("n=%d: the ChaCha20 digest is affine in the data", n)
		}
		if !affineInData(ks, n, r, 8) {
			t.Errorf("n=%d: the keystream-XOR shape is expected to be affine; the guard does not discriminate", n)
		}
	}
	if windowSwapCollides(h, r) {
		t.Error("swapping two 24-byte windows of a 68-byte input leaves the ChaCha20 digest unchanged")
	}
	if !windowSwapCollides(ks, r) {
		t.Error("the keystream-XOR shape is expected to collide under a window swap; the guard does not discriminate")
	}
	// The first output word must depend on the data at every shape.
	seed := [4]uint64{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()}
	for _, n := range []int{13, 20, 36, 68} {
		d1, d2 := make([]byte, n), make([]byte, n)
		r.Read(d1)
		r.Read(d2)
		if h(d1, seed)[0] == h(d2, seed)[0] {
			t.Errorf("n=%d: output word 0 does not depend on the data", n)
		}
	}
}
