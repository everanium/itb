package ctr

import (
	"bytes"
	"testing"
)

// TestNewAtParity proves NewAt is byte-exact: for every cipher and a range of
// byte offsets (block-aligned and intra-block), the keystream from NewAt at
// offset O equals the serial keystream sliced at [O:]. This is the correctness
// guarantee the parallel wrapper relies on, and it is purely deterministic
// counter arithmetic — independent of CPU count or scheduling. On a 1-core
// host the wrapper simply runs one worker (offset 0 == New); the seek math
// here holds regardless.
func TestNewAtParity(t *testing.T) {
	const total = 8192
	for _, name := range []string{
		CipherAreion256, CipherAreion512, CipherSipHash24, CipherAES128CTR,
		CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3,
		CipherChaCha20,
	} {
		ksize, err := KeySize(name)
		if err != nil {
			t.Fatalf("%s: KeySize: %v", name, err)
		}
		nsize, err := NonceSize(name)
		if err != nil {
			t.Fatalf("%s: NonceSize: %v", name, err)
		}
		key := make([]byte, ksize)
		nonce := make([]byte, nsize)
		for i := range key {
			key[i] = byte(i*37 + 5)
		}
		for i := range nonce {
			nonce[i] = byte(i*19 + 3)
		}

		// Serial reference keystream.
		ref, err := New(name, key, nonce)
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		full := make([]byte, total)
		ref.XORKeyStream(full, full)

		// Offsets: 0, intra-block, block-aligned, cross-block, and an odd large one.
		for _, off := range []int{0, 1, 15, 16, 31, 32, 63, 64, 100, 1000, 4097} {
			if off >= total {
				continue
			}
			ks, err := NewAt(name, key, nonce, off)
			if err != nil {
				t.Fatalf("%s: NewAt(%d): %v", name, off, err)
			}
			got := make([]byte, total-off)
			ks.XORKeyStream(got, got)
			if !bytes.Equal(got, full[off:]) {
				t.Fatalf("%s: NewAt(%d) diverges from serial[%d:]", name, off, off)
			}
		}
	}
}
