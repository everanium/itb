package ctr

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// ciphers enumerates the three stream-capable registry primitives with their
// expected key and nonce sizes.
var ciphers = []struct {
	name      string
	keySize   int
	nonceSize int
}{
	{CipherAES128CTR, 16, 16},
	{CipherChaCha20, 32, 12},
	{CipherSipHash24, 16, 16},
}

func mustRead(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read(%d): %v", n, err)
	}
	return b
}

func newKS(t *testing.T, name string, key, nonce []byte) Keystream {
	t.Helper()
	ks, err := New(name, key, nonce)
	if err != nil {
		t.Fatalf("New(%q): %v", name, err)
	}
	return ks
}

// TestKeyNonceSizes verifies the declared key and nonce sizes per cipher and
// the unknown-name error path.
func TestKeyNonceSizes(t *testing.T) {
	for _, c := range ciphers {
		ks, err := KeySize(c.name)
		if err != nil {
			t.Fatalf("KeySize(%q): %v", c.name, err)
		}
		if ks != c.keySize {
			t.Errorf("KeySize(%q) = %d, want %d", c.name, ks, c.keySize)
		}
		ns, err := NonceSize(c.name)
		if err != nil {
			t.Fatalf("NonceSize(%q): %v", c.name, err)
		}
		if ns != c.nonceSize {
			t.Errorf("NonceSize(%q) = %d, want %d", c.name, ns, c.nonceSize)
		}
	}

	if _, err := KeySize("nope"); err == nil {
		t.Error("KeySize(unknown) returned nil error")
	}
	if _, err := NonceSize("nope"); err == nil {
		t.Error("NonceSize(unknown) returned nil error")
	}
	if _, err := New("nope", nil, nil); err == nil {
		t.Error("New(unknown) returned nil error")
	}
}

// TestUnsupportedRegistryPrimitives confirms primitives outside the three
// stream-capable names are rejected by every entry point.
func TestUnsupportedRegistryPrimitives(t *testing.T) {
	for _, name := range []string{"blake3", "blake2s", "areion256", "md5", "crc128", "fnv1a"} {
		if _, err := KeySize(name); err == nil {
			t.Errorf("KeySize(%q) returned nil error", name)
		}
		if _, err := NonceSize(name); err == nil {
			t.Errorf("NonceSize(%q) returned nil error", name)
		}
		if _, err := New(name, make([]byte, 32), make([]byte, 16)); err == nil {
			t.Errorf("New(%q) returned nil error", name)
		}
	}
}

// TestRoundTrip XORs a fresh Keystream over plaintext, then XORs a second fresh
// Keystream (same key+nonce) over the ciphertext and recovers the plaintext.
func TestRoundTrip(t *testing.T) {
	for _, c := range ciphers {
		for _, size := range []int{0, 1, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100, 1024} {
			key := mustRead(t, c.keySize)
			nonce := mustRead(t, c.nonceSize)
			pt := mustRead(t, size)

			ct := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(ct, pt)

			rt := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(rt, ct)

			if !bytes.Equal(rt, pt) {
				t.Errorf("%s size=%d: round-trip mismatch", c.name, size)
			}
			if size > 0 && bytes.Equal(ct, pt) {
				t.Errorf("%s size=%d: ciphertext equals plaintext", c.name, size)
			}
		}
	}
}

// TestChunkedVsWhole confirms keystream continuity: XORing in small chunks
// produces the same output as XORing the whole buffer at once. This exercises
// the sipCTR drain / bulk / tail boundaries.
func TestChunkedVsWhole(t *testing.T) {
	for _, c := range ciphers {
		for _, total := range []int{0, 1, 3, 16, 17, 31, 48, 100, 257} {
			key := mustRead(t, c.keySize)
			nonce := mustRead(t, c.nonceSize)
			pt := mustRead(t, total)

			whole := make([]byte, total)
			newKS(t, c.name, key, nonce).XORKeyStream(whole, pt)

			for _, chunk := range []int{1, 3, 7, 16} {
				chunked := make([]byte, total)
				ks := newKS(t, c.name, key, nonce)
				for off := 0; off < total; off += chunk {
					end := off + chunk
					if end > total {
						end = total
					}
					ks.XORKeyStream(chunked[off:end], pt[off:end])
				}
				if !bytes.Equal(chunked, whole) {
					t.Errorf("%s total=%d chunk=%d: chunked != whole", c.name, total, chunk)
				}
			}
		}
	}
}

// TestTailSizes targets the sub-block tails of the 16-byte SipHash-CTR block
// (and exercises the same odd sizes for the other ciphers).
func TestTailSizes(t *testing.T) {
	for _, c := range ciphers {
		for _, size := range []int{0, 1, 9, 17} {
			key := mustRead(t, c.keySize)
			nonce := mustRead(t, c.nonceSize)
			pt := mustRead(t, size)

			ct := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(ct, pt)
			rt := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(rt, ct)
			if !bytes.Equal(rt, pt) {
				t.Errorf("%s size=%d: tail round-trip mismatch", c.name, size)
			}
		}
	}
}

// TestWrongKeyLength rejects keys whose length does not match KeySize(name).
func TestWrongKeyLength(t *testing.T) {
	for _, c := range ciphers {
		nonce := make([]byte, c.nonceSize)
		for _, bad := range []int{0, c.keySize - 1, c.keySize + 1} {
			if bad < 0 {
				continue
			}
			if _, err := New(c.name, make([]byte, bad), nonce); err == nil {
				t.Errorf("New(%q) accepted key length %d (want %d)", c.name, bad, c.keySize)
			}
		}
	}
}

// TestWrongNonceLength rejects nonces whose length does not match
// NonceSize(name).
func TestWrongNonceLength(t *testing.T) {
	for _, c := range ciphers {
		key := make([]byte, c.keySize)
		for _, bad := range []int{0, c.nonceSize - 1, c.nonceSize + 1} {
			if bad < 0 {
				continue
			}
			if _, err := New(c.name, key, make([]byte, bad)); err == nil {
				t.Errorf("New(%q) accepted nonce length %d (want %d)", c.name, bad, c.nonceSize)
			}
		}
	}
}
