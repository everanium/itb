package ctr

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb/internal/hashprf"
)

// resetCases lists every primitive the ResettableKeystream wrapper
// supports, together with the per-primitive key and nonce widths.
var resetCases = []struct {
	name      string
	keySize   int
	nonceSize int
}{
	{CipherAreion256, 32, 16},
	{CipherAreion512, 64, 16},
	{CipherBLAKE2b256, 32, 16},
	{CipherBLAKE2b512, 32, 16},
	{CipherBLAKE2s, 32, 16},
	{CipherBLAKE3, 32, 16},
	{CipherAES128CTR, 16, 16},
	{CipherSipHash24, 16, 16},
	{CipherChaCha20, 32, 12},
}

// referenceKeystream produces the leading n bytes of the (name, key,
// nonce) keystream by XORing zeros through a fresh New() instance. The
// resulting buffer is then compared against ResettableKeystream output
// sliced at arbitrary offsets.
func referenceKeystream(t *testing.T, name string, key, nonce []byte, n int) []byte {
	t.Helper()
	ks, err := New(name, key, nonce)
	if err != nil {
		t.Fatalf("New(%q): %v", name, err)
	}
	buf := make([]byte, n)
	ks.XORKeyStream(buf, buf)
	return buf
}

// randomKeyNonce draws a CSPRNG key and nonce of the requested widths.
func randomKeyNonce(t *testing.T, keySize, nonceSize int) (key, nonce []byte) {
	t.Helper()
	key = make([]byte, keySize)
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	return
}

// TestResetCounterByteIdentity is the load-bearing equivalence: for
// every supported primitive and every test offset in resetOffsets,
// ResetCounter(offset) followed by an XORKeyStream emits the same bytes
// as the reference keystream starting at offset.
func TestResetCounterByteIdentity(t *testing.T) {
	const refLen = 4096
	resetOffsets := []int{0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 511, 1023, 2048, 3000}

	for _, c := range resetCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			key, nonce := randomKeyNonce(t, c.keySize, c.nonceSize)
			ref := referenceKeystream(t, c.name, key, nonce, refLen)
			ks, err := NewResettable(c.name, key, nonce)
			if err != nil {
				t.Fatalf("NewResettable(%q): %v", c.name, err)
			}
			for _, off := range resetOffsets {
				if off >= refLen {
					continue
				}
				if err := ks.ResetCounter(off); err != nil {
					t.Fatalf("%s ResetCounter(%d): %v", c.name, off, err)
				}
				readLen := refLen - off
				if readLen > 200 {
					readLen = 200
				}
				got := make([]byte, readLen)
				ks.XORKeyStream(got, got)
				if !bytes.Equal(got, ref[off:off+readLen]) {
					t.Fatalf("%s ResetCounter(%d): keystream mismatch\n  got:  %x\n  want: %x",
						c.name, off, got, ref[off:off+readLen])
				}
			}
		})
	}
}

// TestNewResettableAtMatchesNewAt confirms the resettable constructor
// seeked to byteOffset produces the same bytes as the existing NewAt
// over a range of offsets. NewAt and NewResettableAt are two independent
// paths to the same logical keystream byte at any offset.
func TestNewResettableAtMatchesNewAt(t *testing.T) {
	offsets := []int{0, 1, 16, 17, 64, 100, 1000, 4097}
	for _, c := range resetCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			key, nonce := randomKeyNonce(t, c.keySize, c.nonceSize)
			for _, off := range offsets {
				ksA, err := NewResettableAt(c.name, key, nonce, off)
				if err != nil {
					t.Fatalf("NewResettableAt(%q, off=%d): %v", c.name, off, err)
				}
				ksB, err := NewAt(c.name, key, nonce, off)
				if err != nil {
					t.Fatalf("NewAt(%q, off=%d): %v", c.name, off, err)
				}
				const n = 256
				a := make([]byte, n)
				b := make([]byte, n)
				ksA.XORKeyStream(a, a)
				ksB.XORKeyStream(b, b)
				if !bytes.Equal(a, b) {
					t.Fatalf("%s offset=%d: NewResettableAt and NewAt diverged\n  resettable: %x\n  newAt:      %x",
						c.name, off, a, b)
				}
			}
		})
	}
}

// TestResetCounterMultipleHops checks that calling ResetCounter several
// times in succession on one keystream object continues to produce the
// reference bytes at each visited offset, with no carry-over state from
// the previous position.
func TestResetCounterMultipleHops(t *testing.T) {
	const refLen = 2048
	hops := []struct {
		off, n int
	}{
		{0, 80},
		{1000, 50},
		{17, 200},
		{1500, 100},
		{64, 64},
		{511, 33},
	}
	for _, c := range resetCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			key, nonce := randomKeyNonce(t, c.keySize, c.nonceSize)
			ref := referenceKeystream(t, c.name, key, nonce, refLen)
			ks, err := NewResettable(c.name, key, nonce)
			if err != nil {
				t.Fatalf("NewResettable(%q): %v", c.name, err)
			}
			for _, h := range hops {
				if err := ks.ResetCounter(h.off); err != nil {
					t.Fatalf("%s ResetCounter(%d): %v", c.name, h.off, err)
				}
				got := make([]byte, h.n)
				ks.XORKeyStream(got, got)
				if !bytes.Equal(got, ref[h.off:h.off+h.n]) {
					t.Fatalf("%s hop off=%d n=%d: keystream mismatch", c.name, h.off, h.n)
				}
			}
		})
	}
}

// TestResetCounterXorRecovery verifies the round-trip property: XORing
// the ciphertext with a fresh keystream positioned at the same offset
// recovers the plaintext exactly. Two independent ResettableKeystream
// instances stand in for the encrypt and decrypt sides.
func TestResetCounterXorRecovery(t *testing.T) {
	const totalLen = 1024
	for _, c := range resetCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			key, nonce := randomKeyNonce(t, c.keySize, c.nonceSize)
			plain := make([]byte, totalLen)
			if _, err := rand.Read(plain); err != nil {
				t.Fatalf("rand plain: %v", err)
			}
			cipherBuf := make([]byte, totalLen)

			enc, err := NewResettable(c.name, key, nonce)
			if err != nil {
				t.Fatalf("NewResettable(%q): %v", c.name, err)
			}
			// Encrypt in non-sequential chunks, jumping around with
			// ResetCounter; the result must match a serial XOR.
			windows := []struct{ off, n int }{
				{0, 200},
				{500, 100},
				{200, 300},
				{600, 200},
				{800, 224},
			}
			for _, w := range windows {
				if err := enc.ResetCounter(w.off); err != nil {
					t.Fatalf("encrypt ResetCounter(%d): %v", w.off, err)
				}
				enc.XORKeyStream(cipherBuf[w.off:w.off+w.n], plain[w.off:w.off+w.n])
			}

			dec, err := NewResettable(c.name, key, nonce)
			if err != nil {
				t.Fatalf("NewResettable decrypt(%q): %v", c.name, err)
			}
			// Decrypt with one serial pass — XOR'ing the keystream over
			// the assembled ciphertext must restore the plaintext.
			recovered := make([]byte, totalLen)
			dec.XORKeyStream(recovered, cipherBuf)
			if !bytes.Equal(recovered, plain) {
				t.Fatalf("%s: recovered plaintext differs from input", c.name)
			}
		})
	}
}

// TestResetCounterRejectsNegative confirms every implementation rejects
// a negative byteOffset rather than silently wrapping.
func TestResetCounterRejectsNegative(t *testing.T) {
	for _, c := range resetCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			key, nonce := randomKeyNonce(t, c.keySize, c.nonceSize)
			ks, err := NewResettable(c.name, key, nonce)
			if err != nil {
				t.Fatalf("NewResettable(%q): %v", c.name, err)
			}
			if err := ks.ResetCounter(-1); err == nil {
				t.Errorf("%s: ResetCounter(-1) accepted negative offset", c.name)
			}
		})
	}
	if _, err := NewResettableAt(CipherAES128CTR, make([]byte, 16), make([]byte, 16), -1); err == nil {
		t.Error("NewResettableAt(aescmac, -1) accepted negative offset")
	}
}

// TestNewResettableErrors confirms the validation paths in
// NewResettable: unknown name, wrong key length, wrong nonce length.
func TestNewResettableErrors(t *testing.T) {
	if _, err := NewResettable("nope", make([]byte, 32), make([]byte, 16)); err == nil {
		t.Error("NewResettable(unknown): expected error")
	}
	for _, c := range resetCases {
		// Wrong key length.
		badKey := make([]byte, c.keySize-1)
		if _, err := NewResettable(c.name, badKey, make([]byte, c.nonceSize)); err == nil {
			t.Errorf("%s: NewResettable accepted short key", c.name)
		}
		// Wrong nonce length.
		badNonce := make([]byte, c.nonceSize+1)
		if _, err := NewResettable(c.name, make([]byte, c.keySize), badNonce); err == nil {
			t.Errorf("%s: NewResettable accepted oversized nonce", c.name)
		}
	}
}

// TestChaCha20ResetCounterOverflow exercises the 32-bit block-counter
// overflow guard specific to RFC 8439 ChaCha20.
func TestChaCha20ResetCounterOverflow(t *testing.T) {
	key, nonce := randomKeyNonce(t, 32, 12)
	ks, err := NewResettable(CipherChaCha20, key, nonce)
	if err != nil {
		t.Fatalf("NewResettable(chacha20): %v", err)
	}
	// blockOff = byteOffset / 64. The largest valid byteOffset has
	// blockOff <= 2^32 - 1, so anything past 64 * 2^32 must error.
	overflow := (int64(1) << 32) * 64
	if int64(int(overflow)) != overflow {
		t.Skip("platform int width cannot represent overflow boundary")
	}
	if err := ks.ResetCounter(int(overflow)); err == nil {
		t.Error("chacha20 ResetCounter accepted byteOffset that overflows 32-bit block counter")
	}
}

// TestPRFHashBatchResetCounterParity is a focused per-primitive cross-
// check between the batched and single-block PRF-counter implementations
// after ResetCounter. Both paths must produce identical bytes at the
// same offset for the Areion family (which is the only family that
// reaches the batched constructor).
func TestPRFHashBatchResetCounterParity(t *testing.T) {
	for _, name := range []string{CipherAreion256, CipherAreion512} {
		ksize, err := hashprf.KeySize(name)
		if err != nil {
			t.Fatalf("hashprf.KeySize(%q): %v", name, err)
		}
		key, nonce := randomKeyNonce(t, ksize, hashCTRNonceSize)
		// New routes Areion through prfHashCTRBatch (batched path).
		batch, err := NewResettable(name, key, nonce)
		if err != nil {
			t.Fatalf("NewResettable(%q): %v", name, err)
		}
		// Build a single-block reference by directly invoking the
		// non-batched constructor — bypasses tryNewPrfHashCTRBatch so it
		// returns *prfHashCTR.
		prf, blockSize, err := hashprf.New(name, key)
		if err != nil {
			t.Fatalf("hashprf.New(%q): %v", name, err)
		}
		single := &prfHashCTR{
			prf:       prf,
			blockSize: blockSize,
			keystrm:   make([]byte, blockSize),
			input:     make([]byte, hashCTRNonceSize+8),
		}
		copy(single.input[:hashCTRNonceSize], nonce)

		offsets := []int{0, 1, blockSize - 1, blockSize, blockSize + 1, 4*blockSize - 1, 4 * blockSize, 4*blockSize + 1, 16 * blockSize, 17 * blockSize}
		for _, off := range offsets {
			if err := batch.ResetCounter(off); err != nil {
				t.Fatalf("%s batch.ResetCounter(%d): %v", name, off, err)
			}
			if err := single.ResetCounter(off); err != nil {
				t.Fatalf("%s single.ResetCounter(%d): %v", name, off, err)
			}
			const n = 137 // not a multiple of blockSize
			a := make([]byte, n)
			b := make([]byte, n)
			batch.XORKeyStream(a, a)
			single.XORKeyStream(b, b)
			if !bytes.Equal(a, b) {
				t.Fatalf("%s offset=%d: batch and single keystream diverged after ResetCounter", name, off)
			}
		}
	}
}
