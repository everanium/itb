package wrapper

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestWrapRoundTrip(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			rand.Read(plaintext)
			wire, err := Wrap(name, key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := Unwrap(name, key, wire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, recovered) {
				t.Fatalf("%s: round-trip mismatch", name)
			}
		})
	}
}

func TestWrapStreamReaderWriter(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, 50*1024)
			rand.Read(plaintext)

			// Wrap via NewWrapWriter.
			var wireBuf bytes.Buffer
			ww, err := NewWrapWriter(name, key, &wireBuf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ww.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			// Unwrap via NewUnwrapReader.
			rr, err := NewUnwrapReader(name, key, bytes.NewReader(wireBuf.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			recovered := make([]byte, len(plaintext))
			off := 0
			for off < len(recovered) {
				n, err := rr.Read(recovered[off:])
				if err != nil {
					t.Fatal(err)
				}
				off += n
			}
			if !bytes.Equal(plaintext, recovered) {
				t.Fatalf("%s: rw round-trip mismatch", name)
			}
		})
	}
}

// TestWrapInPlaceRoundTrip verifies that WrapInPlace mutates the blob into
// keystream-XORed bytes and returns a nonce that, when prepended, reproduces
// the canonical Wrap wire format and decrypts cleanly via Unwrap.
func TestWrapInPlaceRoundTrip(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			rand.Read(plaintext)
			original := make([]byte, len(plaintext))
			copy(original, plaintext)

			nonce, err := WrapInPlace(name, key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			nlen, err := NonceSize(name)
			if err != nil {
				t.Fatal(err)
			}
			if len(nonce) != nlen {
				t.Fatalf("%s: nonce length %d, want %d", name, len(nonce), nlen)
			}
			if bytes.Equal(original, plaintext) {
				t.Fatalf("%s: blob unchanged after WrapInPlace", name)
			}
			wire := make([]byte, 0, len(nonce)+len(plaintext))
			wire = append(wire, nonce...)
			wire = append(wire, plaintext...)
			recovered, err := Unwrap(name, key, wire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, recovered) {
				t.Fatalf("%s: WrapInPlace+Unwrap mismatch", name)
			}
		})
	}
}

// TestUnwrapInPlaceRoundTrip verifies that UnwrapInPlace reverses Wrap by
// XOR-decrypting the body slice in place and returning the aliased view.
func TestUnwrapInPlaceRoundTrip(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			rand.Read(plaintext)

			wire, err := Wrap(name, key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := UnwrapInPlace(name, key, wire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, recovered) {
				t.Fatalf("%s: UnwrapInPlace mismatch", name)
			}
		})
	}
}

// TestUnwrapInPlaceShortWire verifies the wire-shorter-than-nonce error path.
func TestUnwrapInPlaceShortWire(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			wire := []byte{0x00, 0x01, 0x02}
			if _, err := UnwrapInPlace(name, key, wire); err == nil {
				t.Fatalf("%s: expected error on short wire, got nil", name)
			}
		})
	}
}

// TestKeySizeUnknownCipher exercises the default switch branches in KeySize
// and NonceSize for an unknown cipher name.
func TestKeySizeUnknownCipher(t *testing.T) {
	if n, err := KeySize("nonexistent"); err == nil || n != 0 {
		t.Fatalf("KeySize(nonexistent): got (%d, %v), want (0, non-nil)", n, err)
	}
	if n, err := NonceSize("nonexistent"); err == nil || n != 0 {
		t.Fatalf("NonceSize(nonexistent): got (%d, %v), want (0, non-nil)", n, err)
	}
}

// TestMakeKeystreamUnknownCipher exercises the default switch branch in
// MakeKeystream.
func TestMakeKeystreamUnknownCipher(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	if ks, err := MakeKeystream("nonexistent", key, nonce); err == nil || ks != nil {
		t.Fatalf("MakeKeystream(nonexistent): got (%v, %v), want (nil, non-nil)", ks, err)
	}
}

// TestGenerateKeyUnknownCipher exercises the KeySize error propagation path
// in GenerateKey.
func TestGenerateKeyUnknownCipher(t *testing.T) {
	if k, err := GenerateKey("nonexistent"); err == nil || k != nil {
		t.Fatalf("GenerateKey(nonexistent): got (%v, %v), want (nil, non-nil)", k, err)
	}
}

// TestMakeKeystreamBadKeyLen drives MakeKeystream with a wrong-length key
// for each cipher to exercise the length-check error branches.
func TestMakeKeystreamBadKeyLen(t *testing.T) {
	cases := []struct {
		name    string
		badKey  []byte
		nonceOK []byte
	}{
		{CipherAES128CTR, make([]byte, 15), make([]byte, 16)},
		{CipherChaCha20, make([]byte, 31), make([]byte, 12)},
		{CipherSipHash24, make([]byte, 15), make([]byte, 16)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ks, err := MakeKeystream(c.name, c.badKey, c.nonceOK); err == nil || ks != nil {
				t.Fatalf("%s: expected key-length error, got (%v, %v)", c.name, ks, err)
			}
		})
	}
}

// TestMakeKeystreamBadNonceLen drives MakeKeystream with a wrong-length nonce
// for each cipher to exercise the length-check error branches.
func TestMakeKeystreamBadNonceLen(t *testing.T) {
	cases := []struct {
		name     string
		keyOK    []byte
		badNonce []byte
	}{
		{CipherAES128CTR, make([]byte, 16), make([]byte, 15)},
		{CipherChaCha20, make([]byte, 32), make([]byte, 11)},
		{CipherSipHash24, make([]byte, 16), make([]byte, 15)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ks, err := MakeKeystream(c.name, c.keyOK, c.badNonce); err == nil || ks != nil {
				t.Fatalf("%s: expected nonce-length error, got (%v, %v)", c.name, ks, err)
			}
		})
	}
}

// TestSipHashCTRPartialBlockDrain drives sipCTR.XORKeyStream with a sequence
// of 3-byte writes (24 bytes total). The 3-byte stride is intentionally
// coprime to SipHash's 8-byte block, forcing the refill / leftover-drain
// branches on most iterations.
func TestSipHashCTRPartialBlockDrain(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)
	plaintext := make([]byte, 24)
	rand.Read(plaintext)

	// Encrypt via 3-byte chunks.
	enc, err := newSipHashCTR(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	chunked := make([]byte, 24)
	for i := 0; i < 24; i += 3 {
		enc.XORKeyStream(chunked[i:i+3], plaintext[i:i+3])
	}

	// Encrypt the same plaintext as one 24-byte block — must match.
	enc2, err := newSipHashCTR(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	whole := make([]byte, 24)
	enc2.XORKeyStream(whole, plaintext)
	if !bytes.Equal(chunked, whole) {
		t.Fatalf("siphash-ctr: chunked vs whole keystream mismatch\n chunked=%x\n whole  =%x", chunked, whole)
	}

	// Decrypt the chunked ciphertext via 3-byte chunks — must recover plaintext.
	dec, err := newSipHashCTR(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	recovered := make([]byte, 24)
	for i := 0; i < 24; i += 3 {
		dec.XORKeyStream(recovered[i:i+3], chunked[i:i+3])
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("siphash-ctr: 3-byte chunked round-trip mismatch")
	}
}

// TestSipHashCTRTailUnaligned drives a 9-byte plaintext (8-byte bulk path
// followed by a 1-byte tail) to exercise the i < n tail branch.
func TestSipHashCTRTailUnaligned(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)
	plaintext := make([]byte, 9)
	rand.Read(plaintext)

	enc, err := newSipHashCTR(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, 9)
	enc.XORKeyStream(ct, plaintext)

	dec, err := newSipHashCTR(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	recovered := make([]byte, 9)
	dec.XORKeyStream(recovered, ct)
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("siphash-ctr: 9-byte tail round-trip mismatch")
	}
}

// TestNewUnwrapReaderShortSource passes a source shorter than any cipher's
// nonce, expecting the io.ReadFull error to propagate.
func TestNewUnwrapReaderShortSource(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			src := bytes.NewReader([]byte{0x01, 0x02, 0x03})
			if r, err := NewUnwrapReader(name, key, src); err == nil || r != nil {
				t.Fatalf("%s: expected error on short source, got (%v, %v)", name, r, err)
			}
		})
	}
}

// TestNewWrapWriterUnknownCipher exercises the unknown-cipher error path in
// NewWrapWriter and NewUnwrapReader.
func TestNewWrapWriterUnknownCipher(t *testing.T) {
	key := make([]byte, 16)
	var dst bytes.Buffer
	if w, err := NewWrapWriter("nonexistent", key, &dst); err == nil || w != nil {
		t.Fatalf("NewWrapWriter(nonexistent): got (%v, %v), want (nil, non-nil)", w, err)
	}
	src := bytes.NewReader(make([]byte, 64))
	if r, err := NewUnwrapReader("nonexistent", key, src); err == nil || r != nil {
		t.Fatalf("NewUnwrapReader(nonexistent): got (%v, %v), want (nil, non-nil)", r, err)
	}
}
