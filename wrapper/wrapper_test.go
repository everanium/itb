package wrapper

import (
	"bytes"
	"crypto/mlkem"
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
		{CipherSipHash24, make([]byte, 15), make([]byte, 16)},
		{CipherChaCha20, make([]byte, 31), make([]byte, 12)},
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
		{CipherSipHash24, make([]byte, 16), make([]byte, 15)},
		{CipherChaCha20, make([]byte, 32), make([]byte, 11)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ks, err := MakeKeystream(c.name, c.keyOK, c.badNonce); err == nil || ks != nil {
				t.Fatalf("%s: expected nonce-length error, got (%v, %v)", c.name, ks, err)
			}
		})
	}
}

// TestSipHashCTRPartialBlockDrain drives the siphash24 keystream (via
// MakeKeystream) with a sequence of 3-byte writes (24 bytes total). The
// 3-byte stride is intentionally coprime to the 16-byte keystream block,
// forcing the refill / leftover-drain branches on most iterations.
func TestSipHashCTRPartialBlockDrain(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)
	plaintext := make([]byte, 24)
	rand.Read(plaintext)

	// Encrypt via 3-byte chunks.
	enc, err := MakeKeystream(CipherSipHash24, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	chunked := make([]byte, 24)
	for i := 0; i < 24; i += 3 {
		enc.XORKeyStream(chunked[i:i+3], plaintext[i:i+3])
	}

	// Encrypt the same plaintext as one 24-byte block — must match.
	enc2, err := MakeKeystream(CipherSipHash24, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	whole := make([]byte, 24)
	enc2.XORKeyStream(whole, plaintext)
	if !bytes.Equal(chunked, whole) {
		t.Fatalf("siphash-ctr: chunked vs whole keystream mismatch\n chunked=%x\n whole  =%x", chunked, whole)
	}

	// Decrypt the chunked ciphertext via 3-byte chunks — must recover plaintext.
	dec, err := MakeKeystream(CipherSipHash24, key, nonce)
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

// TestSipHashCTRTailUnaligned drives a 17-byte plaintext (one 16-byte bulk
// block followed by a 1-byte tail) to exercise the i < n tail branch.
func TestSipHashCTRTailUnaligned(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)
	plaintext := make([]byte, 17)
	rand.Read(plaintext)

	enc, err := MakeKeystream(CipherSipHash24, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, 17)
	enc.XORKeyStream(ct, plaintext)

	dec, err := MakeKeystream(CipherSipHash24, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	recovered := make([]byte, 17)
	dec.XORKeyStream(recovered, ct)
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("siphash-ctr: 17-byte tail round-trip mismatch")
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

// TestDeriveKey checks DeriveKey across every cipher: correct length,
// determinism in (name, master), distinctness across masters, and that the
// derived key round-trips through Wrap / Unwrap.
func TestDeriveKey(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	other := make([]byte, 32)
	rand.Read(other)

	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			want, err := KeySize(name)
			if err != nil {
				t.Fatal(err)
			}
			k1, err := DeriveKey(name, master)
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if len(k1) != want {
				t.Fatalf("DeriveKey(%s) len = %d, want %d", name, len(k1), want)
			}
			if k2, _ := DeriveKey(name, master); !bytes.Equal(k1, k2) {
				t.Fatalf("DeriveKey(%s) not deterministic", name)
			}
			if k3, _ := DeriveKey(name, other); bytes.Equal(k1, k3) {
				t.Fatalf("DeriveKey(%s) collided across distinct masters", name)
			}

			pt := []byte("derive-key round-trip payload")
			wire, err := Wrap(name, k1, pt)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			got, err := Unwrap(name, k1, wire)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("DeriveKey(%s) round-trip mismatch", name)
			}
		})
	}
}

// TestDeriveKeyDomainSeparation confirms the cipher name is bound into the
// derivation: one master yields independent keys per cipher even when two
// ciphers share the same key length.
func TestDeriveKeyDomainSeparation(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	ka, err := DeriveKey(CipherAES128CTR, master)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := DeriveKey(CipherSipHash24, master)
	if err != nil {
		t.Fatal(err)
	}
	if len(ka) != len(ks) {
		t.Fatalf("precondition: aes and siphash key lengths differ (%d vs %d)", len(ka), len(ks))
	}
	if bytes.Equal(ka, ks) {
		t.Fatal("DeriveKey: aes and siphash keys identical under the same master")
	}
}

// TestDeriveKeyUnknownCipher exercises the KeySize error path in DeriveKey.
func TestDeriveKeyUnknownCipher(t *testing.T) {
	if k, err := DeriveKey("nonexistent", make([]byte, 32)); err == nil || k != nil {
		t.Fatalf("DeriveKey(nonexistent): got (%v, %v), want (nil, non-nil)", k, err)
	}
}

// TestDeriveKeyFromMLKEM demonstrates the intended post-quantum workflow: an
// ML-KEM-768 shared secret feeds DeriveKey directly, and both endpoints
// derive the same outer key from their respective shared-key copies, which
// then round-trips through the wrapper.
func TestDeriveKeyFromMLKEM(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	sharedEnc, ct := dk.EncapsulationKey().Encapsulate()
	sharedDec, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedEnc, sharedDec) {
		t.Fatal("ML-KEM shared keys differ between endpoints")
	}

	for _, name := range CipherNames {
		kEnc, err := DeriveKey(name, sharedEnc)
		if err != nil {
			t.Fatalf("DeriveKey(enc): %v", err)
		}
		kDec, err := DeriveKey(name, sharedDec)
		if err != nil {
			t.Fatalf("DeriveKey(dec): %v", err)
		}
		if !bytes.Equal(kEnc, kDec) {
			t.Fatalf("%s: derived keys differ across ML-KEM endpoints", name)
		}
		wire, err := Wrap(name, kEnc, []byte("ml-kem derived payload"))
		if err != nil {
			t.Fatalf("%s: Wrap: %v", name, err)
		}
		got, err := Unwrap(name, kDec, wire)
		if err != nil || string(got) != "ml-kem derived payload" {
			t.Fatalf("%s: ml-kem-derived round-trip failed: got=%q err=%v", name, got, err)
		}
	}
}

// TestWrapStreamReaderWriterLargeChunks drives the parallel reseed path: a
// payload streamed in 1 MiB chunks (each well above ParallelThreshold) plus a
// small tail, read back with different chunk boundaries. Every large chunk is
// XORed across workers and the serial keystream re-seated afterwards, so the
// recovered plaintext must match regardless of how either side splits the
// stream — proving the one logical keystream stays continuous across the
// parallel / serial split points.
func TestWrapStreamReaderWriterLargeChunks(t *testing.T) {
	const chunk = 1 << 20 // 1 MiB, > ParallelThreshold
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", name, err)
			}
			total := 4*chunk + 333 // 4 MiB + small tail
			plaintext := make([]byte, total)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("rand: %v", err)
			}

			var wireBuf bytes.Buffer
			ww, err := NewWrapWriter(name, key, &wireBuf)
			if err != nil {
				t.Fatalf("NewWrapWriter(%s): %v", name, err)
			}
			// Encrypt in 1 MiB chunks (parallel) then the small tail.
			for off := 0; off < total; off += chunk {
				end := off + chunk
				if end > total {
					end = total
				}
				if _, err := ww.Write(plaintext[off:end]); err != nil {
					t.Fatalf("Write[%d:%d]: %v", off, end, err)
				}
			}

			// Decrypt with different boundaries (~1.33 MiB) so keystream
			// continuity is split-independent.
			rr, err := NewUnwrapReader(name, key, bytes.NewReader(wireBuf.Bytes()))
			if err != nil {
				t.Fatalf("NewUnwrapReader(%s): %v", name, err)
			}
			recovered := make([]byte, total)
			dchunk := chunk + chunk/3
			for off := 0; off < total; off += dchunk {
				end := off + dchunk
				if end > total {
					end = total
				}
				dst := recovered[off:end]
				for got := 0; got < len(dst); {
					n, rerr := rr.Read(dst[got:])
					got += n
					if n == 0 && rerr == nil {
						t.Fatalf("Read[%d:%d]: zero-length read without error", off, end)
					}
					if rerr != nil && got < len(dst) {
						t.Fatalf("Read[%d:%d]: %v", off, end, rerr)
					}
				}
			}
			if !bytes.Equal(recovered, plaintext) {
				t.Fatalf("%s: large-chunk stream round-trip mismatch", name)
			}
		})
	}
}

// TestXORParallelMatchesSerial drives XORParallel at a buffer size
// well above ParallelThreshold and verifies the output is byte-equal
// to a single serial keystream of the same (name, key, nonce). This
// exercises the C-ABI public entry as well as the parallel chunking
// path inside xorParallelAt that the wire-format tests touch only
// transitively.
func TestXORParallelMatchesSerial(t *testing.T) {
	const n = 4 * ParallelThreshold
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			nonce, err := generateNonce(name)
			if err != nil {
				t.Fatalf("generateNonce: %v", err)
			}
			src := make([]byte, n)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("rand: %v", err)
			}

			gotParallel := make([]byte, n)
			if err := XORParallel(name, key, nonce, gotParallel, src); err != nil {
				t.Fatalf("XORParallel: %v", err)
			}

			ks, err := MakeKeystream(name, key, nonce)
			if err != nil {
				t.Fatalf("MakeKeystream: %v", err)
			}
			wantSerial := make([]byte, n)
			ks.XORKeyStream(wantSerial, src)

			if !bytes.Equal(gotParallel, wantSerial) {
				t.Fatalf("XORParallel output differs from serial keystream")
			}

			// Inverse round-trip - XORing the parallel output a second
			// time recovers the plaintext bit-exactly.
			back := make([]byte, n)
			if err := XORParallel(name, key, nonce, back, gotParallel); err != nil {
				t.Fatalf("XORParallel inverse: %v", err)
			}
			if !bytes.Equal(back, src) {
				t.Fatalf("XORParallel round-trip mismatch")
			}
		})
	}
}

// TestXORParallelAtBaseOffset drives XORParallelAt at a non-zero base
// offset and verifies the output matches a single serial keystream
// advanced to the same offset. Exposes the streaming-continuity contract
// of the C-ABI entry point.
func TestXORParallelAtBaseOffset(t *testing.T) {
	const head = 1024
	const body = 4 * ParallelThreshold
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			nonce, err := generateNonce(name)
			if err != nil {
				t.Fatalf("generateNonce: %v", err)
			}

			full := make([]byte, head+body)
			if _, err := rand.Read(full); err != nil {
				t.Fatalf("rand: %v", err)
			}

			// Serial reference: one keystream over the whole buffer.
			ks, err := MakeKeystream(name, key, nonce)
			if err != nil {
				t.Fatalf("MakeKeystream: %v", err)
			}
			want := make([]byte, head+body)
			ks.XORKeyStream(want, full)

			// Two-stage parallel: first XOR the head at offset 0, then
			// the body at offset head via XORParallelAt. The combined
			// output must equal the single-keystream reference.
			got := make([]byte, head+body)
			if err := XORParallelAt(name, key, nonce, 0, got[:head], full[:head]); err != nil {
				t.Fatalf("XORParallelAt head: %v", err)
			}
			if err := XORParallelAt(name, key, nonce, head, got[head:], full[head:]); err != nil {
				t.Fatalf("XORParallelAt body: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("XORParallelAt two-stage output differs from one-stage serial keystream")
			}
		})
	}
}

// TestXORParallelInPlace verifies that XORParallel accepts dst and
// src aliasing the same slice - the documented in-place mode.
func TestXORParallelInPlace(t *testing.T) {
	const n = 2 * ParallelThreshold
	key, err := GenerateKey(CipherBLAKE3)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	nonce, err := generateNonce(CipherBLAKE3)
	if err != nil {
		t.Fatalf("generateNonce: %v", err)
	}
	original := make([]byte, n)
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("rand: %v", err)
	}
	buf := append([]byte(nil), original...)
	if err := XORParallel(CipherBLAKE3, key, nonce, buf, buf); err != nil {
		t.Fatalf("XORParallel in-place encrypt: %v", err)
	}
	if bytes.Equal(buf, original) {
		t.Fatalf("XORParallel in-place: buffer unchanged")
	}
	// XOR again - recovers the original.
	if err := XORParallel(CipherBLAKE3, key, nonce, buf, buf); err != nil {
		t.Fatalf("XORParallel in-place decrypt: %v", err)
	}
	if !bytes.Equal(buf, original) {
		t.Fatalf("XORParallel in-place round-trip mismatch")
	}
}

// The wrapWorkers w > maxWrapWorkers cap, the rand.Read failure
// branches in GenerateKey / generateNonce, and the "if err != nil"
// arms guarding ctr.New / ctr.NewAt failure for a name that already
// passed the name-validation step are intentionally left untested -
// they require either >32 logical CPUs visible to the runtime or a
// crypto/rand environment failure, neither of which a unit test can
// trigger portably.

// TestWrapUnknownCipher exercises the unknown-cipher error path in
// Wrap. The leading generateNonce call fails with a NonceSize lookup
// error before any keystream work runs.
func TestWrapUnknownCipher(t *testing.T) {
	if out, err := Wrap("nonexistent", make([]byte, 16), []byte("payload")); err == nil || out != nil {
		t.Fatalf("Wrap(nonexistent): got (%v, %v), want (nil, non-nil)", out, err)
	}
}

// TestUnwrapUnknownCipher exercises the unknown-cipher error path in
// Unwrap. The NonceSize lookup fails before any wire-length check.
func TestUnwrapUnknownCipher(t *testing.T) {
	if out, err := Unwrap("nonexistent", make([]byte, 16), make([]byte, 64)); err == nil || out != nil {
		t.Fatalf("Unwrap(nonexistent): got (%v, %v), want (nil, non-nil)", out, err)
	}
}

// TestUnwrapShortWire exercises the wire-shorter-than-nonce branch on
// Unwrap (the in-place variant is already tested by the existing
// suite; the allocating Unwrap path is not).
func TestUnwrapShortWire(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			wire := []byte{0x00, 0x01, 0x02}
			if out, err := Unwrap(name, key, wire); err == nil || out != nil {
				t.Fatalf("%s: expected error on short wire, got (%v, %v)", name, out, err)
			}
		})
	}
}

// TestWrapInPlaceUnknownCipher exercises the unknown-cipher error path
// in WrapInPlace. The leading generateNonce call fails first.
func TestWrapInPlaceUnknownCipher(t *testing.T) {
	if nonce, err := WrapInPlace("nonexistent", make([]byte, 16), make([]byte, 64)); err == nil || nonce != nil {
		t.Fatalf("WrapInPlace(nonexistent): got (%v, %v), want (nil, non-nil)", nonce, err)
	}
}

// TestUnwrapInPlaceUnknownCipher mirrors the in-place variant of the
// unknown-cipher rejection path - the NonceSize lookup fails before
// the wire-length check.
func TestUnwrapInPlaceUnknownCipher(t *testing.T) {
	if out, err := UnwrapInPlace("nonexistent", make([]byte, 16), make([]byte, 64)); err == nil || out != nil {
		t.Fatalf("UnwrapInPlace(nonexistent): got (%v, %v), want (nil, non-nil)", out, err)
	}
}
