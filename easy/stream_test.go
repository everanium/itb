// Package easy_test (external) — round-trip and preflight matrix for
// the plain (non-authenticated) stream IO surface on
// [easy.Encryptor]: EncryptStreamIO and DecryptStreamIO. Coverage
// mirrors the Streaming AEAD IO suite at the plain-stream wrapper
// level, modulo the AEAD-specific tamper / truncate-tail cases that
// have no analogue without a per-chunk MAC.
package easy_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb/easy"
)

// streamSpec lists the (primitive, key_bits) pairs the plain-stream
// IO round-trip tests exercise. One representative PRF per native
// hash width keeps the matrix compact while still covering 128 / 256
// / 512 width dispatch.
var streamSpec = []struct {
	name    string
	keyBits int
	width   int
}{
	{"siphash24", 512, 128},
	{"blake3", 512, 256},
	{"blake2b512", 512, 512},
}

// streamModes lists the two Ouroboros shapes used by every plain
// stream IO round-trip test.
var streamModes = []struct {
	name string
	mode int
}{
	{"Single", 1},
	{"Triple", 3},
}

// generateDataStream fills an n-byte slice with crypto/rand bytes
// for plain stream IO test plaintext.
func generateDataStream(n int) []byte {
	b := make([]byte, n)
	if n == 0 {
		return b
	}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// newStreamEncryptor builds an encryptor for the given primitive /
// key_bits / mode combination. mode = 1 selects [easy.New] (Single
// Ouroboros); mode = 3 selects [easy.New3] (Triple Ouroboros).
func newStreamEncryptor(primitive string, keyBits, mode int) *easy.Encryptor {
	if mode == 3 {
		return easy.New3(primitive, keyBits)
	}
	return easy.New(primitive, keyBits)
}

// streamIOSizes covers the {1, cs-1, cs, cs+1, 10*cs} payload matrix
// for the plain stream IO round-trip. The empty-input case is omitted
// because the underlying single-shot Encrypt path rejects empty
// plaintext (the streaming helper preserves that semantic by simply
// not emitting any chunk).
func streamIOSizes(chunkSize int) []int {
	return []int{1, chunkSize - 1, chunkSize, chunkSize + 1, 10 * chunkSize}
}

// TestEasyStreamIORoundtripMatrix exercises EncryptStreamIO →
// DecryptStreamIO across the (primitive width × Single/Triple ×
// payload size) matrix.
func TestEasyStreamIORoundtripMatrix(t *testing.T) {
	const chunkSize = 1024

	for _, ps := range streamSpec {
		for _, m := range streamModes {
			for _, sz := range streamIOSizes(chunkSize) {
				name := fmt.Sprintf("%s_w%d_%s_sz%d", ps.name, ps.width, m.name, sz)
				t.Run(name, func(t *testing.T) {
					enc := newStreamEncryptor(ps.name, ps.keyBits, m.mode)
					defer enc.Close()

					plaintext := generateDataStream(sz)
					var wire bytes.Buffer
					if err := enc.EncryptStreamIO(bytes.NewReader(plaintext), &wire, chunkSize); err != nil {
						t.Fatalf("EncryptStreamIO: %v", err)
					}
					var recovered bytes.Buffer
					if err := enc.DecryptStreamIO(bytes.NewReader(wire.Bytes()), &recovered); err != nil {
						t.Fatalf("DecryptStreamIO: %v", err)
					}
					if !bytes.Equal(recovered.Bytes(), plaintext) {
						t.Errorf("plaintext roundtrip mismatch: got %d bytes, want %d",
							recovered.Len(), len(plaintext))
					}
				})
			}
		}
	}
}

// TestEasyStreamIOEmptyInputEmitsNothing confirms a 0-byte plaintext
// produces no on-wire output. The plain stream path mirrors the
// underlying single-shot Encrypt's empty-input rejection by simply
// not emitting any chunk.
func TestEasyStreamIOEmptyInputEmitsNothing(t *testing.T) {
	enc := easy.New("siphash24", 512)
	defer enc.Close()

	var wire bytes.Buffer
	if err := enc.EncryptStreamIO(bytes.NewReader(nil), &wire, 1024); err != nil {
		t.Fatalf("EncryptStreamIO empty: %v", err)
	}
	if wire.Len() != 0 {
		t.Errorf("expected empty wire output for empty input, got %d bytes", wire.Len())
	}
}

// TestEasyStreamIOCrossAPIParityIOToCallback confirms a transcript
// produced via EncryptStreamIO decrypts cleanly through the existing
// callback-driven DecryptStream surface.
func TestEasyStreamIOCrossAPIParityIOToCallback(t *testing.T) {
	const chunkSize = 1024
	plaintext := generateDataStream(8192)

	enc := easy.New("siphash24", 512)
	defer enc.Close()

	var wire bytes.Buffer
	if err := enc.EncryptStreamIO(bytes.NewReader(plaintext), &wire, chunkSize); err != nil {
		t.Fatalf("EncryptStreamIO: %v", err)
	}
	var recovered bytes.Buffer
	if err := enc.DecryptStream(wire.Bytes(), func(chunk []byte) error {
		_, e := recovered.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("DecryptStream (callback): %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("IO-encode → callback-decode mismatch: got %d bytes, want %d",
			recovered.Len(), len(plaintext))
	}
}

// TestEasyStreamIOCrossAPIParityCallbackToIO confirms the reverse
// direction — a transcript produced via the callback-driven
// EncryptStream decrypts cleanly through DecryptStreamIO.
func TestEasyStreamIOCrossAPIParityCallbackToIO(t *testing.T) {
	plaintext := generateDataStream(8192)

	enc := easy.New("siphash24", 512)
	defer enc.Close()
	enc.SetChunkSize(1024)

	var wire bytes.Buffer
	if err := enc.EncryptStream(plaintext, func(chunk []byte) error {
		_, e := wire.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("EncryptStream (callback): %v", err)
	}
	var recovered bytes.Buffer
	if err := enc.DecryptStreamIO(bytes.NewReader(wire.Bytes()), &recovered); err != nil {
		t.Fatalf("DecryptStreamIO: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("callback-encode → IO-decode mismatch: got %d bytes, want %d",
			recovered.Len(), len(plaintext))
	}
}

// TestEasyStreamIOEncryptChunkSizeNonPositive verifies the chunkSize
// ≤ 0 preflight rejects without consuming the reader.
func TestEasyStreamIOEncryptChunkSizeNonPositive(t *testing.T) {
	enc := easy.New("siphash24", 512)
	defer enc.Close()

	for _, cs := range []int{0, -1, -1024} {
		t.Run(fmt.Sprintf("cs%d", cs), func(t *testing.T) {
			r := bytes.NewReader([]byte("payload"))
			var w bytes.Buffer
			err := enc.EncryptStreamIO(r, &w, cs)
			if err == nil {
				t.Fatal("expected error on non-positive chunkSize, got nil")
			}
			if r.Len() != len("payload") {
				t.Errorf("reader was consumed: %d bytes remaining (want %d)",
					r.Len(), len("payload"))
			}
			if w.Len() != 0 {
				t.Errorf("writer received %d bytes; expected 0", w.Len())
			}
		})
	}
}

// TestEasyStreamIOClosedEncryptor verifies the IO methods panic with
// [easy.ErrClosed] on a closed encryptor.
func TestEasyStreamIOClosedEncryptor(t *testing.T) {
	t.Run("Encrypt", func(t *testing.T) {
		enc := easy.New("siphash24", 512)
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		defer func() {
			r := recover()
			if r != easy.ErrClosed {
				t.Errorf("post-Close EncryptStreamIO: panic recovered as %v, want ErrClosed", r)
			}
		}()
		_ = enc.EncryptStreamIO(bytes.NewReader([]byte("x")), &bytes.Buffer{}, 1024)
	})
	t.Run("Decrypt", func(t *testing.T) {
		enc := easy.New("siphash24", 512)
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		defer func() {
			r := recover()
			if r != easy.ErrClosed {
				t.Errorf("post-Close DecryptStreamIO: panic recovered as %v, want ErrClosed", r)
			}
		}()
		_ = enc.DecryptStreamIO(bytes.NewReader([]byte("x")), &bytes.Buffer{})
	})
}
