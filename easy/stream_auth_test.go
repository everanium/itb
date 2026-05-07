// Package easy_test (external) — round-trip and tamper-detection
// matrix for the Streaming AEAD surface on [easy.Encryptor]:
// EncryptStreamAuthenticated / DecryptStreamAuthenticated (per-chunk
// Level 1) and EncryptStreamAuth / DecryptStreamAuth (full-stream
// Level 2). Coverage mirrors the Go-core stream_auth_test.go suite at
// the Easy Mode wrapper level.
package easy_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
)

// streamAuthSpec lists the (primitive, key_bits) pairs the
// Streaming AEAD round-trip tests exercise. One representative PRF
// per native hash width keeps the matrix compact while still
// covering 128 / 256 / 512 width dispatch.
var streamAuthSpec = []struct {
	name    string
	keyBits int
	width   int
}{
	{"siphash24", 512, 128},
	{"blake3", 512, 256},
	{"blake2b512", 512, 512},
}

// streamAuthModes lists the two Ouroboros shapes used by every
// Streaming AEAD round-trip test.
var streamAuthModes = []struct {
	name string
	mode int
}{
	{"Single", 1},
	{"Triple", 3},
}

// generateDataStreamAuth fills an n-byte slice with crypto/rand bytes
// for Streaming AEAD test plaintext.
func generateDataStreamAuth(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// newStreamAuthEncryptor builds an encryptor for the given primitive
// / key_bits / mode combination. mode = 1 selects [easy.New] (Single
// Ouroboros); mode = 3 selects [easy.New3] (Triple Ouroboros).
func newStreamAuthEncryptor(primitive string, keyBits, mode int) *easy.Encryptor {
	if mode == 3 {
		return easy.New3(primitive, keyBits)
	}
	return easy.New(primitive, keyBits)
}

// streamAuthZeroID returns a deterministic 32-byte stream anchor for
// per-chunk Level 1 tests that drive the encrypt / decrypt path
// directly with a caller-supplied streamID.
func streamAuthZeroID() [32]byte {
	var sid [32]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	return sid
}

// --- Per-chunk Level 1 round-trip ---

// TestEasyStreamAuthPerChunkRoundtripMatrix exercises the
// per-chunk EncryptStreamAuthenticated → DecryptStreamAuthenticated
// path across (primitive width × Single/Triple) for both
// finalFlag = false and finalFlag = true.
func TestEasyStreamAuthPerChunkRoundtripMatrix(t *testing.T) {
	plaintext := generateDataStreamAuth(1024)
	streamID := streamAuthZeroID()
	const cumOffset = uint64(12345)

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			for _, finalFlag := range []bool{false, true} {
				flagName := "NonFinal"
				if finalFlag {
					flagName = "Final"
				}
				name := fmt.Sprintf("%s_w%d_%s_%s", ps.name, ps.width, m.name, flagName)
				t.Run(name, func(t *testing.T) {
					enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
					defer enc.Close()
					chunk, err := enc.EncryptStreamAuthenticated(plaintext, streamID, cumOffset, finalFlag)
					if err != nil {
						t.Fatalf("EncryptStreamAuthenticated: %v", err)
					}
					pt, recoveredFinal, err := enc.DecryptStreamAuthenticated(chunk, streamID, cumOffset)
					if err != nil {
						t.Fatalf("DecryptStreamAuthenticated: %v", err)
					}
					if !bytes.Equal(pt, plaintext) {
						t.Errorf("plaintext roundtrip mismatch: got %d bytes, want %d", len(pt), len(plaintext))
					}
					if recoveredFinal != finalFlag {
						t.Errorf("finalFlag mismatch: encoded %v, recovered %v", finalFlag, recoveredFinal)
					}
				})
			}
		}
	}
}

// --- Per-chunk Level 1 tampered detection ---

// TestEasyStreamAuthPerChunkTampered verifies that flipping container
// bytes in a per-chunk ciphertext causes decrypt to return a non-nil
// error. Header bytes are preserved so the chunk parses; the
// downstream container body is fully bit-flipped to guarantee
// corruption regardless of seed-driven noise placement.
func TestEasyStreamAuthPerChunkTampered(t *testing.T) {
	plaintext := generateDataStreamAuth(1024)
	streamID := streamAuthZeroID()
	const cumOffset = uint64(7777)

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			name := fmt.Sprintf("%s_w%d_%s", ps.name, ps.width, m.name)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
				defer enc.Close()
				chunk, err := enc.EncryptStreamAuthenticated(plaintext, streamID, cumOffset, true)
				if err != nil {
					t.Fatalf("EncryptStreamAuthenticated: %v", err)
				}
				if len(chunk) < 64 {
					t.Fatalf("chunk too small to tamper: %d bytes", len(chunk))
				}
				tampered := make([]byte, len(chunk))
				copy(tampered, chunk)
				// Flip every bit of every byte beyond a generous header
				// margin; one of those flips will land on the MAC tag
				// area regardless of pixel layout.
				for i := 32; i < len(tampered); i++ {
					tampered[i] ^= 0xFF
				}
				if _, _, err := enc.DecryptStreamAuthenticated(tampered, streamID, cumOffset); err == nil {
					t.Fatal("expected error on tampered chunk, got nil")
				}
			})
		}
	}
}

// --- Per-chunk Level 1 cross-stream replay detection ---

// TestEasyStreamAuthPerChunkCrossStreamReplay confirms that a chunk
// encrypted under streamID_A fails to verify under streamID_B even
// when every other parameter (seeds, MAC, cumulative offset) is held
// constant.
func TestEasyStreamAuthPerChunkCrossStreamReplay(t *testing.T) {
	plaintext := generateDataStreamAuth(1024)
	var streamA, streamB [32]byte
	for i := range streamA {
		streamA[i] = byte(0xA0 + i)
		streamB[i] = byte(0xB0 + i)
	}

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			name := fmt.Sprintf("%s_w%d_%s", ps.name, ps.width, m.name)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
				defer enc.Close()
				chunk, err := enc.EncryptStreamAuthenticated(plaintext, streamA, 0, true)
				if err != nil {
					t.Fatalf("EncryptStreamAuthenticated: %v", err)
				}
				if _, _, err := enc.DecryptStreamAuthenticated(chunk, streamB, 0); err == nil {
					t.Fatal("expected error on streamID mismatch, got nil")
				}
			})
		}
	}
}

// --- Per-chunk Level 1 cumulative-offset reorder detection ---

// TestEasyStreamAuthPerChunkOffsetReorder verifies the cumulative
// pixel offset is bound by the per-chunk MAC. A chunk encrypted at
// offset 0 must fail to verify at offset 1024 and vice-versa.
func TestEasyStreamAuthPerChunkOffsetReorder(t *testing.T) {
	plaintext := generateDataStreamAuth(1024)
	streamID := streamAuthZeroID()

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			name := fmt.Sprintf("%s_w%d_%s", ps.name, ps.width, m.name)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
				defer enc.Close()
				chunkA, err := enc.EncryptStreamAuthenticated(plaintext, streamID, 0, false)
				if err != nil {
					t.Fatalf("EncryptStreamAuthenticated A: %v", err)
				}
				chunkB, err := enc.EncryptStreamAuthenticated(plaintext, streamID, 1024, true)
				if err != nil {
					t.Fatalf("EncryptStreamAuthenticated B: %v", err)
				}
				if _, _, err := enc.DecryptStreamAuthenticated(chunkA, streamID, 1024); err == nil {
					t.Fatal("expected error decrypting A at B's offset, got nil")
				}
				if _, _, err := enc.DecryptStreamAuthenticated(chunkB, streamID, 0); err == nil {
					t.Fatal("expected error decrypting B at A's offset, got nil")
				}
			})
		}
	}
}

// --- Per-chunk Level 1 empty plaintext + finalFlag = true ---

// TestEasyStreamAuthPerChunkEmptyFinal confirms a 0-byte plaintext
// with finalFlag = true round-trips as the legitimate empty
// terminating chunk.
func TestEasyStreamAuthPerChunkEmptyFinal(t *testing.T) {
	streamID := streamAuthZeroID()

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			name := fmt.Sprintf("%s_w%d_%s", ps.name, ps.width, m.name)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
				defer enc.Close()
				chunk, err := enc.EncryptStreamAuthenticated(nil, streamID, 0, true)
				if err != nil {
					t.Fatalf("EncryptStreamAuthenticated: %v", err)
				}
				pt, finalFlag, err := enc.DecryptStreamAuthenticated(chunk, streamID, 0)
				if err != nil {
					t.Fatalf("DecryptStreamAuthenticated: %v", err)
				}
				if len(pt) != 0 {
					t.Errorf("expected empty plaintext, got %d bytes", len(pt))
				}
				if !finalFlag {
					t.Error("expected finalFlag = true on empty terminator")
				}
			})
		}
	}
}

// --- Per-chunk Level 1 empty plaintext + finalFlag = false rejected ---

// TestEasyStreamAuthPerChunkEmptyNonFinalRejected confirms that
// 0-byte plaintext with finalFlag = false is rejected by the
// underlying encrypt path. An empty non-terminating chunk has no
// legitimate use and must surface as an error.
func TestEasyStreamAuthPerChunkEmptyNonFinalRejected(t *testing.T) {
	streamID := streamAuthZeroID()

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			name := fmt.Sprintf("%s_w%d_%s", ps.name, ps.width, m.name)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
				defer enc.Close()
				if _, err := enc.EncryptStreamAuthenticated(nil, streamID, 0, false); err == nil {
					t.Fatal("expected error on empty plaintext with finalFlag = false, got nil")
				}
			})
		}
	}
}

// --- Full-stream Level 2 round-trip ---

// TestEasyStreamAuthFullStreamRoundtripMatrix exercises the full
// EncryptStreamAuth → DecryptStreamAuth path across (primitive width
// × Single/Triple). Plaintext exceeds a single chunk so the cumulative
// pixel offset advance is exercised end-to-end.
func TestEasyStreamAuthFullStreamRoundtripMatrix(t *testing.T) {
	plaintext := generateDataStreamAuth(8192)

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			name := fmt.Sprintf("%s_w%d_%s", ps.name, ps.width, m.name)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
				defer enc.Close()
				enc.SetChunkSize(1024)

				var wire bytes.Buffer
				err := enc.EncryptStreamAuth(plaintext, func(chunk []byte) error {
					_, e := wire.Write(chunk)
					return e
				})
				if err != nil {
					t.Fatalf("EncryptStreamAuth: %v", err)
				}
				var recovered bytes.Buffer
				err = enc.DecryptStreamAuth(wire.Bytes(), func(chunk []byte) error {
					_, e := recovered.Write(chunk)
					return e
				})
				if err != nil {
					t.Fatalf("DecryptStreamAuth: %v", err)
				}
				if !bytes.Equal(recovered.Bytes(), plaintext) {
					t.Errorf("stream roundtrip mismatch: got %d bytes, want %d",
						recovered.Len(), len(plaintext))
				}
			})
		}
	}
}

// --- Full-stream Level 2 truncate-tail detection ---

// TestEasyStreamAuthFullStreamTruncateTail verifies that dropping
// the last chunk of a full-stream transcript produces
// [itb.ErrStreamTruncated] on decrypt. The transcript wire bytes are
// walked with [itb.ParseChunkLen] to find the last chunk's start
// offset; truncation slices the tail off there.
func TestEasyStreamAuthFullStreamTruncateTail(t *testing.T) {
	plaintext := generateDataStreamAuth(8192)

	enc := easy.New("siphash24", 512)
	defer enc.Close()
	enc.SetChunkSize(512)

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuth(plaintext, func(chunk []byte) error {
		_, e := wire.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}

	full := wire.Bytes()
	// First 32 bytes are the stream prefix; the chunks start at
	// offset 32. Walk to find the last chunk's start offset.
	const streamPrefixLen = 32
	off := streamPrefixLen
	var lastStart int
	for off < len(full) {
		clen, err := itb.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen at off %d: %v", off, err)
		}
		lastStart = off
		off += clen
	}
	if lastStart == streamPrefixLen {
		t.Fatal("only one chunk emitted; truncate-tail test needs >=2 chunks")
	}
	truncated := full[:lastStart]

	var sink bytes.Buffer
	err := enc.DecryptStreamAuth(truncated, func(chunk []byte) error {
		_, e := sink.Write(chunk)
		return e
	})
	if err == nil {
		t.Fatal("expected error on truncated transcript, got nil")
	}
	// The exact error class is propagated through from the Go-core
	// helper. Direct equality check via errors.Is is the canonical
	// pattern; for layered wrapping, message check is used as fallback.
	if err.Error() != itb.ErrStreamTruncated.Error() &&
		!bytesContainsString(err.Error(), itb.ErrStreamTruncated.Error()) {
		t.Errorf("expected ErrStreamTruncated wrapping, got %v", err)
	}
}

// bytesContainsString reports whether s contains substr; tiny helper
// used by the truncate-tail test to accept either bare or wrapped
// error messages.
func bytesContainsString(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// --- Full-stream Level 2 stream-prefix tamper detection ---

// TestEasyStreamAuthFullStreamPrefixTamper verifies that flipping a
// single byte of the on-wire 32-byte stream prefix causes the first
// chunk's MAC verification to fail.
func TestEasyStreamAuthFullStreamPrefixTamper(t *testing.T) {
	plaintext := generateDataStreamAuth(2048)

	enc := easy.New("siphash24", 512)
	defer enc.Close()
	enc.SetChunkSize(512)

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuth(plaintext, func(chunk []byte) error {
		_, e := wire.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	tampered := make([]byte, wire.Len())
	copy(tampered, wire.Bytes())
	tampered[0] ^= 0x01

	var sink bytes.Buffer
	err := enc.DecryptStreamAuth(tampered, func(chunk []byte) error {
		_, e := sink.Write(chunk)
		return e
	})
	if err == nil {
		t.Fatal("expected error on stream-prefix tamper, got nil")
	}
}

// --- Final-flag preservation through Triple bit-soup ---

// TestEasyStreamAuthFlagPreservedTripleBitSoup confirms the
// per-chunk finalFlag round-trips intact at chunk_size = 1 plaintext
// byte under Triple Ouroboros with bit-soup mode engaged. Bit-soup
// is the most aggressive bit-level permutation regime; the recovered
// flag must match the encoder-set value across both finalFlag = false
// and finalFlag = true.
func TestEasyStreamAuthFlagPreservedTripleBitSoup(t *testing.T) {
	plaintext := []byte{0x42}
	streamID := streamAuthZeroID()

	for _, ps := range streamAuthSpec {
		for _, finalFlag := range []bool{false, true} {
			flagName := "NonFinal"
			if finalFlag {
				flagName = "Final"
			}
			name := fmt.Sprintf("%s_w%d_TripleBitSoup_%s", ps.name, ps.width, flagName)
			t.Run(name, func(t *testing.T) {
				enc := newStreamAuthEncryptor(ps.name, ps.keyBits, 3)
				defer enc.Close()
				enc.SetBitSoup(1)

				chunk, err := enc.EncryptStreamAuthenticated(plaintext, streamID, 0, finalFlag)
				if err != nil {
					t.Fatalf("EncryptStreamAuthenticated: %v", err)
				}
				pt, recoveredFinal, err := enc.DecryptStreamAuthenticated(chunk, streamID, 0)
				if err != nil {
					t.Fatalf("DecryptStreamAuthenticated: %v", err)
				}
				if !bytes.Equal(pt, plaintext) {
					t.Errorf("plaintext mismatch under bit-soup: got %x, want %x", pt, plaintext)
				}
				if recoveredFinal != finalFlag {
					t.Errorf("flag mismatch under bit-soup: encoded %v, recovered %v",
						finalFlag, recoveredFinal)
				}
			})
		}
	}
}

// --- Full-stream Level 2 empty plaintext round-trip ---

// TestEasyStreamAuthFullStreamEmpty confirms a 0-byte plaintext at
// the full-stream level produces a transcript of [stream prefix +
// single terminator chunk] that decrypts back to 0 bytes with a
// finalFlag = true terminator.
func TestEasyStreamAuthFullStreamEmpty(t *testing.T) {
	enc := easy.New("siphash24", 512)
	defer enc.Close()

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuth(nil, func(chunk []byte) error {
		_, e := wire.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	var recovered bytes.Buffer
	if err := enc.DecryptStreamAuth(wire.Bytes(), func(chunk []byte) error {
		_, e := recovered.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("DecryptStreamAuth: %v", err)
	}
	if recovered.Len() != 0 {
		t.Errorf("expected empty recovered plaintext, got %d bytes", recovered.Len())
	}
}

// --- Closed-encryptor preflight ---

// TestEasyStreamAuthEncryptStreamAuthenticatedClosed verifies
// EncryptStreamAuthenticated panics with [easy.ErrClosed] after
// the encryptor's [easy.Encryptor.Close] has run.
func TestEasyStreamAuthEncryptStreamAuthenticatedClosed(t *testing.T) {
	enc := easy.New()
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	defer func() {
		r := recover()
		if r != easy.ErrClosed {
			t.Errorf("post-Close EncryptStreamAuthenticated: panic recovered as %v, want ErrClosed", r)
		}
	}()
	var sid [32]byte
	_, _ = enc.EncryptStreamAuthenticated([]byte("x"), sid, 0, true)
}

// TestEasyStreamAuthDecryptStreamAuthenticatedClosed verifies
// DecryptStreamAuthenticated panics with [easy.ErrClosed] after the
// encryptor's [easy.Encryptor.Close] has run.
func TestEasyStreamAuthDecryptStreamAuthenticatedClosed(t *testing.T) {
	enc := easy.New()
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	defer func() {
		r := recover()
		if r != easy.ErrClosed {
			t.Errorf("post-Close DecryptStreamAuthenticated: panic recovered as %v, want ErrClosed", r)
		}
	}()
	var sid [32]byte
	_, _, _ = enc.DecryptStreamAuthenticated([]byte("x"), sid, 0)
}

// TestEasyStreamAuthEncryptStreamAuthClosed verifies EncryptStreamAuth
// panics with [easy.ErrClosed] after the encryptor's
// [easy.Encryptor.Close] has run.
func TestEasyStreamAuthEncryptStreamAuthClosed(t *testing.T) {
	enc := easy.New()
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	defer func() {
		r := recover()
		if r != easy.ErrClosed {
			t.Errorf("post-Close EncryptStreamAuth: panic recovered as %v, want ErrClosed", r)
		}
	}()
	_ = enc.EncryptStreamAuth([]byte("x"), func(chunk []byte) error { return nil })
}

// TestEasyStreamAuthDecryptStreamAuthClosed verifies DecryptStreamAuth
// panics with [easy.ErrClosed] after the encryptor's
// [easy.Encryptor.Close] has run.
func TestEasyStreamAuthDecryptStreamAuthClosed(t *testing.T) {
	enc := easy.New()
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	defer func() {
		r := recover()
		if r != easy.ErrClosed {
			t.Errorf("post-Close DecryptStreamAuth: panic recovered as %v, want ErrClosed", r)
		}
	}()
	_ = enc.DecryptStreamAuth([]byte("x"), func(chunk []byte) error { return nil })
}

// --- io.Reader / io.Writer Streaming AEAD round-trip ---

// streamAuthIOSizes covers the {0, 1, cs-1, cs, cs+1, 10*cs} payload
// matrix from the IO-method round-trip spec. Run against a small chunk
// size so the matrix executes within the unit-test budget without
// distorting the encrypt-side sizing arithmetic.
func streamAuthIOSizes(chunkSize int) []int {
	return []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 10 * chunkSize}
}

// TestEasyStreamAuthIORoundtripMatrix exercises EncryptStreamAuthIO →
// DecryptStreamAuthIO across the (primitive width × Single/Triple ×
// payload size) matrix. Round-trip via bytes.Reader / bytes.Buffer
// confirms wire-format symmetry and cumulative-pixel-offset bookkeeping
// across multi-chunk transcripts.
func TestEasyStreamAuthIORoundtripMatrix(t *testing.T) {
	const chunkSize = 1024

	for _, ps := range streamAuthSpec {
		for _, m := range streamAuthModes {
			for _, sz := range streamAuthIOSizes(chunkSize) {
				name := fmt.Sprintf("%s_w%d_%s_sz%d", ps.name, ps.width, m.name, sz)
				t.Run(name, func(t *testing.T) {
					enc := newStreamAuthEncryptor(ps.name, ps.keyBits, m.mode)
					defer enc.Close()

					plaintext := generateDataStreamAuth(sz)
					var wire bytes.Buffer
					if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), &wire, chunkSize); err != nil {
						t.Fatalf("EncryptStreamAuthIO: %v", err)
					}
					var recovered bytes.Buffer
					if err := enc.DecryptStreamAuthIO(bytes.NewReader(wire.Bytes()), &recovered); err != nil {
						t.Fatalf("DecryptStreamAuthIO: %v", err)
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

// TestEasyStreamAuthIOCrossAPIParityIOToCallback confirms a transcript
// produced via EncryptStreamAuthIO decrypts cleanly through the
// existing callback-driven DecryptStreamAuth surface. Wire-format
// compatibility across the IO and callback variants is the load-bearing
// invariant — both paths emit the same on-wire bytes.
func TestEasyStreamAuthIOCrossAPIParityIOToCallback(t *testing.T) {
	const chunkSize = 1024
	plaintext := generateDataStreamAuth(8192)

	enc := easy.New("siphash24", 512)
	defer enc.Close()

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), &wire, chunkSize); err != nil {
		t.Fatalf("EncryptStreamAuthIO: %v", err)
	}
	var recovered bytes.Buffer
	if err := enc.DecryptStreamAuth(wire.Bytes(), func(chunk []byte) error {
		_, e := recovered.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("DecryptStreamAuth (callback): %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("IO-encode → callback-decode mismatch: got %d bytes, want %d",
			recovered.Len(), len(plaintext))
	}
}

// TestEasyStreamAuthIOCrossAPIParityCallbackToIO confirms the reverse
// direction — a transcript produced via the callback-driven
// EncryptStreamAuth decrypts cleanly through DecryptStreamAuthIO.
func TestEasyStreamAuthIOCrossAPIParityCallbackToIO(t *testing.T) {
	plaintext := generateDataStreamAuth(8192)

	enc := easy.New("siphash24", 512)
	defer enc.Close()
	enc.SetChunkSize(1024)

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuth(plaintext, func(chunk []byte) error {
		_, e := wire.Write(chunk)
		return e
	}); err != nil {
		t.Fatalf("EncryptStreamAuth (callback): %v", err)
	}
	var recovered bytes.Buffer
	if err := enc.DecryptStreamAuthIO(bytes.NewReader(wire.Bytes()), &recovered); err != nil {
		t.Fatalf("DecryptStreamAuthIO: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("callback-encode → IO-decode mismatch: got %d bytes, want %d",
			recovered.Len(), len(plaintext))
	}
}

// TestEasyStreamAuthIOEncryptChunkSizeNonPositive verifies the
// chunkSize ≤ 0 preflight rejects without consuming the reader.
func TestEasyStreamAuthIOEncryptChunkSizeNonPositive(t *testing.T) {
	enc := easy.New("siphash24", 512)
	defer enc.Close()

	for _, cs := range []int{0, -1, -1024} {
		t.Run(fmt.Sprintf("cs%d", cs), func(t *testing.T) {
			r := bytes.NewReader([]byte("payload"))
			var w bytes.Buffer
			err := enc.EncryptStreamAuthIO(r, &w, cs)
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

// TestEasyStreamAuthIOClosedEncryptor verifies the IO methods panic
// with [easy.ErrClosed] on a closed encryptor.
func TestEasyStreamAuthIOClosedEncryptor(t *testing.T) {
	t.Run("Encrypt", func(t *testing.T) {
		enc := easy.New("siphash24", 512)
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		defer func() {
			r := recover()
			if r != easy.ErrClosed {
				t.Errorf("post-Close EncryptStreamAuthIO: panic recovered as %v, want ErrClosed", r)
			}
		}()
		_ = enc.EncryptStreamAuthIO(bytes.NewReader([]byte("x")), &bytes.Buffer{}, 1024)
	})
	t.Run("Decrypt", func(t *testing.T) {
		enc := easy.New("siphash24", 512)
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		defer func() {
			r := recover()
			if r != easy.ErrClosed {
				t.Errorf("post-Close DecryptStreamAuthIO: panic recovered as %v, want ErrClosed", r)
			}
		}()
		_ = enc.DecryptStreamAuthIO(bytes.NewReader([]byte("x")), &bytes.Buffer{})
	})
}

// TestEasyStreamAuthIOTruncateTail verifies that dropping the last
// chunk of an IO-driven transcript yields [itb.ErrStreamTruncated]
// on decrypt. Walks the wire bytes via [easy.Encryptor.ParseChunkLen]
// to find the last chunk's start offset and slices the tail off
// there.
func TestEasyStreamAuthIOTruncateTail(t *testing.T) {
	plaintext := generateDataStreamAuth(8192)
	const chunkSize = 512

	enc := easy.New("siphash24", 512)
	defer enc.Close()

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), &wire, chunkSize); err != nil {
		t.Fatalf("EncryptStreamAuthIO: %v", err)
	}

	full := wire.Bytes()
	const streamPrefixLen = 32
	off := streamPrefixLen
	var lastStart int
	for off < len(full) {
		clen, err := enc.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen at off %d: %v", off, err)
		}
		lastStart = off
		off += clen
	}
	if lastStart == streamPrefixLen {
		t.Fatal("only one chunk emitted; truncate-tail test needs >=2 chunks")
	}
	truncated := full[:lastStart]

	var sink bytes.Buffer
	err := enc.DecryptStreamAuthIO(bytes.NewReader(truncated), &sink)
	if err == nil {
		t.Fatal("expected error on truncated transcript, got nil")
	}
	if err.Error() != itb.ErrStreamTruncated.Error() &&
		!bytesContainsString(err.Error(), itb.ErrStreamTruncated.Error()) {
		t.Errorf("expected ErrStreamTruncated wrapping, got %v", err)
	}
}

// TestEasyStreamAuthIOAfterFinal verifies that appending an extra
// chunk after the terminating chunk yields [itb.ErrStreamAfterFinal]
// on decrypt. Constructs the trailing chunk by re-encoding a fresh
// terminator over the same encryptor — the test is structural (any
// well-formed chunk after a final-flag chunk must be rejected).
func TestEasyStreamAuthIOAfterFinal(t *testing.T) {
	plaintext := generateDataStreamAuth(2048)
	const chunkSize = 512

	enc := easy.New("siphash24", 512)
	defer enc.Close()

	var wire bytes.Buffer
	if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), &wire, chunkSize); err != nil {
		t.Fatalf("EncryptStreamAuthIO: %v", err)
	}
	// Extract the wire prefix + chunks; append a freshly produced
	// terminator chunk to the assembled stream. The cumulative-offset
	// for the synthetic trailer doesn't matter — the decoder must
	// reject any post-terminator content before per-chunk MAC verify.
	full := wire.Bytes()
	var streamID [32]byte
	copy(streamID[:], full[:32])
	extra, err := enc.EncryptStreamAuthenticated([]byte("x"), streamID, 0, true)
	if err != nil {
		t.Fatalf("EncryptStreamAuthenticated synthetic trailer: %v", err)
	}
	tampered := append([]byte(nil), full...)
	tampered = append(tampered, extra...)

	var sink bytes.Buffer
	err = enc.DecryptStreamAuthIO(bytes.NewReader(tampered), &sink)
	if err == nil {
		t.Fatal("expected error on post-terminator content, got nil")
	}
	if err.Error() != itb.ErrStreamAfterFinal.Error() &&
		!bytesContainsString(err.Error(), itb.ErrStreamAfterFinal.Error()) {
		t.Errorf("expected ErrStreamAfterFinal wrapping, got %v", err)
	}
}
