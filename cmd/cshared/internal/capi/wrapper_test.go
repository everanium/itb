package capi

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb/wrapper"
)

// wrapper_test.go — round-trip parity tests for the FFI-side
// format-deniability surface. Each test runs every shipped outer
// cipher (aes / chacha / siphash) through one of the four single-
// shot variants plus the streaming Init / Update / Free path, and
// confirms the recovered plaintext matches the input.
//
// Cross-checks against the Go-native wrapper package: where the
// FFI helper takes a caller-allocated buffer, the matching
// Go-native call (wrapper.Wrap / wrapper.Unwrap) is invoked with
// the same key + plaintext + nonce so the comparison is wire-bit
// identical (the FFI Wrap helper draws its own fresh nonce, so
// the wire-level cross-check uses the FFI's emitted bytes as the
// reference and round-trips through the Go-native UnwrapInPlace).

func mustGenerateKey(t *testing.T, name string) []byte {
	t.Helper()
	key, err := wrapper.GenerateKey(name)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", name, err)
	}
	return key
}

// TestWrapperSizes covers WrapperKeySize / WrapperNonceSize across
// the three shipped outer ciphers and an unknown-name negative.
func TestWrapperSizes(t *testing.T) {
	want := map[string]struct {
		key, nonce int
	}{
		"aes":     {16, 16},
		"chacha":  {32, 12},
		"siphash": {16, 16},
	}
	for name, exp := range want {
		k, st := WrapperKeySize(name)
		if st != StatusOK || k != exp.key {
			t.Errorf("WrapperKeySize(%s) = %d, %v; want %d, OK", name, k, st, exp.key)
		}
		n, st := WrapperNonceSize(name)
		if st != StatusOK || n != exp.nonce {
			t.Errorf("WrapperNonceSize(%s) = %d, %v; want %d, OK", name, n, st, exp.nonce)
		}
	}
	if _, st := WrapperKeySize("nope"); st != StatusBadInput {
		t.Errorf("WrapperKeySize(nope) status = %v, want StatusBadInput", st)
	}
	if _, st := WrapperNonceSize("nope"); st != StatusBadInput {
		t.Errorf("WrapperNonceSize(nope) status = %v, want StatusBadInput", st)
	}
}

// TestWrapUnwrapRoundTrip exercises the allocating Wrap / Unwrap
// pair. The FFI Wrap call produces nonce || ciphertext into a
// caller buffer; the FFI Unwrap call recovers the plaintext.
// Compared against a Go-native wrapper.Unwrap on the same FFI-
// emitted wire to confirm the wire format is consistent across
// sides.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	for _, name := range wrapper.CipherNames {
		t.Run(name, func(t *testing.T) {
			key := mustGenerateKey(t, name)
			plain := make([]byte, 4096)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			nonceSz, _ := wrapper.NonceSize(name)
			wire := make([]byte, nonceSz+len(plain))
			n, st := Wrap(name, key, plain, wire)
			if st != StatusOK || n != len(wire) {
				t.Fatalf("Wrap(%s): n=%d st=%v want %d OK", name, n, st, len(wire))
			}

			// FFI Unwrap parity.
			recovered := make([]byte, len(plain))
			n2, st := Unwrap(name, key, wire, recovered)
			if st != StatusOK || n2 != len(plain) {
				t.Fatalf("Unwrap(%s): n=%d st=%v", name, n2, st)
			}
			if !bytes.Equal(plain, recovered) {
				t.Fatalf("Unwrap(%s): mismatch", name)
			}

			// Go-native wrapper.Unwrap on the FFI-emitted wire.
			gp, err := wrapper.Unwrap(name, key, wire)
			if err != nil {
				t.Fatalf("wrapper.Unwrap(%s): %v", name, err)
			}
			if !bytes.Equal(plain, gp) {
				t.Fatalf("wrapper.Unwrap(%s): mismatch", name)
			}
		})
	}
}

// TestWrapInPlaceRoundTrip exercises the in-place encrypt + decrypt
// pair and verifies the FFI helpers mutate the caller buffer in
// place (the recovered plaintext lives in the same backing array).
func TestWrapInPlaceRoundTrip(t *testing.T) {
	for _, name := range wrapper.CipherNames {
		t.Run(name, func(t *testing.T) {
			key := mustGenerateKey(t, name)
			plain := make([]byte, 4096)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			plainCopy := append([]byte(nil), plain...)

			nonceSz, _ := wrapper.NonceSize(name)
			outNonce := make([]byte, nonceSz)
			n, st := WrapInPlace(name, key, plain, outNonce)
			if st != StatusOK || n != nonceSz {
				t.Fatalf("WrapInPlace(%s): n=%d st=%v", name, n, st)
			}
			// plain must now hold the keystream-XORed body.
			if bytes.Equal(plain, plainCopy) && len(plain) > 0 {
				t.Fatalf("WrapInPlace(%s): blob untouched", name)
			}

			// Build the wire buffer (nonce || encrypted body) for
			// UnwrapInPlace — the canonical receive shape.
			wire := make([]byte, nonceSz+len(plain))
			copy(wire[:nonceSz], outNonce)
			copy(wire[nonceSz:], plain)

			n2, st := UnwrapInPlace(name, key, wire)
			if st != StatusOK || n2 != len(plainCopy) {
				t.Fatalf("UnwrapInPlace(%s): n=%d st=%v", name, n2, st)
			}
			if !bytes.Equal(wire[nonceSz:], plainCopy) {
				t.Fatalf("UnwrapInPlace(%s): mismatch", name)
			}
		})
	}
}

// TestWrapStream exercises the handle-based streaming surface. The
// encrypt-side handle emits its nonce on Init, then drives several
// Update calls of varying sizes through the keystream; the
// decrypt-side handle consumes that nonce on Init, then mirrors
// the same Update slicing to recover the plaintext.
func TestWrapStream(t *testing.T) {
	for _, name := range wrapper.CipherNames {
		t.Run(name, func(t *testing.T) {
			key := mustGenerateKey(t, name)
			plain := make([]byte, 50*1024)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}

			nonceSz, _ := wrapper.NonceSize(name)
			outNonce := make([]byte, nonceSz)
			wid, n, st := NewWrapStreamWriter(name, key, outNonce)
			if st != StatusOK || n != nonceSz {
				t.Fatalf("NewWrapStreamWriter(%s): n=%d st=%v", name, n, st)
			}
			defer FreeWrapStream(wid)

			// Encrypt in three uneven chunks to exercise the
			// keystream counter advancement across boundaries.
			cipher := make([]byte, len(plain))
			split1 := 1234
			split2 := 1234 + 17000
			for _, span := range [][2]int{{0, split1}, {split1, split2}, {split2, len(plain)}} {
				lo, hi := span[0], span[1]
				m, st := WrapStreamUpdate(wid, plain[lo:hi], cipher[lo:hi])
				if st != StatusOK || m != hi-lo {
					t.Fatalf("WrapStreamUpdate(%s) [%d:%d]: m=%d st=%v", name, lo, hi, m, st)
				}
			}

			// Decrypt-side handle.
			rid, st := NewUnwrapStreamReader(name, key, outNonce)
			if st != StatusOK {
				t.Fatalf("NewUnwrapStreamReader(%s): st=%v", name, st)
			}
			defer FreeWrapStream(rid)

			recovered := make([]byte, len(plain))
			// Different splitting on decrypt side — the keystream
			// counter must advance the same total bytes regardless
			// of chunk shape.
			for _, span := range [][2]int{{0, 8000}, {8000, 30000}, {30000, len(plain)}} {
				lo, hi := span[0], span[1]
				m, st := WrapStreamUpdate(rid, cipher[lo:hi], recovered[lo:hi])
				if st != StatusOK || m != hi-lo {
					t.Fatalf("WrapStreamUpdate.decrypt(%s) [%d:%d]: m=%d st=%v", name, lo, hi, m, st)
				}
			}
			if !bytes.Equal(plain, recovered) {
				t.Fatalf("stream round-trip mismatch (%s)", name)
			}
		})
	}
}

// TestWrapStreamInPlace exercises the dst==src case to confirm the
// FFI Update path supports in-place XOR (no internal scratch
// buffer that would defeat the zero-allocation contract).
func TestWrapStreamInPlace(t *testing.T) {
	for _, name := range wrapper.CipherNames {
		t.Run(name, func(t *testing.T) {
			key := mustGenerateKey(t, name)
			plain := make([]byte, 16*1024)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			plainCopy := append([]byte(nil), plain...)

			nonceSz, _ := wrapper.NonceSize(name)
			outNonce := make([]byte, nonceSz)
			wid, _, st := NewWrapStreamWriter(name, key, outNonce)
			if st != StatusOK {
				t.Fatalf("NewWrapStreamWriter(%s): st=%v", name, st)
			}
			defer FreeWrapStream(wid)

			n, st := WrapStreamUpdate(wid, plain, plain)
			if st != StatusOK || n != len(plain) {
				t.Fatalf("WrapStreamUpdate inplace(%s): n=%d st=%v", name, n, st)
			}
			if bytes.Equal(plain, plainCopy) {
				t.Fatalf("WrapStreamUpdate inplace(%s): blob untouched", name)
			}

			rid, st := NewUnwrapStreamReader(name, key, outNonce)
			if st != StatusOK {
				t.Fatalf("NewUnwrapStreamReader(%s): st=%v", name, st)
			}
			defer FreeWrapStream(rid)

			n, st = WrapStreamUpdate(rid, plain, plain)
			if st != StatusOK || n != len(plain) {
				t.Fatalf("WrapStreamUpdate.dec inplace(%s): n=%d st=%v", name, n, st)
			}
			if !bytes.Equal(plain, plainCopy) {
				t.Fatalf("stream inplace round-trip mismatch (%s)", name)
			}
		})
	}
}

// TestWrapErrors exercises the validation paths.
func TestWrapErrors(t *testing.T) {
	key := mustGenerateKey(t, "aes")
	plain := []byte("hello, deniable world")
	wire := make([]byte, 16+len(plain))

	// Unknown cipher name.
	if _, st := Wrap("nope", key, plain, wire); st != StatusBadInput {
		t.Errorf("Wrap(unknown): st=%v want StatusBadInput", st)
	}
	// Bad key length.
	if _, st := Wrap("aes", key[:8], plain, wire); st != StatusBadInput {
		t.Errorf("Wrap(short-key): st=%v want StatusBadInput", st)
	}
	// Buffer too small.
	if n, st := Wrap("aes", key, plain, wire[:10]); st != StatusBufferTooSmall || n != len(wire) {
		t.Errorf("Wrap(short-out): n=%d st=%v want %d StatusBufferTooSmall", n, st, len(wire))
	}
	// Wire shorter than nonce on Unwrap.
	if _, st := Unwrap("aes", key, []byte{1, 2, 3}, wire); st != StatusBadInput {
		t.Errorf("Unwrap(short-wire): st=%v want StatusBadInput", st)
	}
	// Bad handle on Update.
	dst := make([]byte, 16)
	if _, st := WrapStreamUpdate(0, plain, dst); st != StatusBadHandle {
		t.Errorf("WrapStreamUpdate(0): st=%v want StatusBadHandle", st)
	}
	// Bad handle on Free.
	if st := FreeWrapStream(0); st != StatusBadHandle {
		t.Errorf("FreeWrapStream(0): st=%v want StatusBadHandle", st)
	}
}
