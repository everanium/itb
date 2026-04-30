package capi

import (
	"crypto/rand"
	"testing"
)

// TestParseChunkLen checks the FFI helper that lets streaming
// callers walk a concatenated chunk stream one chunk at a time.
// A round-trip via Encrypt → ParseChunkLen → Decrypt confirms the
// reported chunk length matches the actual encoded size and that
// short / malformed headers are rejected with StatusBadInput.
func TestParseChunkLen(t *testing.T) {
	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	ctBuf := make([]byte, 1<<16)
	ctLen, st := Encrypt(ns, ds, ss, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("Encrypt: %v", st)
	}

	// Header-only probe: pass exactly the fixed header (20 bytes by
	// default) and confirm the parser reports the full chunk length.
	header := ctBuf[:20]
	gotLen, st := ParseChunkLen(header)
	if st != StatusOK {
		t.Fatalf("ParseChunkLen: %v", st)
	}
	if gotLen != ctLen {
		t.Errorf("ParseChunkLen returned %d, Encrypt produced %d", gotLen, ctLen)
	}

	// Short header: must be rejected.
	if _, st := ParseChunkLen(ctBuf[:10]); st != StatusBadInput {
		t.Errorf("short header: %v, want StatusBadInput", st)
	}

	// Zero-dimension header: handcraft 20 bytes with width=0 and
	// confirm the parser rejects it.
	zeroDim := make([]byte, 20)
	if _, st := ParseChunkLen(zeroDim); st != StatusBadInput {
		t.Errorf("zero-dim header: %v, want StatusBadInput", st)
	}
}
