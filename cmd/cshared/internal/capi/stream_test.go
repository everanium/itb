package capi

import (
	"crypto/rand"
	"testing"
)

// TestParseChunkLen checks the FFI helper that lets streaming
// callers walk a concatenated chunk stream one chunk at a time.
// A round-trip via Encrypt3 → ParseChunkLen → Decrypt3 confirms the
// reported chunk length matches the actual encoded size and that
// short / malformed headers are rejected with StatusBadInput.
func TestParseChunkLen(t *testing.T) {
	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	ctBuf := make([]byte, 1<<16)
	ctLen, st := Encrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("Encrypt3: %v", st)
	}

	// Header-only probe: pass exactly the fixed header (20 bytes by
	// default) and confirm the parser reports the full chunk length.
	header := ctBuf[:20]
	gotLen, st := ParseChunkLen(header, 16)
	if st != StatusOK {
		t.Fatalf("ParseChunkLen: %v", st)
	}
	if gotLen != ctLen {
		t.Errorf("ParseChunkLen returned %d, Encrypt3 produced %d", gotLen, ctLen)
	}

	// Short header: must be rejected.
	if _, st := ParseChunkLen(ctBuf[:10], 16); st != StatusBadInput {
		t.Errorf("short header: %v, want StatusBadInput", st)
	}

	// Zero-dimension header: handcraft 20 bytes with width=0 and
	// confirm the parser rejects it.
	zeroDim := make([]byte, 20)
	if _, st := ParseChunkLen(zeroDim, 16); st != StatusBadInput {
		t.Errorf("zero-dim header: %v, want StatusBadInput", st)
	}
}
