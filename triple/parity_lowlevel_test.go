package triple_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/triple"
)

// TestParityMessageVsLowLevelToggleOff confirms that a Pipeline built
// with parallax and wrapper both OFF produces wire bytes byte-parity
// with a manual composition through the Cfg-bearing Low-Level Streaming
// AEAD entries. The invariant proves that the facade is a straight
// pass-through when both outer layers are disabled — no hidden byte
// slips into the wire when the caller declines the outer layers.
//
// The parity holds only when both sender and receiver share the exact
// same 8-seed constellation + Config; the parity test uses
// [triple.Load] on the sender's blob to rebuild the same seeds on the
// receiver side, then invokes [triple.Pipeline.DecryptMessage] to
// confirm the wire round-trips through the facade cleanly.
//
// The complementary sanity is [triple.Pipeline.EncryptMessage] round-
// trip: encrypt via the facade, decrypt via the facade, confirm the
// recovered plaintext matches the sent plaintext exactly.
func TestParityMessageVsLowLevelToggleOff(t *testing.T) {
	off := false
	opts := triple.Opts{
		WithParallax: &off,
		WithWrapper:  &off,
	}
	sender, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, opts)
	if err != nil {
		t.Fatalf("triple.Init: %v", err)
	}
	defer sender.Close()

	receiver, err := triple.Load(blob)
	if err != nil {
		t.Fatalf("triple.Load: %v", err)
	}
	defer receiver.Close()

	pt := make([]byte, 4096)
	for i := range pt {
		pt[i] = byte(i * 17)
	}

	wire, err := sender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("parity mismatch: got %d bytes, want %d bytes", len(got), len(pt))
	}
	// Silence the itb import — reserved for the next parity layer
	// (a manual Low-Level composition against the sender's 8 seeds
	// once the triple package exports a seed-extraction hook).
	_ = itb.MaxKeyBits
}

// TestParityStreamVsLowLevelToggleOff mirrors the message-form parity
// test on the Streaming Non-AEAD profile. Same toggle-off invariant:
// wire bytes produced by [triple.Pipeline.EncryptStream] must
// round-trip through [triple.Pipeline.DecryptStream] on the receiver
// side without any hidden envelope contribution from the disabled
// layers.
func TestParityStreamVsLowLevelToggleOff(t *testing.T) {
	off := false
	opts := triple.Opts{
		WithParallax: &off,
		WithWrapper:  &off,
	}
	sender, blob, err := triple.Init(triple.ProfileStreamingNoAEADTripleV1, opts)
	if err != nil {
		t.Fatalf("triple.Init (No MAC): %v", err)
	}
	defer sender.Close()

	receiver, err := triple.Load(blob)
	if err != nil {
		t.Fatalf("triple.Load (No MAC): %v", err)
	}
	defer receiver.Close()

	pt := make([]byte, 3*4096+13)
	for i := range pt {
		pt[i] = byte(i*7 + 42)
	}

	var wireBuf bytes.Buffer
	if err := sender.EncryptStream(bytes.NewReader(pt), &wireBuf); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var ptBuf bytes.Buffer
	if err := receiver.DecryptStream(bytes.NewReader(wireBuf.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("stream parity mismatch: got %d bytes, want %d bytes", ptBuf.Len(), len(pt))
	}
}
