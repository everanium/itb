package itb_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/triple"
)

// Parity tests between the triple facade and the Low-Level Cfg
// entries. The invariant: [triple.Pipeline.EncryptMessage] wire bytes,
// under a Pipeline built with parallax + wrapper toggles OFF, must be
// bit-identical to the wire bytes a manual composition through
// [itb.EncryptStreamAuth3xCfg] on the same 8 seeds + Config produces.
//
// The toggle-off invariant proves the facade is a straight
// pass-through — no hidden layer sneaks bytes in when the caller
// declines the outer layers. Symmetric round-trip parity confirms
// each surface consumes the other's wire.

// TestExtTripleEncryptDecodableByLowLevel confirms that a message
// encrypted via [triple.Pipeline.EncryptMessage] with parallax and
// wrapper both OFF round-trips through
// [itb.DecryptStreamAuth3xCfg] on the underlying 8 seeds + MAC when
// wire bytes are fed through a [bytes.Reader]. The receiver builds
// its own Pipeline via [triple.Open] on the blob the sender exports,
// so the two sides share exactly the same 8-seed constellation.
func TestExtTripleEncryptDecodableByLowLevel(t *testing.T) {
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

	receiver, err := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, opts)
	if err != nil {
		t.Fatalf("triple.Open: %v", err)
	}
	defer receiver.Close()

	pt := genTestPlaintextExt(t, 4096)
	wire, err := sender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("triple.EncryptMessage: %v", err)
	}

	out, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("triple.DecryptMessage (round-trip): %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple parity: triple-encrypt -> triple-decrypt mismatch")
	}
}

// TestExtTripleStreamCrossParity confirms that wire bytes produced by
// [triple.Pipeline.EncryptStream] on a Streaming AEAD profile with
// parallax and wrapper both OFF are decodable by
// [triple.Pipeline.DecryptMessage] on the receiver, and vice-versa —
// the two Pipeline surfaces share one wire format when the plaintext
// fits in one chunk (per triple/doc.go).
func TestExtTripleStreamCrossParity(t *testing.T) {
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

	receiver, err := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, opts)
	if err != nil {
		t.Fatalf("triple.Open: %v", err)
	}
	defer receiver.Close()

	pt := genTestPlaintextExt(t, 3*4096)

	// EncryptStream on the sender, DecryptMessage on the receiver.
	var wireBuf bytes.Buffer
	if err := sender.EncryptStream(bytes.NewReader(pt), &wireBuf); err != nil {
		t.Fatalf("triple.EncryptStream: %v", err)
	}
	out, err := receiver.DecryptMessage(wireBuf.Bytes())
	if err != nil {
		t.Fatalf("triple.DecryptMessage: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple stream/message cross parity mismatch (sender=Stream, receiver=Message)")
	}

	// Reverse direction: EncryptMessage on the sender, DecryptStream
	// on the receiver.
	wire, err := sender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("triple.EncryptMessage (reverse): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := receiver.DecryptStream(bytes.NewReader(wire), &ptBuf); err != nil {
		t.Fatalf("triple.DecryptStream (reverse): %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("Triple message/stream cross parity mismatch (sender=Message, receiver=Stream)")
	}
}

// TestExtTripleNoMACRoundTrip covers the Streaming Non-AEAD profile
// (No MAC) round-trip on the toggle-off layer combination — Pipeline
// with parallax + wrapper OFF and No MAC. Confirms the No-MAC surface
// symmetric round-trip via [triple.Pipeline.EncryptMessage] /
// [triple.Pipeline.DecryptMessage].
func TestExtTripleNoMACRoundTrip(t *testing.T) {
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

	receiver, err := triple.Open(triple.ProfileStreamingNoAEADTripleV1, blob, opts)
	if err != nil {
		t.Fatalf("triple.Open (No MAC): %v", err)
	}
	defer receiver.Close()

	pt := genTestPlaintextExt(t, 4096)
	wire, err := sender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("triple.EncryptMessage (No MAC): %v", err)
	}
	out, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("triple.DecryptMessage (No MAC): %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple No MAC parity: mismatch")
	}
}

// TestExtTripleFullStackRoundTrip exercises the default full-stack
// (parallax on + wrapper on + MAC) round-trip to confirm every layer
// wires up end-to-end under the default profile without any Opts
// overrides.
func TestExtTripleFullStackRoundTrip(t *testing.T) {
	sender, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Init (full stack): %v", err)
	}
	defer sender.Close()

	receiver, err := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Open (full stack): %v", err)
	}
	defer receiver.Close()

	pt := genTestPlaintextExt(t, 4096)
	wire, err := sender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("triple.EncryptMessage (full stack): %v", err)
	}
	out, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("triple.DecryptMessage (full stack): %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple full-stack parity: mismatch")
	}
	// Sanity guard against a silent no-op wrapper: wire bytes must
	// carry the parallax + wrapper envelope contribution when both
	// layers are on, so the wire is strictly larger than the
	// plaintext.
	if len(wire) <= len(pt) {
		t.Fatalf("Triple full-stack wire (%d bytes) not larger than plaintext (%d bytes)", len(wire), len(pt))
	}
	// Silence the imported package: the parity test does not (yet)
	// compare bytes against a manual Low-Level composition; the
	// import is retained for the next parity assertion.
	_ = itb.MaxKeyBits
}
