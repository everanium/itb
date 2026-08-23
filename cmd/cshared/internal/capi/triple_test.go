package capi

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/everanium/itb/triple"
)

// triplePlaintext returns an n-byte CSPRNG plaintext for the FFI
// round-trip tests.
func triplePlaintext(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return buf
}

// TestTripleInitOpenRoundTrip covers the lifecycle path Init → Open →
// EncryptMessage → DecryptMessage → Close across every shipped
// cipher-bearing profile with default opts (full stack: parallax on
// + wrapper on).
func TestTripleInitOpenRoundTrip(t *testing.T) {
	profiles := []string{
		triple.ProfileStreamingAEADTripleMACV1,
		triple.ProfileStreamingNoAEADTripleV1,
		triple.ProfileSingleMsgTripleMACV1,
		triple.ProfileSingleMsgTripleNoMACV1,
	}
	for _, prof := range profiles {
		t.Run(prof, func(t *testing.T) {
			blobBuf := make([]byte, 1<<15)
			sID, blobLen, st := TripleInit(prof, "", blobBuf)
			if st != StatusOK {
				t.Fatalf("TripleInit: %v", st)
			}
			defer FreeTriple(sID)

			rID, st := TripleOpen(prof, blobBuf[:blobLen], "")
			if st != StatusOK {
				t.Fatalf("TripleOpen: %v", st)
			}
			defer FreeTriple(rID)

			pt := triplePlaintext(t, 4096)
			wireBuf := make([]byte, len(pt)+64<<10)
			wLen, st := TripleEncryptMessage(sID, pt, wireBuf)
			if st != StatusOK {
				t.Fatalf("TripleEncryptMessage: %v", st)
			}
			ptOut := make([]byte, len(pt)+1024)
			pLen, st := TripleDecryptMessage(rID, wireBuf[:wLen], ptOut)
			if st != StatusOK {
				t.Fatalf("TripleDecryptMessage: %v", st)
			}
			if !bytes.Equal(ptOut[:pLen], pt) {
				t.Fatalf("round-trip plaintext mismatch: got %d bytes, want %d bytes", pLen, len(pt))
			}
		})
	}
}

// TestTripleStreamRoundTrip covers the Streaming AEAD FFI surface
// (TripleEncryptStream / TripleDecryptStream) for the default
// full-stack profile.
func TestTripleStreamRoundTrip(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)

	rID, st := TripleOpen(triple.ProfileStreamingAEADTripleMACV1, blobBuf[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen: %v", st)
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, 3*4096)
	wireBuf := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptStream(sID, pt, wireBuf)
	if st != StatusOK {
		t.Fatalf("TripleEncryptStream: %v", st)
	}
	ptOut := make([]byte, len(pt)+1024)
	pLen, st := TripleDecryptStream(rID, wireBuf[:wLen], ptOut)
	if st != StatusOK {
		t.Fatalf("TripleDecryptStream: %v", st)
	}
	if !bytes.Equal(ptOut[:pLen], pt) {
		t.Fatalf("stream round-trip mismatch: got %d bytes, want %d bytes", pLen, len(pt))
	}
}

// TestTripleBufferTooSmall confirms the buffer-too-small probe path
// on both Init and cipher entries — the caller sizes their buffer via
// a zero-capacity probe, then retries with the reported capacity.
func TestTripleBufferTooSmall(t *testing.T) {
	// Init probe: undersized blob buffer must return
	// StatusBufferTooSmall + the required capacity through blobLen.
	// The Pipeline is closed internally on the too-small path so no
	// handle leaks even though the FFI caller does not receive one.
	tinyBuf := make([]byte, 4)
	_, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", tinyBuf)
	if st != StatusBufferTooSmall {
		t.Fatalf("TripleInit tiny buf: %v, want StatusBufferTooSmall", st)
	}
	if blobLen <= len(tinyBuf) {
		t.Fatalf("TripleInit tiny buf: blobLen=%d not greater than cap=%d", blobLen, len(tinyBuf))
	}

	// EncryptMessage probe: too-small wire buffer must return
	// StatusBufferTooSmall + required capacity through outLen.
	blobBuf := make([]byte, 1<<15)
	sID, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)

	pt := triplePlaintext(t, 1024)
	wLen, st := TripleEncryptMessage(sID, pt, tinyBuf)
	if st != StatusBufferTooSmall {
		t.Fatalf("TripleEncryptMessage tiny buf: %v, want StatusBufferTooSmall", st)
	}
	if wLen <= len(tinyBuf) {
		t.Fatalf("TripleEncryptMessage tiny buf: wLen=%d not greater than cap=%d", wLen, len(tinyBuf))
	}
}

// TestTripleRekeyRoundTrip confirms that TripleRekey rotates the
// masters and the receiver's Pipeline continues to decrypt after
// opening on the rekeyed blob.
func TestTripleRekeyRoundTrip(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)

	// Draw two fresh masters for the rotation.
	pm := make([]byte, 32)
	wm := make([]byte, 32)
	if _, err := rand.Read(pm); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(wm); err != nil {
		t.Fatal(err)
	}
	newBlob := make([]byte, 1<<15)
	nLen, st := TripleRekey(sID, pm, wm, newBlob)
	if st != StatusOK {
		t.Fatalf("TripleRekey: %v", st)
	}

	// Old blob and rekeyed blob differ.
	if bytes.Equal(blobBuf[:blobLen], newBlob[:nLen]) {
		t.Fatalf("TripleRekey produced identical blob bytes")
	}

	// Fresh receiver on the rekeyed blob still round-trips.
	rID, st := TripleOpen(triple.ProfileStreamingAEADTripleMACV1, newBlob[:nLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen (rekeyed): %v", st)
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, 2048)
	wire := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptMessage(sID, pt, wire)
	if st != StatusOK {
		t.Fatalf("TripleEncryptMessage post-rekey: %v", st)
	}
	ptOut := make([]byte, len(pt)+1024)
	pLen, st := TripleDecryptMessage(rID, wire[:wLen], ptOut)
	if st != StatusOK {
		t.Fatalf("TripleDecryptMessage post-rekey: %v", st)
	}
	if !bytes.Equal(ptOut[:pLen], pt) {
		t.Fatalf("post-rekey round-trip mismatch: got %d bytes, want %d bytes", pLen, len(pt))
	}
}

// TestTripleCloseThenUse confirms that a Pipeline whose Close has
// fired rejects every cipher-path call with StatusTripleClosed.
func TestTripleCloseThenUse(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	id, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(id)

	if st := TripleClose(id); st != StatusOK {
		t.Fatalf("TripleClose: %v", st)
	}
	// Second Close is a no-op returning StatusOK.
	if st := TripleClose(id); st != StatusOK {
		t.Fatalf("TripleClose (idempotent): %v", st)
	}

	pt := []byte("closed pipeline")
	wire := make([]byte, 1024)
	_, st = TripleEncryptMessage(id, pt, wire)
	if st != StatusTripleClosed {
		t.Fatalf("TripleEncryptMessage post-close: %v, want StatusTripleClosed", st)
	}
}

// TestTripleBadHandle covers the resolveTriple(0) short-circuit and
// the FreeTriple(0) short-circuit.
func TestTripleBadHandle(t *testing.T) {
	pt := []byte("bad handle")
	wire := make([]byte, 1024)
	if _, st := TripleEncryptMessage(0, pt, wire); st != StatusBadHandle {
		t.Fatalf("TripleEncryptMessage(0): %v, want StatusBadHandle", st)
	}
	if st := FreeTriple(0); st != StatusBadHandle {
		t.Fatalf("FreeTriple(0): %v, want StatusBadHandle", st)
	}
	if st := TripleClose(0); st != StatusBadHandle {
		t.Fatalf("TripleClose(0): %v, want StatusBadHandle", st)
	}
}

// TestTripleOptsUnknownKey confirms that a URL-query opts string with
// a key the parser does not recognise is rejected with StatusBadInput
// rather than silently ignored — the "typoed override silently does
// nothing" trap is closed at the FFI layer.
func TestTripleOptsUnknownKey(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	_, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "wibble=42", blobBuf)
	if st != StatusBadInput {
		t.Fatalf("TripleInit unknown key: %v, want StatusBadInput", st)
	}
}

// TestTripleOptsMalformedHex confirms that a hex-decoding failure on
// pm= / wm= surfaces as StatusBadInput.
func TestTripleOptsMalformedHex(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	// odd-length hex → hex.DecodeString error → StatusBadInput.
	_, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "pm=abc", blobBuf)
	if st != StatusBadInput {
		t.Fatalf("TripleInit odd hex: %v, want StatusBadInput", st)
	}
}

// TestTripleOptsTypedOverride confirms that a well-formed opts string
// carrying a per-Pipeline override (nonceBits=256) drives the
// Pipeline through Init without a parse error. The round-trip on
// EncryptMessage → DecryptMessage confirms the override does not
// break the wire shape.
func TestTripleOptsTypedOverride(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "nonceBits=256&barrierFill=4&maxWorkers=2", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit typed override: %v", st)
	}
	defer FreeTriple(sID)

	rID, st := TripleOpen(triple.ProfileStreamingAEADTripleMACV1, blobBuf[:blobLen], "nonceBits=256&barrierFill=4&maxWorkers=2")
	if st != StatusOK {
		t.Fatalf("TripleOpen typed override: %v", st)
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, 2048)
	wire := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptMessage(sID, pt, wire)
	if st != StatusOK {
		t.Fatalf("TripleEncryptMessage: %v", st)
	}
	ptOut := make([]byte, len(pt)+1024)
	pLen, st := TripleDecryptMessage(rID, wire[:wLen], ptOut)
	if st != StatusOK {
		t.Fatalf("TripleDecryptMessage: %v", st)
	}
	if !bytes.Equal(ptOut[:pLen], pt) {
		t.Fatalf("override round-trip mismatch")
	}
}

// TestTripleOptsProfileKeyIgnored confirms that a profile= key on the
// opts string is accepted silently rather than raising an unknown-key
// error. Bindings echo the profile name into the opts payload for
// diagnostic bookkeeping; the parser must ignore that redundancy.
func TestTripleOptsProfileKeyIgnored(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	_, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "profile=streaming-aead-triple-mac-v1", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit profile= echo: %v", st)
	}
}

// TestTripleOptsMasterHex confirms that hex-encoded pm / wm master
// values are decoded and honoured — the Pipeline that opens against
// the blob resolves the same masters, and the round-trip succeeds.
func TestTripleOptsMasterHex(t *testing.T) {
	pm := make([]byte, 32)
	wm := make([]byte, 32)
	if _, err := rand.Read(pm); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(wm); err != nil {
		t.Fatal(err)
	}
	opts := "pm=" + hex.EncodeToString(pm) + "&wm=" + hex.EncodeToString(wm)

	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, opts, blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit master hex: %v", st)
	}
	defer FreeTriple(sID)

	rID, st := TripleOpen(triple.ProfileStreamingAEADTripleMACV1, blobBuf[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen: %v", st)
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, 1024)
	wire := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptMessage(sID, pt, wire)
	if st != StatusOK {
		t.Fatalf("TripleEncryptMessage: %v", st)
	}
	ptOut := make([]byte, len(pt)+1024)
	pLen, st := TripleDecryptMessage(rID, wire[:wLen], ptOut)
	if st != StatusOK {
		t.Fatalf("TripleDecryptMessage: %v", st)
	}
	if !bytes.Equal(ptOut[:pLen], pt) {
		t.Fatalf("master-hex round-trip mismatch")
	}
}
