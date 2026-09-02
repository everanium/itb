package capi

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// Scope: status-code label surface, the BlobWidth / BlobMode metadata
// accessors across all three widths and the bad-handle paths behind
// them, ParseChunkLen header validation branches, and the
// parseTripleOpts / parseBoolOpt option-string parsing branches.

// TestStatusStringAllCodes verifies every defined status code carries
// a non-empty distinct-from-unknown label, and that an out-of-range
// value falls through to the "unknown status" label.
func TestStatusStringAllCodes(t *testing.T) {
	defined := []Status{
		StatusOK, StatusBadHash, StatusBadKeyBits, StatusBadHandle,
		StatusBadInput, StatusBufferTooSmall, StatusEncryptFailed,
		StatusDecryptFailed, StatusSeedWidthMix, StatusBadMAC,
		StatusMACFailure,
		StatusReserved11, StatusReserved12, StatusReserved13,
		StatusReserved14, StatusReserved15, StatusReserved16,
		StatusReserved17,
		StatusBlobModeMismatch, StatusBlobMalformed,
		StatusBlobVersionTooNew, StatusBlobTooManyOpts,
		StatusStreamTruncated, StatusStreamAfterFinal,
		StatusTripleClosed, StatusProfileExists,
		StatusInternal,
	}
	for _, s := range defined {
		label := s.String()
		if label == "" || label == "unknown status" {
			t.Errorf("Status(%d).String() = %q, want a defined label", int(s), label)
		}
	}
	if got := Status(-1).String(); got != "unknown status" {
		t.Errorf("Status(-1).String() = %q, want \"unknown status\"", got)
	}
	if got := Status(1000).String(); got != "unknown status" {
		t.Errorf("Status(1000).String() = %q, want \"unknown status\"", got)
	}
}

// TestBlobWidthModeAllWidths verifies the BlobWidth / BlobMode
// metadata accessors on freshly constructed handles at every width: a
// fresh handle reports its construction width and Mode == 0 (no
// Import / Export state transition yet).
func TestBlobWidthModeAllWidths(t *testing.T) {
	cases := []struct {
		name  string
		mk    func() (BlobHandleID, Status)
		width hashes.Width
	}{
		{"W128", NewBlob128, hashes.W128},
		{"W256", NewBlob256, hashes.W256},
		{"W512", NewBlob512, hashes.W512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, st := tc.mk()
			if st != StatusOK {
				t.Fatalf("constructor: %v", st)
			}
			defer FreeBlob(id)
			w, st := BlobWidth(id)
			if st != StatusOK || w != tc.width {
				t.Fatalf("BlobWidth = (%v, %v), want (%v, ok)", w, st, tc.width)
			}
			mode, st := BlobMode(id)
			if st != StatusOK || mode != 0 {
				t.Fatalf("BlobMode = (%d, %v), want (0, ok) on a fresh handle", mode, st)
			}
		})
	}
}

// TestBlobWidthModeBadHandle verifies that the metadata accessors
// reject a zero handle and a stale (already freed) handle with
// StatusBadHandle instead of panicking — the stale-handle path routes
// through resolveBlob's deferred recover.
func TestBlobWidthModeBadHandle(t *testing.T) {
	if _, st := BlobWidth(0); st != StatusBadHandle {
		t.Fatalf("BlobWidth(0) = %v, want StatusBadHandle", st)
	}
	if _, st := BlobMode(0); st != StatusBadHandle {
		t.Fatalf("BlobMode(0) = %v, want StatusBadHandle", st)
	}
	id, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128: %v", st)
	}
	if st := FreeBlob(id); st != StatusOK {
		t.Fatalf("FreeBlob: %v", st)
	}
	if _, st := BlobWidth(id); st != StatusBadHandle {
		t.Fatalf("BlobWidth(stale) = %v, want StatusBadHandle", st)
	}
	if _, st := BlobMode(id); st != StatusBadHandle {
		t.Fatalf("BlobMode(stale) = %v, want StatusBadHandle", st)
	}
}

// TestParseChunkLenHeaderValidation walks the ParseChunkLen rejection
// branches: unsupported nonce size, truncated header, zero dimensions,
// and an announced pixel count above the container cap — then confirms
// the accept path at every supported nonce size.
func TestParseChunkLenHeaderValidation(t *testing.T) {
	mkHeader := func(nonceBytes int, width, height uint16) []byte {
		h := make([]byte, 2*nonceBytes+4)
		binary.BigEndian.PutUint16(h[2*nonceBytes:], width)
		binary.BigEndian.PutUint16(h[2*nonceBytes+2:], height)
		return h
	}

	if _, st := ParseChunkLen(make([]byte, 64), 24); st != StatusBadInput {
		t.Fatalf("nonceBytes=24: %v, want StatusBadInput", st)
	}
	if _, st := ParseChunkLen(make([]byte, 2*16+3), 16); st != StatusBadInput {
		t.Fatalf("short header: %v, want StatusBadInput", st)
	}
	if _, st := ParseChunkLen(mkHeader(16, 0, 7), 16); st != StatusBadInput {
		t.Fatalf("zero width: %v, want StatusBadInput", st)
	}
	if _, st := ParseChunkLen(mkHeader(16, 7, 0), 16); st != StatusBadInput {
		t.Fatalf("zero height: %v, want StatusBadInput", st)
	}
	// 65535 * 65535 pixels overflows the container pixel cap.
	if _, st := ParseChunkLen(mkHeader(16, 65535, 65535), 16); st != StatusBadInput {
		t.Fatalf("pixel cap: %v, want StatusBadInput", st)
	}
	for _, nonceBytes := range []int{16, 32, 64} {
		n, st := ParseChunkLen(mkHeader(nonceBytes, 12, 34), nonceBytes)
		if st != StatusOK {
			t.Fatalf("nonceBytes=%d: %v, want ok", nonceBytes, st)
		}
		want := 2*nonceBytes + 4 + 12*34*itb.Channels
		if n != want {
			t.Fatalf("nonceBytes=%d: chunk len %d, want %d", nonceBytes, n, want)
		}
	}
}

// TestParseTripleOptsKeys drives every accepted option key through
// parseTripleOpts and confirms the parsed triple.Opts fields.
func TestParseTripleOptsKeys(t *testing.T) {
	opts, err := parseTripleOpts("")
	if err != nil {
		t.Fatalf("empty query: %v", err)
	}
	if opts.MaxWorkers != 0 || opts.WithParallax != nil {
		t.Fatalf("empty query produced non-zero opts: %+v", opts)
	}

	query := strings.Join([]string{
		"profile=ignored",
		"pm=0a0b0c",
		"wm=feff",
		"withParallax=true",
		"withWrapper=false",
		"maxWorkers=3",
		"nonceBits=256",
		"barrierFill=4",
		"chunkSize=65536",
		"keyBits=1024",
		"parallaxSegmentSize=17",
		"macName=keccak800",
		"innerHash=blake3",
		"innerHashes=a,b,c,d,e,f,g,h",
		"outerCipher=chacha20",
		"parallaxPalette=blake2s,blake3",
	}, "&")
	opts, err = parseTripleOpts(query)
	if err != nil {
		t.Fatalf("full query: %v", err)
	}
	if string(opts.PermMaster) != "\x0a\x0b\x0c" || string(opts.WrapMaster) != "\xfe\xff" {
		t.Fatalf("pm/wm mismatch: %x / %x", opts.PermMaster, opts.WrapMaster)
	}
	if opts.WithParallax == nil || !*opts.WithParallax {
		t.Fatal("withParallax=true not honoured")
	}
	if opts.WithWrapper == nil || *opts.WithWrapper {
		t.Fatal("withWrapper=false not honoured")
	}
	if opts.MaxWorkers != 3 || opts.NonceBits != 256 || opts.BarrierFill != 4 ||
		opts.ChunkSize != 65536 || opts.KeyBits != 1024 || opts.ParallaxSegmentSize != 17 {
		t.Fatalf("numeric opts mismatch: %+v", opts)
	}
	if opts.MacName != "keccak800" || opts.InnerHash != "blake3" || opts.OuterCipher != "chacha20" {
		t.Fatalf("name opts mismatch: %+v", opts)
	}
	if opts.MixedHashes != [8]string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		t.Fatalf("innerHashes mismatch: %+v", opts.MixedHashes)
	}
	if len(opts.ParallaxPalette) != 2 || opts.ParallaxPalette[0] != "blake2s" || opts.ParallaxPalette[1] != "blake3" {
		t.Fatalf("parallaxPalette mismatch: %+v", opts.ParallaxPalette)
	}
}

// TestParseTripleOptsRejections walks the parseTripleOpts error
// branches: malformed query encoding, invalid hex, invalid bool,
// invalid integers, wrong innerHashes arity, and an unknown key.
func TestParseTripleOptsRejections(t *testing.T) {
	bad := []string{
		"pm=%zz",
		"pm=xyz",
		"wm=xyz",
		"withParallax=yes",
		"withWrapper=1",
		"maxWorkers=three",
		"nonceBits=big",
		"barrierFill=full",
		"chunkSize=lots",
		"keyBits=many",
		"parallaxSegmentSize=wide",
		"innerHashes=a,b,c",
		"noSuchKey=1",
	}
	for _, q := range bad {
		if _, err := parseTripleOpts(q); err == nil {
			t.Errorf("query %q: accepted, want error", q)
		}
	}
	// Empty values for the list-typed keys are silently skipped.
	opts, err := parseTripleOpts("innerHashes=&parallaxPalette=")
	if err != nil {
		t.Fatalf("empty list values: %v", err)
	}
	if opts.MixedHashes != [8]string{} || opts.ParallaxPalette != nil {
		t.Fatalf("empty list values populated opts: %+v", opts)
	}
}

// TestParseBoolOpt verifies the strict three-state bool parsing:
// only the exact lowercase "true" / "false" strings are accepted.
func TestParseBoolOpt(t *testing.T) {
	if b, err := parseBoolOpt("true"); err != nil || !b {
		t.Fatalf("true: (%v, %v)", b, err)
	}
	if b, err := parseBoolOpt("false"); err != nil || b {
		t.Fatalf("false: (%v, %v)", b, err)
	}
	for _, v := range []string{"True", "FALSE", "yes", "1", ""} {
		if _, err := parseBoolOpt(v); err == nil {
			t.Errorf("value %q: accepted, want error", v)
		}
	}
}

// TestParseTripleOptsTagStubSize covers the tagStubSize option key:
// accepted decimal value lands in triple.Opts.TagStubSize, absent key
// leaves the zero value (profile default), and a non-numeric value is
// rejected.
func TestParseTripleOptsTagStubSize(t *testing.T) {
	opts, err := parseTripleOpts("tagStubSize=16")
	if err != nil {
		t.Fatalf("tagStubSize=16: %v", err)
	}
	if opts.TagStubSize != 16 {
		t.Fatalf("TagStubSize = %d, want 16", opts.TagStubSize)
	}
	opts, err = parseTripleOpts("chunkSize=65536")
	if err != nil {
		t.Fatalf("absent tagStubSize: %v", err)
	}
	if opts.TagStubSize != 0 {
		t.Fatalf("absent key: TagStubSize = %d, want 0", opts.TagStubSize)
	}
	if _, err := parseTripleOpts("tagStubSize=wide"); err == nil {
		t.Fatal("tagStubSize=wide: accepted, want error")
	}
	// Out-of-range values (accepted set is 0 or [16, 64]) are rejected
	// at the parser so the binding-side error surfaces before Init.
	for _, v := range []string{"-1", "15", "65", "128"} {
		if _, err := parseTripleOpts("tagStubSize=" + v); err == nil {
			t.Errorf("tagStubSize=%s: accepted, want range rejection", v)
		}
	}
	for _, v := range []string{"0", "16", "64"} {
		if _, err := parseTripleOpts("tagStubSize=" + v); err != nil {
			t.Errorf("tagStubSize=%s: rejected (%v), want accept", v, err)
		}
	}
}
