package capi

import (
	"bytes"
	"strings"
	"testing"

	"github.com/everanium/itb/triple"
)

// tripleRegisterOptsFull returns a URL-query opts string that
// installs a full-stack streaming AEAD profile shape (parallax on +
// wrapper on, MAC-authenticated, 512-bit inner hash). Callers append
// or drop fields to exercise the validation surface.
func tripleRegisterOptsFull() string {
	return strings.Join([]string{
		"mode=streaming-aead",
		"width=512",
		"innerHash=areion512",
		"keyBits=1024",
		"macName=hmac-blake3",
		"outerCipher=chacha20",
		"parallaxPalette=aescmac,chacha20,blake3",
		"parallaxSegmentSize=4093",
		"chunkSize=16777216",
		"parallaxOn=true",
		"wrapperOn=true",
	}, "&")
}

// TestTripleRegisterProfileCapi covers the capi entry surface:
// success, duplicate-name (StatusProfileExists), reserved-prefix
// rejection (StatusBadInput), and unknown-key rejection
// (StatusBadInput).
func TestTripleRegisterProfileCapi(t *testing.T) {
	const name = "capitest-triple-register-v1"
	if st := TripleRegisterProfile(name, tripleRegisterOptsFull()); st != StatusOK {
		t.Fatalf("TripleRegisterProfile initial: %v (%s)", st, LastError())
	}

	// Duplicate name → StatusProfileExists.
	if st := TripleRegisterProfile(name, tripleRegisterOptsFull()); st != StatusProfileExists {
		t.Fatalf("TripleRegisterProfile duplicate: %v, want StatusProfileExists", st)
	}

	// Reserved-prefix name → StatusBadInput.
	if st := TripleRegisterProfile("streaming-user-v1", tripleRegisterOptsFull()); st != StatusBadInput {
		t.Fatalf("TripleRegisterProfile reserved-prefix: %v, want StatusBadInput", st)
	}

	// Unknown query key → StatusBadInput.
	badOpts := tripleRegisterOptsFull() + "&notARealKey=1"
	if st := TripleRegisterProfile("capitest-triple-badkey-v1", badOpts); st != StatusBadInput {
		t.Fatalf("TripleRegisterProfile unknown key: %v, want StatusBadInput", st)
	}

	// Malformed value (non-integer width) → StatusBadInput.
	badWidth := "mode=streaming-aead&width=abc&innerHash=areion512&keyBits=1024&macName=hmac-blake3&outerCipher=chacha20&parallaxPalette=aescmac,chacha20,blake3&parallaxSegmentSize=4093&chunkSize=16777216&parallaxOn=true&wrapperOn=true"
	if st := TripleRegisterProfile("capitest-triple-badwidth-v1", badWidth); st != StatusBadInput {
		t.Fatalf("TripleRegisterProfile bad width: %v, want StatusBadInput", st)
	}

	// Invalid inner-hash → StatusBadInput.
	badHash := "mode=streaming-aead&width=512&innerHash=notreal&keyBits=1024&macName=hmac-blake3&outerCipher=chacha20&parallaxPalette=aescmac,chacha20,blake3&parallaxSegmentSize=4093&chunkSize=16777216&parallaxOn=true&wrapperOn=true"
	if st := TripleRegisterProfile("capitest-triple-badhash-v1", badHash); st != StatusBadInput {
		t.Fatalf("TripleRegisterProfile bad inner hash: %v, want StatusBadInput", st)
	}
}

// TestTripleRegisterProfileNilName exercises the C-side wrapper's
// nil-guard behaviour; nil name maps to StatusBadInput without
// panicking through cgo.
func TestTripleRegisterProfileNilName(t *testing.T) {
	// Empty-string name — the pattern-match rejection path in
	// triple.RegisterProfile, exercised through the capi surface.
	if st := TripleRegisterProfile("", tripleRegisterOptsFull()); st != StatusBadInput {
		t.Fatalf("TripleRegisterProfile empty name: %v, want StatusBadInput", st)
	}
}

// TestTripleRegisterProfileRoundTrip installs a fresh custom profile
// via TripleRegisterProfile and then exercises TripleInit →
// TripleEncryptMessage → TripleDecryptMessage against the newly
// registered name — the receiver reconstructs an equivalent Pipeline
// via TripleOpen and decrypts the sender's wire bytes.
func TestTripleRegisterProfileRoundTrip(t *testing.T) {
	const name = "capitest-triple-roundtrip-v1"
	// singlemsg-mac mode so the round-trip covers EncryptMessage /
	// DecryptMessage — the Streaming variant is covered by the
	// pre-existing TestTripleStreamRoundTrip.
	opts := strings.Join([]string{
		"mode=singlemsg-mac",
		"width=512",
		"innerHash=areion512",
		"keyBits=1024",
		"macName=hmac-blake3",
		"outerCipher=chacha20",
		"parallaxPalette=aescmac,chacha20,blake3",
		"parallaxSegmentSize=4093",
		"chunkSize=16777216",
		"parallaxOn=true",
		"wrapperOn=true",
	}, "&")
	if st := TripleRegisterProfile(name, opts); st != StatusOK {
		t.Fatalf("TripleRegisterProfile: %v (%s)", st, LastError())
	}

	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(name, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit against registered profile: %v (%s)", st, LastError())
	}
	defer FreeTriple(sID)

	rID, st := TripleOpen(name, blobBuf[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen against registered profile: %v (%s)", st, LastError())
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, 2048)
	wire := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptMessage(sID, pt, wire)
	if st != StatusOK {
		t.Fatalf("TripleEncryptMessage: %v (%s)", st, LastError())
	}
	out := make([]byte, len(pt)+1024)
	pLen, st := TripleDecryptMessage(rID, wire[:wLen], out)
	if st != StatusOK {
		t.Fatalf("TripleDecryptMessage: %v (%s)", st, LastError())
	}
	if !bytes.Equal(out[:pLen], pt) {
		t.Fatalf("round-trip plaintext mismatch: got %d bytes, want %d bytes",
			pLen, len(pt))
	}
}

// TestTripleRegisterProfileEmptyOptsRejected confirms an empty opts
// string is rejected — a zero-value triple.Profile fails validation
// on Mode (empty), which surfaces as StatusBadInput.
func TestTripleRegisterProfileEmptyOptsRejected(t *testing.T) {
	if st := TripleRegisterProfile("capitest-triple-emptyopts-v1", ""); st != StatusBadInput {
		t.Fatalf("TripleRegisterProfile empty opts: %v, want StatusBadInput", st)
	}
}

// TestTripleRegisterProfileSentinelDistinct confirms the duplicate-
// name path returns StatusProfileExists (distinct from
// StatusBadInput) so bindings can map the two paths to different
// language-side exceptions.
func TestTripleRegisterProfileSentinelDistinct(t *testing.T) {
	name := "capitest-triple-sentinel-v1"
	if st := TripleRegisterProfile(name, tripleRegisterOptsFull()); st != StatusOK {
		t.Fatalf("TripleRegisterProfile initial: %v (%s)", st, LastError())
	}
	st := TripleRegisterProfile(name, tripleRegisterOptsFull())
	if st == StatusBadInput {
		t.Fatalf("duplicate name mapped to StatusBadInput; should be StatusProfileExists")
	}
	if st != StatusProfileExists {
		t.Fatalf("duplicate name: got %v, want StatusProfileExists", st)
	}
	// Reinforce with a direct lookup — the profile installed by the
	// initial call must still be visible via the Go registry.
	pipe, _, err := triple.Init(name, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Init against registered profile: %v", err)
	}
	pipe.Close()
}

// TestParseTripleRegisterOptsTagStubSize covers the tagStubSize
// profile-shape key: accepted decimal value lands in
// triple.Profile.TagStubSize, absent key leaves the zero value
// (defer to the MacName auto-probe or the 32-byte default), and a
// non-numeric value is rejected.
func TestParseTripleRegisterOptsTagStubSize(t *testing.T) {
	prof, err := parseTripleRegisterOpts("tagStubSize=16")
	if err != nil {
		t.Fatalf("tagStubSize=16: %v", err)
	}
	if prof.TagStubSize != 16 {
		t.Fatalf("TagStubSize = %d, want 16", prof.TagStubSize)
	}
	prof, err = parseTripleRegisterOpts("chunkSize=65536")
	if err != nil {
		t.Fatalf("absent tagStubSize: %v", err)
	}
	if prof.TagStubSize != 0 {
		t.Fatalf("absent key: TagStubSize = %d, want 0", prof.TagStubSize)
	}
	if _, err := parseTripleRegisterOpts("tagStubSize=wide"); err == nil {
		t.Fatal("tagStubSize=wide: accepted, want error")
	}
	// Out-of-range values (accepted set is 0 or [16, 64]) are rejected
	// at the parser so the binding-side error surfaces before
	// triple.RegisterProfile runs.
	for _, v := range []string{"-1", "15", "65", "128"} {
		if _, err := parseTripleRegisterOpts("tagStubSize=" + v); err == nil {
			t.Errorf("tagStubSize=%s: accepted, want range rejection", v)
		}
	}
	for _, v := range []string{"0", "16", "64"} {
		if _, err := parseTripleRegisterOpts("tagStubSize=" + v); err != nil {
			t.Errorf("tagStubSize=%s: rejected (%v), want accept", v, err)
		}
	}
}
