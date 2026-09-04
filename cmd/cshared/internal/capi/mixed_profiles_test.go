package capi

import (
	"bytes"
	"testing"

	"github.com/everanium/itb/triple"
)

// shippedMixedProfileNamesCapi mirrors the shipped mixed profile
// identifiers exposed by the triple package. Kept as a local literal
// slice so the test suite exercises the FFI-visible name shape
// verbatim.
var shippedMixedProfileNamesCapi = []string{
	triple.ProfileStreamingAEADTripleMACMixedV1,
	triple.ProfileStreamingNoAEADTripleMixedV1,
	triple.ProfileSingleMsgTripleMACMixedV1,
	triple.ProfileSingleMsgTripleNoMACMixedV1,
}

// TestTripleInitShippedMixedProfilesCapi round-trips every shipped
// mixed profile through the capi surface via TripleInit + TripleLoad
// + TripleEncryptMessage + TripleDecryptMessage. This is the FFI-side
// counterpart to triple/mixed_profiles_test.go's Go-side round-trip
// suite.
func TestTripleInitShippedMixedProfilesCapi(t *testing.T) {
	for _, name := range shippedMixedProfileNamesCapi {
		t.Run(name, func(t *testing.T) {
			blobBuf := make([]byte, 1<<15)
			sID, blobLen, st := TripleInit(name, "", blobBuf)
			if st != StatusOK {
				t.Fatalf("TripleInit(%q): %v (%s)", name, st, LastError())
			}
			defer FreeTriple(sID)

			rID, st := TripleLoad(blobBuf[:blobLen])
			if st != StatusOK {
				t.Fatalf("TripleLoad(%q): %v (%s)", name, st, LastError())
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
		})
	}
}

// TestTripleRegisterMixedCapiRoundTrip installs a custom mixed
// profile via TripleRegister with a hashes array in the profile JSON,
// then round-trips a message through the FFI cipher path.
func TestTripleRegisterMixedCapiRoundTrip(t *testing.T) {
	const name = "capitest-triple-mixed-roundtrip-v1"
	// Width-256 mixed constellation using every shipped width-256
	// primitive with two-slot repeats.
	opts := `{"mode":"singlemsg-mac","width":256,` +
		`"hashes":["areion256","blake3","blake2b256","blake2s","chacha20","areion256","blake3","blake2b256"],` +
		`"keybits":1024,"mac":"hmac-blake3","wrapper":true,"outer":"chacha20",` +
		`"parallax":true,"palette":["aescmac","chacha20","blake3"],"segment":4093,"chunk":16777216}`
	if st := TripleRegister(name, opts); st != StatusOK {
		t.Fatalf("TripleRegister: %v (%s)", st, LastError())
	}

	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(name, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit against registered mixed profile: %v (%s)", st, LastError())
	}
	defer FreeTriple(sID)

	rID, st := TripleLoad(blobBuf[:blobLen])
	if st != StatusOK {
		t.Fatalf("TripleLoad against registered mixed profile: %v (%s)", st, LastError())
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

// TestTripleRegisterMixedCapiValidationErrors exercises the
// mixed-path profile-JSON validation surface: wrong entry count,
// unknown primitive name, mixed-alongside-hash, width mismatch.
// Every failure surfaces as StatusBadInput at the capi boundary.
func TestTripleRegisterMixedCapiValidationErrors(t *testing.T) {
	base := `"mode":"singlemsg-mac","width":256,"keybits":1024,"mac":"hmac-blake3","wrapper":true,"outer":"chacha20","parallax":true,"palette":["aescmac","chacha20","blake3"],"segment":4093,"chunk":16777216`

	cases := []struct {
		label string
		name  string
		opts  string
	}{
		{
			label: "seven-entries",
			name:  "capitest-triple-mixed-seven-v1",
			opts:  `{` + base + `,"hashes":["areion256","blake3","blake2b256","blake2s","chacha20","areion256","blake3"]}`,
		},
		{
			label: "nine-entries",
			name:  "capitest-triple-mixed-nine-v1",
			opts:  `{` + base + `,"hashes":["areion256","blake3","blake2b256","blake2s","chacha20","areion256","blake3","blake2b256","blake2s"]}`,
		},
		{
			label: "unknown-primitive-slot4",
			name:  "capitest-triple-mixed-unknown-v1",
			opts:  `{` + base + `,"hashes":["areion256","blake3","blake2b256","blake2s","not-a-hash","areion256","blake3","blake2b256"]}`,
		},
		{
			label: "width-mismatch-aescmac-in-256",
			name:  "capitest-triple-mixed-widthmix-v1",
			// aescmac is width 128; profile width is 256.
			opts: `{` + base + `,"hashes":["areion256","blake3","aescmac","blake2s","chacha20","areion256","blake3","blake2b256"]}`,
		},
		{
			label: "mixed-alongside-hash",
			name:  "capitest-triple-mixed-both-v1",
			opts:  `{` + base + `,"hash":"areion256","hashes":["areion256","blake3","blake2b256","blake2s","chacha20","areion256","blake3","blake2b256"]}`,
		},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			st := TripleRegister(c.name, c.opts)
			if st != StatusBadInput {
				t.Fatalf("TripleRegister %s: got %v, want StatusBadInput; LastError=%q",
					c.label, st, LastError())
			}
		})
	}
}

// TestTripleRegisterMixedCapiEmptyInnerHashes confirms that an
// empty hashes array is treated as "no mixed entries" — the
// single-primitive path must still fire when hash is supplied
// alongside.
func TestTripleRegisterMixedCapiEmptyInnerHashes(t *testing.T) {
	const name = "capitest-triple-mixed-empty-v1"
	opts := `{"mode":"singlemsg-mac","width":512,"hash":"areion512","hashes":[],"keybits":1024,"mac":"hmac-blake3","wrapper":true,"outer":"chacha20","parallax":true,"palette":["aescmac","chacha20","blake3"],"segment":4093,"chunk":16777216}`
	if st := TripleRegister(name, opts); st != StatusOK {
		t.Fatalf("TripleRegister empty hashes: %v (%s)", st, LastError())
	}
}

// TestTripleInitPerCallMixedHashesOverrideCapi exercises the per-call
// innerHashes= opts key at the TripleInit boundary: a shipped
// single-primitive profile is switched to a mixed constellation for
// one Pipeline instance without registering a new profile, and
// TripleLoad reproduces the constellation from the blob's record. The FFI-side round-trip matches
// triple/opts_mixedhashes_test.go's TestOptsMixedHashesOverrideSingleToMixed
// on the Go side and confirms the URL-query key wired through
// parseTripleOpts lands in triple.Opts.MixedHashes correctly.
func TestTripleInitPerCallMixedHashesOverrideCapi(t *testing.T) {
	// Shipped single-primitive width-512 profile; override to an
	// 8-slot width-512 constellation using both shipped width-512
	// primitives.
	opts := "innerHashes=areion512,blake2b512,areion512,blake2b512,areion512,blake2b512,areion512,blake2b512"

	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, opts, blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit(single-primitive profile, per-call innerHashes): %v (%s)", st, LastError())
	}
	defer FreeTriple(sID)

	rID, st := TripleLoad(blobBuf[:blobLen])
	if st != StatusOK {
		t.Fatalf("TripleLoad(single-primitive profile, per-call innerHashes): %v (%s)", st, LastError())
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
		t.Fatalf("round-trip plaintext mismatch: got %d bytes, want %d bytes", pLen, len(pt))
	}
}

// TestTripleInitPerCallMixedHashesValidationCapi confirms that malformed
// per-call innerHashes values (wrong entry count, unknown primitive)
// surface as StatusBadInput at the capi boundary — same fail-fast
// discipline the Register-side path already enforces.
func TestTripleInitPerCallMixedHashesValidationCapi(t *testing.T) {
	blobBuf := make([]byte, 1<<15)

	cases := []struct {
		label string
		opts  string
	}{
		{
			label: "seven-entries",
			opts:  "innerHashes=areion512,blake2b512,areion512,blake2b512,areion512,blake2b512,areion512",
		},
		{
			label: "nine-entries",
			opts:  "innerHashes=areion512,blake2b512,areion512,blake2b512,areion512,blake2b512,areion512,blake2b512,areion512",
		},
		{
			label: "unknown-primitive-slot4",
			opts:  "innerHashes=areion512,blake2b512,areion512,blake2b512,not-a-hash,blake2b512,areion512,blake2b512",
		},
		{
			label: "width-mismatch-blake3-in-512",
			opts:  "innerHashes=areion512,blake2b512,blake3,blake2b512,areion512,blake2b512,areion512,blake2b512",
		},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			_, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, c.opts, blobBuf)
			if st != StatusBadInput {
				t.Fatalf("TripleInit %s: got %v, want StatusBadInput; LastError=%q",
					c.label, st, LastError())
			}
		})
	}
}
