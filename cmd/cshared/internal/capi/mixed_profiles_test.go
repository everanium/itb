package capi

import (
	"bytes"
	"strings"
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
// mixed profile through the capi surface via TripleInit + TripleOpen
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

			rID, st := TripleOpen(name, blobBuf[:blobLen], "")
			if st != StatusOK {
				t.Fatalf("TripleOpen(%q): %v (%s)", name, st, LastError())
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

// TestTripleRegisterProfileMixedCapiRoundTrip installs a custom mixed
// profile via TripleRegisterProfile + innerHashes= opts key, then
// round-trips a message through the FFI cipher path.
func TestTripleRegisterProfileMixedCapiRoundTrip(t *testing.T) {
	const name = "capitest-triple-mixed-roundtrip-v1"
	// Width-256 mixed constellation using every shipped width-256
	// primitive with two-slot repeats.
	opts := strings.Join([]string{
		"mode=singlemsg-mac",
		"width=256",
		"innerHashes=areion256,blake3,blake2b256,blake2s,chacha20,areion256,blake3,blake2b256",
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
		t.Fatalf("TripleInit against registered mixed profile: %v (%s)", st, LastError())
	}
	defer FreeTriple(sID)

	rID, st := TripleOpen(name, blobBuf[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen against registered mixed profile: %v (%s)", st, LastError())
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

// TestTripleRegisterProfileMixedCapiValidationErrors exercises the
// mixed-path opts-string validation surface: wrong entry count,
// unknown primitive name, mixed-alongside-innerHash, width mismatch.
// Every failure surfaces as StatusBadInput at the capi boundary.
func TestTripleRegisterProfileMixedCapiValidationErrors(t *testing.T) {
	base := "mode=singlemsg-mac&width=256&keyBits=1024&macName=hmac-blake3&outerCipher=chacha20&parallaxPalette=aescmac,chacha20,blake3&parallaxSegmentSize=4093&chunkSize=16777216&parallaxOn=true&wrapperOn=true"

	cases := []struct {
		label string
		name  string
		opts  string
	}{
		{
			label: "seven-entries",
			name:  "capitest-triple-mixed-seven-v1",
			opts:  base + "&innerHashes=areion256,blake3,blake2b256,blake2s,chacha20,areion256,blake3",
		},
		{
			label: "nine-entries",
			name:  "capitest-triple-mixed-nine-v1",
			opts:  base + "&innerHashes=areion256,blake3,blake2b256,blake2s,chacha20,areion256,blake3,blake2b256,blake2s",
		},
		{
			label: "unknown-primitive-slot4",
			name:  "capitest-triple-mixed-unknown-v1",
			opts:  base + "&innerHashes=areion256,blake3,blake2b256,blake2s,not-a-hash,areion256,blake3,blake2b256",
		},
		{
			label: "width-mismatch-aescmac-in-256",
			name:  "capitest-triple-mixed-widthmix-v1",
			// aescmac is width 128; profile width is 256.
			opts: base + "&innerHashes=areion256,blake3,aescmac,blake2s,chacha20,areion256,blake3,blake2b256",
		},
		{
			label: "mixed-alongside-innerhash",
			name:  "capitest-triple-mixed-both-v1",
			opts:  base + "&innerHash=areion256&innerHashes=areion256,blake3,blake2b256,blake2s,chacha20,areion256,blake3,blake2b256",
		},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			st := TripleRegisterProfile(c.name, c.opts)
			if st != StatusBadInput {
				t.Fatalf("TripleRegisterProfile %s: got %v, want StatusBadInput; LastError=%q",
					c.label, st, LastError())
			}
		})
	}
}

// TestTripleRegisterProfileMixedCapiEmptyInnerHashes confirms that an
// empty innerHashes= value is treated as "no mixed entries" (skipped
// silently by the parser) — the single-primitive path must still fire
// when innerHash= is supplied alongside.
func TestTripleRegisterProfileMixedCapiEmptyInnerHashes(t *testing.T) {
	const name = "capitest-triple-mixed-empty-v1"
	opts := "mode=singlemsg-mac&width=512&innerHash=areion512&innerHashes=&keyBits=1024&macName=hmac-blake3&outerCipher=chacha20&parallaxPalette=aescmac,chacha20,blake3&parallaxSegmentSize=4093&chunkSize=16777216&parallaxOn=true&wrapperOn=true"
	if st := TripleRegisterProfile(name, opts); st != StatusOK {
		t.Fatalf("TripleRegisterProfile empty innerHashes: %v (%s)", st, LastError())
	}
}
