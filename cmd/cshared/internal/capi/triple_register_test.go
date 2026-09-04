package capi

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/everanium/itb/triple"
)

// tripleRegisterJSONFull returns a profile JSON record that installs a
// full-stack streaming AEAD profile shape (parallax on + wrapper on,
// MAC-authenticated, 512-bit inner hash). Callers rewrite fields to
// exercise the validation surface.
func tripleRegisterJSONFull() string {
	return `{"mode":"streaming-aead","width":512,"hash":"areion512","keybits":1024,` +
		`"mac":"hmac-blake3","wrapper":true,"outer":"chacha20",` +
		`"parallax":true,"palette":["aescmac","chacha20","blake3"],"segment":4093,"chunk":16777216}`
}

// TestTripleRegisterCapi covers the capi entry surface: success,
// duplicate-name (StatusProfileExists), reserved-prefix rejection
// (StatusBadInput), unknown-key rejection (StatusBadInput), and the
// name-key agreement rule.
func TestTripleRegisterCapi(t *testing.T) {
	const name = "capitest-triple-register-v1"
	if st := TripleRegister(name, tripleRegisterJSONFull()); st != StatusOK {
		t.Fatalf("TripleRegister initial: %v (%s)", st, LastError())
	}

	// Duplicate name → StatusProfileExists.
	if st := TripleRegister(name, tripleRegisterJSONFull()); st != StatusProfileExists {
		t.Fatalf("TripleRegister duplicate: %v, want StatusProfileExists", st)
	}

	// Reserved-prefix name → StatusBadInput.
	if st := TripleRegister("streaming-user-v1", tripleRegisterJSONFull()); st != StatusBadInput {
		t.Fatalf("TripleRegister reserved-prefix: %v, want StatusBadInput", st)
	}

	// Unknown JSON key → StatusBadInput.
	badKey := `{"notARealKey":1,` + tripleRegisterJSONFull()[1:]
	if st := TripleRegister("capitest-triple-badkey-v1", badKey); st != StatusBadInput {
		t.Fatalf("TripleRegister unknown key: %v, want StatusBadInput", st)
	}

	// Malformed value (string width) → StatusBadInput.
	badWidth := `{"mode":"streaming-aead","width":"abc","hash":"areion512","keybits":1024,"mac":"hmac-blake3","wrapper":true,"outer":"chacha20","parallax":true,"palette":["aescmac","chacha20","blake3"]}`
	if st := TripleRegister("capitest-triple-badwidth-v1", badWidth); st != StatusBadInput {
		t.Fatalf("TripleRegister bad width: %v, want StatusBadInput", st)
	}

	// Invalid inner-hash → StatusBadInput.
	badHash := `{"mode":"streaming-aead","width":512,"hash":"notreal","keybits":1024,"mac":"hmac-blake3","wrapper":true,"outer":"chacha20","parallax":true,"palette":["aescmac","chacha20","blake3"]}`
	if st := TripleRegister("capitest-triple-badhash-v1", badHash); st != StatusBadInput {
		t.Fatalf("TripleRegister bad inner hash: %v, want StatusBadInput", st)
	}

	// Malformed JSON → StatusBadInput.
	if st := TripleRegister("capitest-triple-badjson-v1", `{"mode":`); st != StatusBadInput {
		t.Fatalf("TripleRegister malformed JSON: %v, want StatusBadInput", st)
	}

	// hashes array of length 3 → StatusBadInput at the codec.
	badHashes := `{"mode":"streaming-aead","width":512,"hashes":["areion512","blake2b512","areion512"],"keybits":1024,"mac":"hmac-blake3","wrapper":true,"outer":"chacha20","parallax":true,"palette":["aescmac","chacha20","blake3"]}`
	if st := TripleRegister("capitest-triple-badhashes-v1", badHashes); st != StatusBadInput {
		t.Fatalf("TripleRegister hashes length 3: %v, want StatusBadInput", st)
	}

	// A name key inside the JSON must be empty or equal to the name
	// argument.
	withName := `{"name":"capitest-triple-named-v1",` + tripleRegisterJSONFull()[1:]
	if st := TripleRegister("capitest-triple-named-v1", withName); st != StatusOK {
		t.Fatalf("TripleRegister matching name key: %v (%s)", st, LastError())
	}
	if st := TripleRegister("capitest-triple-othername-v1", withName); st != StatusBadInput {
		t.Fatalf("TripleRegister disagreeing name key: %v, want StatusBadInput", st)
	}
}

// TestTripleRegisterNilName exercises the C-side wrapper's nil-guard
// behaviour; an empty name maps to StatusBadInput without panicking
// through cgo.
func TestTripleRegisterNilName(t *testing.T) {
	// Empty-string name — the pattern-match rejection path in
	// triple.Register, exercised through the capi surface.
	if st := TripleRegister("", tripleRegisterJSONFull()); st != StatusBadInput {
		t.Fatalf("TripleRegister empty name: %v, want StatusBadInput", st)
	}
}

// TestTripleRegisterRoundTrip installs a fresh custom profile via
// TripleRegister and then exercises TripleInit → TripleEncryptMessage
// → TripleDecryptMessage against the newly registered name — the
// receiver reconstructs an equivalent Pipeline via TripleLoad and
// decrypts the sender's wire bytes.
func TestTripleRegisterRoundTrip(t *testing.T) {
	const name = "capitest-triple-roundtrip-v1"
	// singlemsg-mac mode so the round-trip covers EncryptMessage /
	// DecryptMessage — the Streaming variant is covered by the
	// pre-existing TestTripleStreamRoundTrip.
	opts := `{"mode":"singlemsg-mac","width":512,"hash":"areion512","keybits":1024,` +
		`"mac":"hmac-blake3","wrapper":true,"outer":"chacha20",` +
		`"parallax":true,"palette":["aescmac","chacha20","blake3"],"segment":4093,"chunk":16777216}`
	if st := TripleRegister(name, opts); st != StatusOK {
		t.Fatalf("TripleRegister: %v (%s)", st, LastError())
	}

	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(name, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit against registered profile: %v (%s)", st, LastError())
	}
	defer FreeTriple(sID)

	rID, st := TripleLoad(blobBuf[:blobLen])
	if st != StatusOK {
		t.Fatalf("TripleLoad against registered profile: %v (%s)", st, LastError())
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

// TestTripleRegisterEmptyJSONRejected confirms an empty profile string
// is rejected with StatusBadInput, and that an empty object (a
// zero-value triple.Profile) fails validation on Mode.
func TestTripleRegisterEmptyJSONRejected(t *testing.T) {
	if st := TripleRegister("capitest-triple-emptyopts-v1", ""); st != StatusBadInput {
		t.Fatalf("TripleRegister empty string: %v, want StatusBadInput", st)
	}
	if st := TripleRegister("capitest-triple-emptyobj-v1", "{}"); st != StatusBadInput {
		t.Fatalf("TripleRegister empty object: %v, want StatusBadInput", st)
	}
}

// TestTripleRegisterSentinelDistinct confirms the duplicate-name path
// returns StatusProfileExists (distinct from StatusBadInput) so
// bindings can map the two paths to different language-side
// exceptions.
func TestTripleRegisterSentinelDistinct(t *testing.T) {
	name := "capitest-triple-sentinel-v1"
	if st := TripleRegister(name, tripleRegisterJSONFull()); st != StatusOK {
		t.Fatalf("TripleRegister initial: %v (%s)", st, LastError())
	}
	st := TripleRegister(name, tripleRegisterJSONFull())
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

// TestTripleLookupCapi covers TripleLookup: a shipped name and a
// registered name come back as the profile JSON (decodable through
// the codec, name populated), a short buffer reports the required
// size with StatusBufferTooSmall, and an unknown name is
// StatusUnknownProfile.
func TestTripleLookupCapi(t *testing.T) {
	buf := make([]byte, 4096)
	n, st := TripleLookup(triple.ProfileSingleMsgTripleMACV1, buf)
	if st != StatusOK {
		t.Fatalf("TripleLookup shipped: %v (%s)", st, LastError())
	}
	var prof triple.Profile
	if err := json.Unmarshal(buf[:n], &prof); err != nil {
		t.Fatalf("TripleLookup output does not decode: %v", err)
	}
	if prof.Name != triple.ProfileSingleMsgTripleMACV1 || prof.Mode != "singlemsg-mac" || prof.Width != 512 {
		t.Fatalf("TripleLookup shipped: decoded %+v", prof)
	}

	// Short buffer → StatusBufferTooSmall with the required size.
	short, st := TripleLookup(triple.ProfileSingleMsgTripleMACV1, buf[:8])
	if st != StatusBufferTooSmall || short != n {
		t.Fatalf("TripleLookup short buffer: (%d, %v), want (%d, StatusBufferTooSmall)", short, st, n)
	}

	// Unknown name → StatusUnknownProfile.
	if _, st := TripleLookup("no-such-profile-xyz", buf); st != StatusUnknownProfile {
		t.Fatalf("TripleLookup unknown: %v, want StatusUnknownProfile", st)
	}

	// A registered custom profile round-trips through Lookup.
	const name = "capitest-triple-lookup-v1"
	if st := TripleRegister(name, tripleRegisterJSONFull()); st != StatusOK {
		t.Fatalf("TripleRegister: %v (%s)", st, LastError())
	}
	n, st = TripleLookup(name, buf)
	if st != StatusOK {
		t.Fatalf("TripleLookup registered: %v (%s)", st, LastError())
	}
	if err := json.Unmarshal(buf[:n], &prof); err != nil {
		t.Fatalf("TripleLookup registered output does not decode: %v", err)
	}
	if prof.Name != name || prof.InnerHash != "areion512" || len(prof.ParallaxPalette) != 3 {
		t.Fatalf("TripleLookup registered: decoded %+v", prof)
	}
}

// TestTripleProfilesCapi covers TripleProfiles: the output is a sorted
// JSON array of strings that contains every shipped name plus names
// registered through TripleRegister, and a short buffer reports the
// required size with StatusBufferTooSmall.
func TestTripleProfilesCapi(t *testing.T) {
	const name = "capitest-triple-profiles-v1"
	if st := TripleRegister(name, tripleRegisterJSONFull()); st != StatusOK && st != StatusProfileExists {
		t.Fatalf("TripleRegister: %v (%s)", st, LastError())
	}

	buf := make([]byte, 1<<16)
	n, st := TripleProfiles(buf)
	if st != StatusOK {
		t.Fatalf("TripleProfiles: %v (%s)", st, LastError())
	}
	var names []string
	if err := json.Unmarshal(buf[:n], &names); err != nil {
		t.Fatalf("TripleProfiles output does not decode: %v", err)
	}
	want := triple.Profiles()
	if len(names) != len(want) {
		t.Fatalf("TripleProfiles: %d names, want %d", len(names), len(want))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("TripleProfiles[%d] = %q, want %q", i, names[i], want[i])
		}
	}
	found := false
	for _, s := range names {
		if s == name {
			found = true
		}
	}
	if !found {
		t.Fatalf("TripleProfiles output lacks registered name %q", name)
	}

	short, st := TripleProfiles(buf[:4])
	if st != StatusBufferTooSmall || short != n {
		t.Fatalf("TripleProfiles short buffer: (%d, %v), want (%d, StatusBufferTooSmall)", short, st, n)
	}
}
