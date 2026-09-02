package triple

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/macs"
)

// registerStub16MAC installs a deterministic 16-byte-tag custom MAC
// (HMAC-SHA256 truncated to 16 bytes) under the name "stub16mac".
// Registration is process-global and append-only, so a re-run within
// the same process tolerates ErrMACExists.
func registerStub16MAC(t *testing.T) {
	t.Helper()
	err := macs.Register(macs.Spec{
		Name:        "stub16mac",
		KeySize:     32,
		TagSize:     16,
		MinKeyBytes: 16,
		MakeMAC: func(key []byte) (itb.MACFunc, error) {
			k := append([]byte(nil), key...)
			return func(data []byte) []byte {
				h := hmac.New(sha256.New, k)
				h.Write(data)
				return h.Sum(nil)[:16]
			}, nil
		},
	})
	if err != nil && !errors.Is(err, macs.ErrMACExists) {
		t.Fatalf("macs.Register(stub16mac): %v", err)
	}
}

// TestTagStubSizeProfileDriven verifies that a registered No MAC
// profile carrying Profile.TagStubSize threads the value into the
// Pipeline's itb.Config on both construction paths — Init from the
// resolved profile shape and Open from the same resolution on the
// blob-reopen side (the inner blob's Config snapshot carries no stub
// field, so the reopen re-derives it from the profile / Opts merge).
func TestTagStubSizeProfileDriven(t *testing.T) {
	name := "userns-tagstub-profile-v1"
	prof := baseValidProfile()
	prof.Mode = modeSingleMsgNoMAC
	prof.MacName = ""
	prof.TagStubSize = 16
	if err := RegisterProfile(name, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile: %v", err)
	}

	sender, blob, err := Init(name, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", name, err)
	}
	defer sender.Close()
	if got := sender.cfg.TagStubSize; got != 16 {
		t.Fatalf("Init profile-driven: TagStubSize = %d, want 16", got)
	}

	receiver, err := Open(name, blob, Opts{})
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer receiver.Close()
	if got := receiver.cfg.TagStubSize; got != 16 {
		t.Fatalf("Open profile-driven: TagStubSize = %d, want 16", got)
	}

	// The reserved stub is pure CSPRNG on the No MAC path — the pair
	// stays fully functional end-to-end.
	plain := []byte("profile-driven 16-byte stub round trip")
	wire, err := sender.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip plaintext mismatch: got %q, want %q", got, plain)
	}
}

// TestTagStubSizeOptsOverride verifies the Opts.TagStubSize override
// wins over the registered profile's Profile.TagStubSize on both the
// Init and Open construction paths.
func TestTagStubSizeOptsOverride(t *testing.T) {
	name := "userns-tagstub-optsoverride-v1"
	prof := baseValidProfile()
	prof.Mode = modeSingleMsgNoMAC
	prof.MacName = ""
	prof.TagStubSize = 16
	if err := RegisterProfile(name, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile: %v", err)
	}

	sender, blob, err := Init(name, Opts{TagStubSize: 24})
	if err != nil {
		t.Fatalf("Init(%q): %v", name, err)
	}
	defer sender.Close()
	if got := sender.cfg.TagStubSize; got != 24 {
		t.Fatalf("Init Opts override: TagStubSize = %d, want 24", got)
	}

	receiver, err := Open(name, blob, Opts{TagStubSize: 24})
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer receiver.Close()
	if got := receiver.cfg.TagStubSize; got != 24 {
		t.Fatalf("Open Opts override: TagStubSize = %d, want 24", got)
	}
}

// TestTagStubSizePrecedence pins the resolution chain
// Opts > Profile > MacName auto-probe > default 32 across its
// observable levels:
//
//   - a MAC-carrying profile with an explicit Profile.TagStubSize
//     resolves to the profile value ahead of the MAC probe;
//   - the same profile shape without the field falls through to the
//     MAC probe (48 for the stub48mac fixture);
//   - a No MAC profile with neither Opts nor Profile field leaves the
//     Config field at zero — the envelope helper's zero-value
//     fallback then reserves for a 32-byte tag.
//
// The Opts-over-Profile level is pinned by
// [TestTagStubSizeOptsOverride]; the Config-explicit level above all
// of these is a Low-Level surface pinned by the itb-root
// wire_shape_parity_test.go resolution test.
func TestTagStubSizePrecedence(t *testing.T) {
	registerStub48MAC(t)

	// Profile field ahead of the MAC auto-probe.
	nameProfWins := "userns-tagstub-prec-profile-v1"
	prof := baseValidProfile()
	prof.Mode = modeSingleMsgMAC
	prof.MacName = "stub48mac"
	prof.TagStubSize = 20
	if err := RegisterProfile(nameProfWins, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameProfWins, err)
	}
	pProf, _, err := Init(nameProfWins, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameProfWins, err)
	}
	defer pProf.Close()
	if got := pProf.cfg.TagStubSize; got != 20 {
		t.Fatalf("Profile-over-probe: TagStubSize = %d, want 20", got)
	}

	// MAC auto-probe when the profile leaves the field at zero.
	nameProbe := "userns-tagstub-prec-probe-v1"
	prof = baseValidProfile()
	prof.Mode = modeSingleMsgMAC
	prof.MacName = "stub48mac"
	if err := RegisterProfile(nameProbe, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameProbe, err)
	}
	pProbe, _, err := Init(nameProbe, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameProbe, err)
	}
	defer pProbe.Close()
	if got := pProbe.cfg.TagStubSize; got != 48 {
		t.Fatalf("MacName auto-probe: TagStubSize = %d, want 48", got)
	}

	// Zero everywhere on a No MAC profile — the Config field stays 0
	// and the envelope helper's fallback reserves for a 32-byte tag.
	nameDefault := "userns-tagstub-prec-default-v1"
	prof = baseValidProfile()
	prof.Mode = modeSingleMsgNoMAC
	prof.MacName = ""
	if err := RegisterProfile(nameDefault, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameDefault, err)
	}
	pDefault, _, err := Init(nameDefault, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameDefault, err)
	}
	defer pDefault.Close()
	if got := pDefault.cfg.TagStubSize; got != 0 {
		t.Fatalf("default level: TagStubSize = %d, want 0 (zero-value fallback resolves to 32)", got)
	}
}

// TestTagStubSizeWireShapeParityPipelines verifies the wire-shape
// target end-to-end at the triple.Pipeline layer: a No MAC profile
// pinned to TagStubSize 16 produces a Single Message wire whose byte
// count equals the wire of a paired MAC-carrying profile whose MAC
// emits 16-byte tags, for the same plaintext under the same profile
// shape (same width, primitive, key bits, parallax palette, and
// Outer cipher). Envelope sizing is deterministic in the plaintext
// and the reservation arithmetic, so equal reservations
// (tagSize + 1 on both sides) yield byte-count-equal wires even
// across independently drawn sessions. Both wires are round-tripped
// so the parity claim covers functioning envelopes, not just
// matching lengths.
func TestTagStubSizeWireShapeParityPipelines(t *testing.T) {
	registerStub16MAC(t)

	nameMAC := "userns-tagstub-parity-mac-v1"
	profMAC := baseValidProfile()
	profMAC.Mode = modeSingleMsgMAC
	profMAC.MacName = "stub16mac"
	if err := RegisterProfile(nameMAC, profMAC); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameMAC, err)
	}

	nameNoMAC := "userns-tagstub-parity-nomac-v1"
	profNoMAC := baseValidProfile()
	profNoMAC.Mode = modeSingleMsgNoMAC
	profNoMAC.MacName = ""
	profNoMAC.TagStubSize = 16
	if err := RegisterProfile(nameNoMAC, profNoMAC); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameNoMAC, err)
	}

	plain := make([]byte, 4096)
	for i := range plain {
		plain[i] = byte(i%251 + 1) // identical bytes on both paths — COBS lengths match by construction
	}

	sMAC, bMAC, err := Init(nameMAC, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameMAC, err)
	}
	defer sMAC.Close()
	sNoMAC, bNoMAC, err := Init(nameNoMAC, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameNoMAC, err)
	}
	defer sNoMAC.Close()

	wireMAC, err := sMAC.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage (MAC): %v", err)
	}
	wireNoMAC, err := sNoMAC.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage (No MAC): %v", err)
	}
	if len(wireMAC) != len(wireNoMAC) {
		t.Fatalf("wire-shape drift: MAC=%d No MAC=%d", len(wireMAC), len(wireNoMAC))
	}

	rMAC, err := Open(nameMAC, bMAC, Opts{})
	if err != nil {
		t.Fatalf("Open(%q): %v", nameMAC, err)
	}
	defer rMAC.Close()
	gotMAC, err := rMAC.DecryptMessage(wireMAC)
	if err != nil {
		t.Fatalf("DecryptMessage (MAC): %v", err)
	}
	if !bytes.Equal(gotMAC, plain) {
		t.Fatal("MAC round-trip plaintext mismatch")
	}

	rNoMAC, err := Open(nameNoMAC, bNoMAC, Opts{})
	if err != nil {
		t.Fatalf("Open(%q): %v", nameNoMAC, err)
	}
	defer rNoMAC.Close()
	gotNoMAC, err := rNoMAC.DecryptMessage(wireNoMAC)
	if err != nil {
		t.Fatalf("DecryptMessage (No MAC): %v", err)
	}
	if !bytes.Equal(gotNoMAC, plain) {
		t.Fatal("No MAC round-trip plaintext mismatch")
	}
}

// TestTagStubSizeRangeValidation pins the accepted TagStubSize value
// set — 0 or [16, 64] inclusive — on every validation surface:
// RegisterProfile rejects out-of-range Profile.TagStubSize fail-fast,
// and Init / Open reject out-of-range Opts.TagStubSize before any
// session material is drawn. The floor matches the macs.Register
// TagSize >= 16 contract; the ceiling covers the longest realistic
// MAC tag (64 bytes).
func TestTagStubSizeRangeValidation(t *testing.T) {
	newNoMACProfile := func(stub int) Profile {
		prof := baseValidProfile()
		prof.Mode = modeSingleMsgNoMAC
		prof.MacName = ""
		prof.TagStubSize = stub
		return prof
	}

	// RegisterProfile-side rejections.
	for _, stub := range []int{-1, 1, 15, 65, 128} {
		name := fmt.Sprintf("userns-tagstub-range-bad%d-v1", stub&0xfff)
		if err := RegisterProfile(name, newNoMACProfile(stub)); err == nil {
			t.Errorf("RegisterProfile accepted TagStubSize=%d, want rejection", stub)
		}
	}

	// RegisterProfile-side acceptances (0 = defer; boundary values in
	// range). Each registration lands under a distinct name.
	for _, stub := range []int{0, 16, 32, 64} {
		name := fmt.Sprintf("userns-tagstub-range-ok%d-v1", stub)
		if err := RegisterProfile(name, newNoMACProfile(stub)); err != nil && !errors.Is(err, ErrProfileExists) {
			t.Errorf("RegisterProfile rejected TagStubSize=%d: %v", stub, err)
		}
	}

	// Opts-side rejections on Init and Open.
	nameOK := "userns-tagstub-range-ok0-v1"
	_, blob, err := Init(nameOK, Opts{})
	if err != nil {
		t.Fatalf("Init baseline: %v", err)
	}
	for _, stub := range []int{-1, 15, 65} {
		if _, _, err := Init(nameOK, Opts{TagStubSize: stub}); err == nil {
			t.Errorf("Init accepted Opts.TagStubSize=%d, want rejection", stub)
		}
		if _, err := Open(nameOK, blob, Opts{TagStubSize: stub}); err == nil {
			t.Errorf("Open accepted Opts.TagStubSize=%d, want rejection", stub)
		}
	}

	// Opts-side boundary acceptances.
	for _, stub := range []int{16, 64} {
		p, _, err := Init(nameOK, Opts{TagStubSize: stub})
		if err != nil {
			t.Errorf("Init rejected Opts.TagStubSize=%d: %v", stub, err)
			continue
		}
		if got := p.cfg.TagStubSize; got != stub {
			t.Errorf("Init Opts.TagStubSize=%d: cfg.TagStubSize = %d", stub, got)
		}
		p.Close()
	}
}
