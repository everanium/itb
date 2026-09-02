package triple

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/macs"
)

// registerStub48MAC installs a deterministic 48-byte-tag custom MAC
// (HMAC-SHA512 truncated to 48 bytes) under the name "stub48mac".
// Registration is process-global and append-only, so a re-run within
// the same process tolerates ErrMACExists.
func registerStub48MAC(t *testing.T) {
	t.Helper()
	err := macs.Register(macs.Spec{
		Name:        "stub48mac",
		KeySize:     32,
		TagSize:     48,
		MinKeyBytes: 16,
		MakeMAC: func(key []byte) (itb.MACFunc, error) {
			k := append([]byte(nil), key...)
			return func(data []byte) []byte {
				h := hmac.New(sha512.New, k)
				h.Write(data)
				return h.Sum(nil)[:48]
			}, nil
		},
	})
	if err != nil && !errors.Is(err, macs.ErrMACExists) {
		t.Fatalf("macs.Register(stub48mac): %v", err)
	}
}

// TestTagStubSizeAutoPopulation verifies that a MAC-carrying
// Pipeline auto-populates itb.Config.TagStubSize from its
// profile's MAC tag length on both construction paths — Init probes
// the freshly built MAC closure, Open mirrors the probe from the
// blob's resolved MAC — so the No MAC stub reservation a Pipeline's
// Config would drive always matches the profile's authenticated
// envelope shape, for custom tag sizes beyond the shipped 32.
func TestTagStubSizeAutoPopulation(t *testing.T) {
	registerStub48MAC(t)

	name := "userns-stub48-autopop-v1"
	prof := baseValidProfile()
	prof.Mode = modeSingleMsgMAC
	prof.MacName = "stub48mac"
	if err := RegisterProfile(name, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile: %v", err)
	}

	sender, blob, err := Init(name, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", name, err)
	}
	defer sender.Close()
	if got := sender.cfg.TagStubSize; got != 48 {
		t.Fatalf("Init auto-population: TagStubSize = %d, want 48", got)
	}

	receiver, err := Open(name, blob, Opts{})
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer receiver.Close()
	if got := receiver.cfg.TagStubSize; got != 48 {
		t.Fatalf("Open auto-population: TagStubSize = %d, want 48", got)
	}

	// End-to-end round trip under the 48-byte-tag MAC confirms the
	// populated Config keeps the authenticated pipeline functional.
	plain := []byte("48-byte-tag auto-population round trip")
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

// TestTagStubSizeShippedDefault verifies the auto-population
// lands on 32 for a shipped-MAC profile (every shipped MAC emits
// 32-byte tags — the same value the zero-field fallback resolves to,
// so wire bytes are unchanged for shipped pipelines), and stays at
// the zero value for a No MAC profile, which has no MAC to probe.
func TestTagStubSizeShippedDefault(t *testing.T) {
	nameMAC := "userns-stub-shipped-mac-v1"
	profMAC := baseValidProfile()
	profMAC.Mode = modeSingleMsgMAC
	if err := RegisterProfile(nameMAC, profMAC); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameMAC, err)
	}
	pMAC, _, err := Init(nameMAC, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameMAC, err)
	}
	defer pMAC.Close()
	if got := pMAC.cfg.TagStubSize; got != 32 {
		t.Fatalf("shipped-MAC profile: TagStubSize = %d, want 32", got)
	}

	nameNoMAC := "userns-stub-nomac-v1"
	profNoMAC := baseValidProfile()
	profNoMAC.Mode = modeSingleMsgNoMAC
	profNoMAC.MacName = ""
	if err := RegisterProfile(nameNoMAC, profNoMAC); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile(%q): %v", nameNoMAC, err)
	}
	pNoMAC, _, err := Init(nameNoMAC, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", nameNoMAC, err)
	}
	defer pNoMAC.Close()
	if got := pNoMAC.cfg.TagStubSize; got != 0 {
		t.Fatalf("No MAC profile: TagStubSize = %d, want 0 (zero-value fallback resolves to 32)", got)
	}
}
