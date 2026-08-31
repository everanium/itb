package triple

import (
	"bytes"
	"strings"
	"testing"
)

// TestOptsMixedHashesOverrideSingleToMixed exercises the per-call
// override path introduced with [Opts.MixedHashes]: a shipped
// single-primitive profile is switched to a mixed-primitive
// constellation for a specific Pipeline instance via Opts, without
// registering a new profile.
//
// Round-trip discipline: the same override must be passed to Open as
// to Init so both sides reconstruct the same effective shape. This
// mirrors how the shipping mixed profiles work — sender and receiver
// agree on the constellation, only here the agreement is per-call
// rather than baked into the profile name.
func TestOptsMixedHashesOverrideSingleToMixed(t *testing.T) {
	// ProfileStreamingAEADTripleMACV1 is single-primitive, width 512
	// (InnerHash = "areion512"). Override to an 8-slot width-512
	// constellation alternating the two shipped width-512 primitives.
	override := [8]string{
		"areion512", "blake2b512", "areion512", "blake2b512",
		"areion512", "blake2b512", "areion512", "blake2b512",
	}
	opts := Opts{MixedHashes: override}

	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, opts)
	if err != nil {
		t.Fatalf("Init(single-primitive profile, Opts{MixedHashes}): %v", err)
	}
	defer sender.Close()

	receiver, err := Open(ProfileStreamingAEADTripleMACV1, blob, opts)
	if err != nil {
		t.Fatalf("Open(single-primitive profile, Opts{MixedHashes}): %v", err)
	}
	defer receiver.Close()

	plain := []byte("per-call MixedHashes override round-trip payload")
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

// TestOptsMixedHashesOverrideMixedToDifferentMixed swaps one mixed
// constellation for another via Opts against a shipped mixed profile
// as the base — override wins over the profile's own MixedHashes.
func TestOptsMixedHashesOverrideMixedToDifferentMixed(t *testing.T) {
	// Shipped mixed profile is width 256 (ProfileStreamingAEADTripleMACMixedV1
	// spreads across every shipped width-256 primitive). Override to a
	// different width-256 constellation so both sender and receiver
	// see the same effective shape but different from the profile
	// default.
	override := [8]string{
		"blake3", "blake2b256", "blake2s", "chacha20",
		"areion256", "blake3", "blake2b256", "blake2s",
	}
	opts := Opts{MixedHashes: override}

	sender, blob, err := Init(ProfileStreamingAEADTripleMACMixedV1, opts)
	if err != nil {
		t.Fatalf("Init(mixed profile, Opts{MixedHashes}): %v", err)
	}
	defer sender.Close()

	receiver, err := Open(ProfileStreamingAEADTripleMACMixedV1, blob, opts)
	if err != nil {
		t.Fatalf("Open(mixed profile, Opts{MixedHashes}): %v", err)
	}
	defer receiver.Close()

	plain := []byte("mixed→mixed override round-trip payload")
	wire, err := sender.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip plaintext mismatch")
	}
}

// TestOptsMixedHashesRejectsWidthMismatch confirms fail-fast
// validation surfaces at Init: an override slot whose primitive width
// differs from the profile's effective width is rejected with a clear
// error naming the offending slot. Semantics match the
// RegisterProfile-side validation, which runs in allocEightSeedsMixed
// on the resolved constellation regardless of whether the override
// came from Opts or from the profile default.
func TestOptsMixedHashesRejectsWidthMismatch(t *testing.T) {
	// Profile is width 512; override slot 3 with a width-256 primitive.
	override := [8]string{
		"areion512", "blake2b512", "areion512", "blake3", // slot 3 is width 256
		"areion512", "blake2b512", "areion512", "blake2b512",
	}
	opts := Opts{MixedHashes: override}

	_, _, err := Init(ProfileStreamingAEADTripleMACV1, opts)
	if err == nil {
		t.Fatalf("Init succeeded on Opts.MixedHashes with width mismatch; want error")
	}
	if !strings.Contains(err.Error(), "mixedHashes[3]") ||
		!strings.Contains(err.Error(), "width") {
		t.Fatalf("Init error does not name mixedHashes[3] + width: %v", err)
	}
}

// TestOptsMixedHashesRejectsUnknownPrimitive confirms an override slot
// whose primitive name does not resolve via [hashes.Find] fails fast
// with an error naming the offending slot and primitive.
func TestOptsMixedHashesRejectsUnknownPrimitive(t *testing.T) {
	override := [8]string{
		"areion512", "blake2b512", "areion512", "blake2b512",
		"areion512", "blake2b512", "areion512", "no-such-hash",
	}
	opts := Opts{MixedHashes: override}

	_, _, err := Init(ProfileStreamingAEADTripleMACV1, opts)
	if err == nil {
		t.Fatalf("Init succeeded on Opts.MixedHashes with unknown primitive; want error")
	}
	if !strings.Contains(err.Error(), "mixedHashes[7]") {
		t.Fatalf("Init error does not name mixedHashes[7]: %v", err)
	}
}

// TestOptsMixedHashesRejectsPartialFill confirms a half-populated
// Opts.MixedHashes (some slots set, others empty) is rejected. The
// allocation helper enforces every slot non-empty; partial fills are
// refused rather than defaulted per slot.
func TestOptsMixedHashesRejectsPartialFill(t *testing.T) {
	override := [8]string{
		"areion512", "", "areion512", "", // half-populated
		"areion512", "", "areion512", "",
	}
	opts := Opts{MixedHashes: override}

	_, _, err := Init(ProfileStreamingAEADTripleMACV1, opts)
	if err == nil {
		t.Fatalf("Init succeeded on partial Opts.MixedHashes; want error")
	}
	if !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("Init error does not name empty slot: %v", err)
	}
}

// TestOptsMixedHashesEmptyDefersToProfile confirms zero-value
// Opts.MixedHashes leaves the profile default intact — the mixed
// shipped profile continues to work identically to when no Opts is
// supplied.
func TestOptsMixedHashesEmptyDefersToProfile(t *testing.T) {
	opts := Opts{} // MixedHashes is [8]string{} — all slots empty

	sender, blob, err := Init(ProfileStreamingAEADTripleMACMixedV1, opts)
	if err != nil {
		t.Fatalf("Init(mixed profile, Opts{}): %v", err)
	}
	defer sender.Close()

	receiver, err := Open(ProfileStreamingAEADTripleMACMixedV1, blob, opts)
	if err != nil {
		t.Fatalf("Open(mixed profile, Opts{}): %v", err)
	}
	defer receiver.Close()

	plain := []byte("zero-value Opts.MixedHashes deferral round-trip")
	wire, err := sender.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip plaintext mismatch")
	}
}

// TestOptsMixedHashesWinsOverInnerHash confirms the resolver's
// mutual-exclusion rule when both Opts.InnerHash and Opts.MixedHashes
// are set: MixedHashes wins, InnerHash is cleared, mixed dispatch
// takes over. Mirrors [Profile]-level mutual exclusion.
func TestOptsMixedHashesWinsOverInnerHash(t *testing.T) {
	override := [8]string{
		"areion512", "blake2b512", "areion512", "blake2b512",
		"areion512", "blake2b512", "areion512", "blake2b512",
	}
	// InnerHash set alongside MixedHashes — must be silently ignored.
	opts := Opts{
		InnerHash:   "blake2b512",
		MixedHashes: override,
	}

	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, opts)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	receiver, err := Open(ProfileStreamingAEADTripleMACV1, blob, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer receiver.Close()

	plain := []byte("mutual-exclusion round-trip: MixedHashes wins over InnerHash")
	wire, err := sender.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch")
	}
}
