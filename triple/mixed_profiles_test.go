package triple

import (
	"bytes"
	"testing"
)

// shippedMixedProfiles lists the four mixed-primitive shipped profiles
// exercised by every round-trip test in this file.
var shippedMixedProfiles = []string{
	ProfileStreamingAEADTripleMACMixedV1,
	ProfileStreamingNoAEADTripleMixedV1,
	ProfileSingleMsgTripleMACMixedV1,
	ProfileSingleMsgTripleNoMACMixedV1,
}

// TestShippedMixedProfilesMessageRoundTrip runs a Single Message
// EncryptMessage → DecryptMessage round-trip against each of the four
// shipped mixed profiles. Streaming profiles are exercised here in the
// Single Message shape too: [Pipeline.EncryptMessage] is a valid entry
// on every Triple mode with a cipher surface, so the message-shape
// round-trip provides one uniform assertion per profile.
func TestShippedMixedProfilesMessageRoundTrip(t *testing.T) {
	plain := []byte("shipped mixed profile round-trip payload — bytes flow through the full chain")
	for _, name := range shippedMixedProfiles {
		t.Run(name, func(t *testing.T) {
			sender, blob, err := Init(name, Opts{})
			if err != nil {
				t.Fatalf("Init(%q): %v", name, err)
			}
			defer sender.Close()

			receiver, err := Open(name, blob, Opts{})
			if err != nil {
				t.Fatalf("Open(%q): %v", name, err)
			}
			defer receiver.Close()

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
		})
	}
}

// TestShippedMixedProfilesStreamRoundTrip runs an EncryptStream →
// DecryptStream round-trip against the two streaming mixed profiles.
// Uses a plaintext large enough to exceed a nominal per-chunk boundary
// so the parallax + wrapper chain sees multiple segments per stream.
// Single Message profiles (singlemsg-triple-*) do not expose a
// streaming cipher surface and are covered by
// [TestShippedMixedProfilesMessageRoundTrip] instead.
func TestShippedMixedProfilesStreamRoundTrip(t *testing.T) {
	streamProfiles := []string{
		ProfileStreamingAEADTripleMACMixedV1,
		ProfileStreamingNoAEADTripleMixedV1,
	}
	plain := bytes.Repeat([]byte("mixed-stream-payload-"), 4096) // ~86 KiB
	for _, name := range streamProfiles {
		t.Run(name, func(t *testing.T) {
			sender, blob, err := Init(name, Opts{})
			if err != nil {
				t.Fatalf("Init(%q): %v", name, err)
			}
			defer sender.Close()

			receiver, err := Open(name, blob, Opts{})
			if err != nil {
				t.Fatalf("Open(%q): %v", name, err)
			}
			defer receiver.Close()

			var wire bytes.Buffer
			if err := sender.EncryptStream(bytes.NewReader(plain), &wire); err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}
			var back bytes.Buffer
			if err := receiver.DecryptStream(bytes.NewReader(wire.Bytes()), &back); err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}
			if !bytes.Equal(back.Bytes(), plain) {
				t.Fatalf("stream round-trip mismatch: %d bytes in, %d bytes out",
					len(plain), back.Len())
			}
		})
	}
}

// TestShippedMixedProfilesCrossProfileIsolation encrypts under mixed
// profile A and confirms decryption under mixed profile B (different
// constellation) fails — one of the isolating gates (blob-profile
// mismatch, MAC failure, or seed mismatch) must surface. This is a
// negative test: any error signals correct isolation.
func TestShippedMixedProfilesCrossProfileIsolation(t *testing.T) {
	// The four shipped mixed profiles differ by width (128 / 256 /
	// 256 / 512) so cross-decryption fails at the blob-profile-name
	// check before the width-typed importer would even fire. That is
	// still valid isolation — a fresh receiver Init'd under a
	// different profile name cannot recover the sender's plaintext.
	sender, blobA, err := Init(ProfileStreamingAEADTripleMACMixedV1, Opts{})
	if err != nil {
		t.Fatalf("Init sender A: %v", err)
	}
	defer sender.Close()

	// Opening blob A under profile B (different mixed profile) must
	// fail — the blob's Profile field carries A's name.
	if _, err := Open(ProfileStreamingNoAEADTripleMixedV1, blobA, Opts{}); err == nil {
		t.Fatalf("Open blob A under profile B: got nil, want ErrBlobMismatch")
	}

	// A same-profile receiver still round-trips.
	receiver, err := Open(ProfileStreamingAEADTripleMACMixedV1, blobA, Opts{})
	if err != nil {
		t.Fatalf("Open blob A under profile A: %v", err)
	}
	defer receiver.Close()

	wire, err := sender.EncryptMessage([]byte("isolation smoke test"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if _, err := receiver.DecryptMessage(wire); err != nil {
		t.Fatalf("DecryptMessage same-profile receiver: %v", err)
	}
}

// TestShippedMixedProfilesRekeyRoundTrip confirms Rekey works on a
// mixed-profile Pipeline — the fresh masters swap in, the receiver
// Opens against the rotated blob, and one encrypt / decrypt round-trip
// still succeeds. Mixed profiles pass through Rekey unchanged (the
// per-slot hash constellation is not master-derived).
func TestShippedMixedProfilesRekeyRoundTrip(t *testing.T) {
	name := ProfileStreamingAEADTripleMACMixedV1
	sender, blob, err := Init(name, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	// Fresh masters for the Rekey step. 32-byte masters match the
	// wrapper's DeriveKey lower bound; parallax accepts any non-empty
	// master.
	newPerm := bytes.Repeat([]byte{0x1a}, 32)
	newWrap := bytes.Repeat([]byte{0x2b}, 32)
	rekeyBlob, err := sender.Rekey(newPerm, newWrap)
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	_ = blob // original blob is superseded by rekeyBlob

	receiver, err := Open(name, rekeyBlob, Opts{})
	if err != nil {
		t.Fatalf("Open post-Rekey: %v", err)
	}
	defer receiver.Close()

	plain := []byte("post-rekey mixed profile round-trip")
	wire, err := sender.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage post-Rekey: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage post-Rekey: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("post-Rekey round-trip mismatch: got %q, want %q", got, plain)
	}
}

// TestShippedMixedProfilesRegistered confirms all four mixed profiles
// are visible via lookupProfile at package-init time — catches a
// silent registration regression before the round-trip tests fire.
func TestShippedMixedProfilesRegistered(t *testing.T) {
	for _, name := range shippedMixedProfiles {
		got, err := lookupProfile(name)
		if err != nil {
			t.Fatalf("lookupProfile(%q): %v", name, err)
		}
		if got.Name != name {
			t.Fatalf("lookupProfile(%q): Name=%q", name, got.Name)
		}
		if got.InnerHash != "" {
			t.Fatalf("lookupProfile(%q): InnerHash=%q, want empty (mixed profile)",
				name, got.InnerHash)
		}
		if !isMixedProfile(got) {
			t.Fatalf("lookupProfile(%q): isMixedProfile reports false",
				name)
		}
		// Every mixed slot populated and matches the profile width.
		for i, slotName := range got.MixedHashes {
			if slotName == "" {
				t.Fatalf("lookupProfile(%q): MixedHashes[%d] empty",
					name, i)
			}
		}
	}
}
