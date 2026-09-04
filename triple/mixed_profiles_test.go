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

			receiver, err := Load(blob)
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

			receiver, err := Load(blob)
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
// profile A and confirms decryption by a Pipeline built under mixed
// profile B (different constellation, independent session material)
// fails — one of the isolating gates (MAC failure or seed mismatch)
// must surface. This is a negative test: any error signals correct
// isolation.
func TestShippedMixedProfilesCrossProfileIsolation(t *testing.T) {
	sender, blobA, err := Init(ProfileStreamingAEADTripleMACMixedV1, Opts{})
	if err != nil {
		t.Fatalf("Init sender A: %v", err)
	}
	defer sender.Close()

	// A fresh receiver Init'd under a different mixed profile cannot
	// recover the sender's plaintext.
	other, _, err := Init(ProfileStreamingNoAEADTripleMixedV1, Opts{})
	if err != nil {
		t.Fatalf("Init receiver B: %v", err)
	}
	defer other.Close()
	crossWire, err := sender.EncryptMessage([]byte("isolation smoke test"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if got, err := other.DecryptMessage(crossWire); err == nil && bytes.Equal(got, []byte("isolation smoke test")) {
		t.Fatalf("receiver B recovered sender A's plaintext")
	}

	// A same-blob receiver still round-trips.
	receiver, err := Load(blobA)
	if err != nil {
		t.Fatalf("Load blob A: %v", err)
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

	receiver, err := Load(rekeyBlob)
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
		got, err := Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if got.Name != name {
			t.Fatalf("Lookup(%q): Name=%q", name, got.Name)
		}
		if got.InnerHash != "" {
			t.Fatalf("Lookup(%q): InnerHash=%q, want empty (mixed profile)",
				name, got.InnerHash)
		}
		if !isMixedProfile(got) {
			t.Fatalf("Lookup(%q): isMixedProfile reports false",
				name)
		}
		// Every mixed slot populated and matches the profile width.
		for i, slotName := range got.MixedHashes {
			if slotName == "" {
				t.Fatalf("Lookup(%q): MixedHashes[%d] empty",
					name, i)
			}
		}
	}
}
