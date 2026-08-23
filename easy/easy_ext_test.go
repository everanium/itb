package easy_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb/easy"
)

// 4 MB round-trip plaintext size — large enough to exercise the
// streaming chunk emit / parse path on Encrypt / Decrypt and to
// surface integer-overflow / off-by-one bugs that small payloads
// hide. The plaintext is freshly randomised per test so a
// regression in the per-chunk PRF derivation cannot accidentally
// pass via a fixed test vector.
const mixedExtPlaintextSize = 4 * 1024 * 1024

// generateMixedExtPlaintext produces a fresh CSPRNG-filled
// plaintext for the round-trip tests. crypto/rand failure aborts
// the test — the underlying read is part of the build environment,
// not a behaviour the round-trip is testing.
func generateMixedExtPlaintext(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, mixedExtPlaintextSize)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return buf
}

// TestEasyMixedTripleRoundtripExt — Triple-Ouroboros 8-slot mixed
// encryptor: 1 noise + 1 lockSeed + 3 data + 3 start, with four
// 256-bit primitives cycled across the main slots and the lockSeed
// pinned to Areion-SoEM-256. 1024-bit ITB key, KMAC256 MAC bound
// at construction, plain Encrypt3x / Decrypt3x round-trip on a
// 4 MB CSPRNG payload.
func TestEasyMixedTripleRoundtripExt(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake2b256",
		PrimitiveD3: "areion256",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake2b256",
		PrimitiveL:  "areion256",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	plaintext := generateMixedExtPlaintext(t)
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("Triple mixed roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestEasyMixedTripleAuthRoundtripExt — Triple mixed encryptor
// authenticated variant. EncryptAuth / DecryptAuth across the
// 8-slot mixed configuration with the embedded KMAC256 tag verified
// end-to-end.
func TestEasyMixedTripleAuthRoundtripExt(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake2b256",
		PrimitiveD3: "areion256",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake2b256",
		PrimitiveL:  "areion256",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	plaintext := generateMixedExtPlaintext(t)
	ct, err := enc.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	pt, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("Triple mixed auth roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestEasyMixedTripleDefaultLockSeedPrimitive — MixedSpec3.PrimitiveL
// empty adopts the noiseSeed primitive for the lockSeed slot; the
// round-trip must succeed with lockSeed silently keyed by the
// noiseSeed's primitive.
func TestEasyMixedTripleDefaultLockSeedPrimitive(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake2b256",
		PrimitiveD3: "areion256",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake2b256",
		PrimitiveL:  "", // adopt noise primitive
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	if got := enc.PrimitiveAt(1); got != "blake3" {
		t.Errorf("lockSeed slot primitive: got %q, want %q (should adopt noiseSeed primitive when PrimitiveL is empty)",
			got, "blake3")
	}

	plaintext := []byte("default lockSeed primitive round-trip payload")
	ct, err := enc.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	pt, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("default-lockSeed round-trip mismatch")
	}
}
