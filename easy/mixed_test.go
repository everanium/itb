package easy_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/everanium/itb/easy"
)

// TestMixedTripleRoundtrip verifies Triple Ouroboros mixed mode
// round-trips plain Encrypt / Decrypt with distinct primitives
// wired across the 8 seed slots (noise + lockSeed + 3 data +
// 3 start). The resulting encryptor's Primitive field carries the
// [MixedPrimitive] literal, IsMixed reports true, and PrimitiveAt
// returns each slot's chosen primitive name.
func TestMixedTripleRoundtrip(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "areion256",
		PrimitiveL:  "blake2b256",
		PrimitiveD1: "blake3",
		PrimitiveD2: "blake2s",
		PrimitiveD3: "chacha20",
		PrimitiveS1: "blake2b256",
		PrimitiveS2: "blake3",
		PrimitiveS3: "blake2s",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	if !enc.IsMixed() {
		t.Errorf("IsMixed() = false, want true")
	}
	wants := []string{
		"areion256", "blake2b256",
		"blake3", "blake2s", "chacha20",
		"blake2b256", "blake3", "blake2s",
	}
	for i, want := range wants {
		if got := enc.PrimitiveAt(i); got != want {
			t.Errorf("PrimitiveAt(%d) = %q, want %q", i, got, want)
		}
	}

	plaintext := []byte("mixed Triple round-trip payload")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

// TestMixedTripleAuthRoundtrip verifies authenticated Encrypt /
// Decrypt on a Triple mixed encryptor with the lockSeed slot
// distinct from every other primitive.
func TestMixedTripleAuthRoundtrip(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveL:  "areion256",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake2s",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake3",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	if got := enc.PrimitiveAt(1); got != "areion256" {
		t.Errorf("PrimitiveAt(1) = %q, want areion256 (lockSeed slot)", got)
	}
	plaintext := []byte("mixed Triple + auth payload")
	ct, err := enc.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	pt, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

// TestMixedTripleDefaultLockSeed verifies an empty PrimitiveL
// adopts the noiseSeed primitive for the lockSeed slot.
func TestMixedTripleDefaultLockSeed(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveL:  "", // adopt noise primitive
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake2s",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake3",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	if got := enc.PrimitiveAt(1); got != "blake3" {
		t.Errorf("PrimitiveAt(1) = %q, want blake3 (should adopt noiseSeed primitive)", got)
	}
	plaintext := []byte("default lockSeed primitive payload")
	if _, err := enc.EncryptAuth(plaintext); err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
}

// TestMixedTripleStreamRoundtrip verifies streaming encrypt / decrypt
// cycles through the Triple mixed-mode dispatch path.
func TestMixedTripleStreamRoundtrip(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveL:  "areion256",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake2s",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake3",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	plaintext := bytes.Repeat([]byte("mixed Triple stream payload "), 1024)

	var encOut bytes.Buffer
	if err := enc.EncryptStream(plaintext, func(chunk []byte) error {
		encOut.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var decOut bytes.Buffer
	if err := enc.DecryptStream(encOut.Bytes(), func(chunk []byte) error {
		decOut.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(decOut.Bytes(), plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

// TestMixedRejectMixedWidth verifies that mixing primitives across
// native hash widths panics with [ErrEasyMixedWidth] before any
// allocation runs.
func TestMixedRejectMixedWidth(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		err, ok := r.(error)
		if ok && errors.Is(err, easy.ErrEasyMixedWidth) {
			return
		}
		if s, ok := r.(string); ok && contains(s, "mixed-mode primitives must share") {
			return
		}
		t.Errorf("panic %v does not signal ErrEasyMixedWidth", r)
	}()
	_ = easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",    // 256-bit
		PrimitiveD1: "areion512", // 512-bit ← width mismatch
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake3",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake3",
		PrimitiveS3: "blake3",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
}

// TestMixedRejectUnknownPrimitive verifies that an unknown primitive
// name in any slot panics at construction time.
func TestMixedRejectUnknownPrimitive(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "no-such-primitive",
		PrimitiveD1: "blake3",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake3",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake3",
		PrimitiveS3: "blake3",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
}

// TestMixedRejectLockSeedWidthMismatch verifies that a lockSeed
// primitive of a different width panics.
func TestMixedRejectLockSeedWidthMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3", // 256-bit
		PrimitiveD1: "blake3",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake3",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake3",
		PrimitiveS3: "blake3",
		PrimitiveL:  "areion512", // 512-bit ← width mismatch
		KeyBits:     1024,
		MACName:     "kmac256",
	})
}

// TestMixedDefaultsBehaveLikeNonMixed verifies that [New3]
// encryptors return their own primitive name from PrimitiveAt for
// every slot — the parallel-array compat path for code that walks
// PrimitiveAt regardless of construction style.
func TestMixedDefaultsBehaveLikeNonMixed(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	if enc.IsMixed() {
		t.Errorf("IsMixed() on New3() encryptor = true, want false")
	}
	for i := 0; i < 8; i++ {
		if got := enc.PrimitiveAt(i); got != "blake3" {
			t.Errorf("PrimitiveAt(%d) on single-primitive encryptor = %q, want blake3", i, got)
		}
	}
}

// TestMixedTripleExportImport verifies a Triple mixed encryptor
// round-trips through Export → fresh NewMixed3 receiver → Import →
// bit-exact decrypt.
func TestMixedTripleExportImport(t *testing.T) {
	spec := easy.MixedSpec3{
		PrimitiveN:  "areion256",
		PrimitiveL:  "blake3",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake2b256",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake3",
		KeyBits:     1024,
		MACName:     "kmac256",
	}
	sender := easy.NewMixed3(spec)
	defer sender.Close()

	plaintext := []byte("Triple mixed Export/Import roundtrip payload")
	ct, err := sender.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("sender EncryptAuth: %v", err)
	}
	blob := sender.Export()

	receiver := easy.NewMixed3(spec)
	defer receiver.Close()
	if err := receiver.Import(blob); err != nil {
		t.Fatalf("receiver Import: %v", err)
	}

	pt, err := receiver.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("receiver DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch across Export/Import")
	}
}

// contains is a tiny substring predicate used by the panic-message
// matching in TestMixedRejectMixedWidth; keeps the imports minimal
// (no strings package needed elsewhere in this file).
func contains(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
