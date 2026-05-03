package easy_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/everanium/itb/easy"
)

// ─── Single-mode mixed round-trip ────────────────────────────────────

// TestMixedSingleRoundtrip verifies the basic Single Ouroboros
// round-trip with three different 256-bit primitives wired across
// the noise / data / start slots and no dedicated lockSeed. The
// resulting encryptor's Primitive field carries the [MixedPrimitive]
// literal, IsMixed reports true, and PrimitiveAt(slot) returns each
// slot's chosen primitive name.
func TestMixedSingleRoundtrip(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer enc.Close()

	if !enc.IsMixed() {
		t.Errorf("IsMixed() = false, want true")
	}
	if enc.Primitive != easy.MixedPrimitive {
		t.Errorf("Primitive = %q, want %q", enc.Primitive, easy.MixedPrimitive)
	}
	if got := enc.PrimitiveAt(0); got != "blake3" {
		t.Errorf("PrimitiveAt(0) = %q, want blake3", got)
	}
	if got := enc.PrimitiveAt(1); got != "blake2s" {
		t.Errorf("PrimitiveAt(1) = %q, want blake2s", got)
	}
	if got := enc.PrimitiveAt(2); got != "areion256" {
		t.Errorf("PrimitiveAt(2) = %q, want areion256", got)
	}

	plaintext := []byte("mixed-mode Single round-trip payload")
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

// TestMixedSingleAuthRoundtrip verifies authenticated encrypt /
// decrypt round-trips on a mixed-primitive Single encryptor.
func TestMixedSingleAuthRoundtrip(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "areion256",
		PrimitiveD: "blake3",
		PrimitiveS: "chacha20",
		KeyBits:    512,
		MACName:    "hmac-blake3",
	})
	defer enc.Close()

	plaintext := []byte("mixed Single + auth payload")
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

// TestMixedSingleWithLockSeed verifies the dedicated lockSeed slot
// is allocated under its own primitive choice when PrimitiveL is
// non-empty, with BitSoup + LockSoup auto-coupled on the
// on-direction. PrimitiveAt(3) returns the lockSeed primitive.
func TestMixedSingleWithLockSeed(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake3",
		PrimitiveL: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer enc.Close()

	if got := enc.PrimitiveAt(3); got != "areion256" {
		t.Errorf("PrimitiveAt(3) = %q, want areion256", got)
	}
	// BitSoup + LockSoup are auto-coupled in mixed-mode lockSeed
	// allocation; the success of the encrypt / decrypt cycle below
	// confirms the overlay is engaged (a non-coupled lockSeed slot
	// would have wire-effect-free derivation and wouldn't change
	// ciphertext shape, but the lockSeed.AttachLockSeed call would
	// also panic on the build-PRF overlay-off guard at encrypt).
	plaintext := []byte("mixed Single + dedicated lockSeed payload")
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

// ─── Triple-mode mixed round-trip ────────────────────────────────────

// TestMixedTripleRoundtrip verifies the Triple Ouroboros round-trip
// with seven different 256-bit primitives wired across the noise /
// 3 data / 3 start slots and no dedicated lockSeed.
func TestMixedTripleRoundtrip(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "areion256",
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
		"areion256", "blake3", "blake2s", "chacha20",
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

// TestMixedTripleWithLockSeed verifies Triple Ouroboros mixed mode
// with the dedicated lockSeed slot allocated under its own primitive.
// Total slot count is 8 (1 noise + 3 data + 3 start + 1 lock).
func TestMixedTripleWithLockSeed(t *testing.T) {
	enc := easy.NewMixed3(easy.MixedSpec3{
		PrimitiveN:  "blake3",
		PrimitiveD1: "blake2s",
		PrimitiveD2: "blake3",
		PrimitiveD3: "blake2s",
		PrimitiveS1: "blake3",
		PrimitiveS2: "blake2s",
		PrimitiveS3: "blake3",
		PrimitiveL:  "areion256",
		KeyBits:     1024,
		MACName:     "kmac256",
	})
	defer enc.Close()

	if got := enc.PrimitiveAt(7); got != "areion256" {
		t.Errorf("PrimitiveAt(7) = %q, want areion256 (lockSeed slot)", got)
	}
	plaintext := []byte("mixed Triple + dedicated lockSeed payload")
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

// ─── Stream round-trip ───────────────────────────────────────────────

// TestMixedSingleStreamRoundtrip verifies streaming encrypt /
// decrypt cycles through the mixed-mode dispatch path.
func TestMixedSingleStreamRoundtrip(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake3",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer enc.Close()

	plaintext := bytes.Repeat([]byte("mixed stream payload bytes "), 1024)

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

// ─── Validation paths ────────────────────────────────────────────────

// TestMixedRejectMixedWidth verifies that mixing primitives across
// native hash widths panics with [ErrEasyMixedWidth] before any
// allocation runs.
func TestMixedRejectMixedWidth(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		// Panic message contains the wrapped sentinel.
		err, ok := r.(error)
		if ok && errors.Is(err, easy.ErrEasyMixedWidth) {
			return
		}
		// Many panics in this package are formatted strings carrying
		// the sentinel via fmt.Sprintf("...%w...", err). errors.Is
		// only works on error values; string panics need substring
		// matching.
		if s, ok := r.(string); ok && contains(s, "mixed-mode primitives must share") {
			return
		}
		t.Errorf("panic %v does not signal ErrEasyMixedWidth", r)
	}()
	_ = easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",     // 256-bit
		PrimitiveD: "areion512",  // 512-bit ← width mismatch
		PrimitiveS: "blake3",
		KeyBits:    1024,
		MACName:    "kmac256",
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
	_ = easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "no-such-primitive",
		PrimitiveD: "blake3",
		PrimitiveS: "blake3",
		KeyBits:    1024,
		MACName:    "kmac256",
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
	_ = easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",     // 256-bit
		PrimitiveD: "blake3",
		PrimitiveS: "blake3",
		PrimitiveL: "areion512",  // 512-bit ← width mismatch
		KeyBits:    1024,
		MACName:    "kmac256",
	})
}

// TestMixedDefaultsBehaveLikeNonMixed verifies that [New] /
// [New3] encryptors return their own primitive name from
// PrimitiveAt for every slot — the parallel-array compat path for
// code that walks PrimitiveAt regardless of construction style.
func TestMixedDefaultsBehaveLikeNonMixed(t *testing.T) {
	enc := easy.New("blake3", 1024, "kmac256")
	defer enc.Close()

	if enc.IsMixed() {
		t.Errorf("IsMixed() on New() encryptor = true, want false")
	}
	for i := 0; i < 3; i++ {
		if got := enc.PrimitiveAt(i); got != "blake3" {
			t.Errorf("PrimitiveAt(%d) on single-primitive encryptor = %q, want blake3", i, got)
		}
	}
}

// ─── State blob round-trip — mixed Export / Import ───────────────────

// TestMixedExportImportSingle verifies a mixed Single-mode encryptor
// round-trips through Export → fresh NewMixed receiver → Import →
// bit-exact decrypt of the sender's ciphertext. The receiver must
// be constructed with the matching MixedSpec; the per-slot primitive
// match is part of the Import validation contract.
func TestMixedExportImportSingle(t *testing.T) {
	spec := easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
	}
	sender := easy.NewMixed(spec)
	defer sender.Close()

	plaintext := []byte("mixed Single Export/Import roundtrip")
	ct, err := sender.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	blob := sender.Export()
	if len(blob) == 0 {
		t.Fatal("Export returned empty blob")
	}

	receiver := easy.NewMixed(spec)
	defer receiver.Close()
	if err := receiver.Import(blob); err != nil {
		t.Fatalf("Import: %v", err)
	}

	pt, err := receiver.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth on receiver: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch after Import")
	}
	for i, want := range []string{spec.PrimitiveN, spec.PrimitiveD, spec.PrimitiveS} {
		if got := receiver.PrimitiveAt(i); got != want {
			t.Errorf("PrimitiveAt(%d) post-Import = %q, want %q", i, got, want)
		}
	}
}

// TestMixedExportImportTriple verifies the Triple-mode mixed
// round-trip with a dedicated lockSeed slot in the spec — exercises
// the 8-slot path including the rawLockSeed:true blob field and
// per-slot primitive validation across all 8 slots.
func TestMixedExportImportTriple(t *testing.T) {
	spec := easy.MixedSpec3{
		PrimitiveN:  "areion256",
		PrimitiveD1: "blake3",
		PrimitiveD2: "blake2s",
		PrimitiveD3: "chacha20",
		PrimitiveS1: "blake2b256",
		PrimitiveS2: "blake3",
		PrimitiveS3: "blake2s",
		PrimitiveL:  "areion256",
		KeyBits:     1024,
		MACName:     "kmac256",
	}
	sender := easy.NewMixed3(spec)
	defer sender.Close()

	plaintext := bytes.Repeat([]byte("mixed Triple+lockSeed Export/Import "), 32)
	ct, err := sender.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	blob := sender.Export()

	receiver := easy.NewMixed3(spec)
	defer receiver.Close()
	if err := receiver.Import(blob); err != nil {
		t.Fatalf("Import: %v", err)
	}

	pt, err := receiver.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth on receiver: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch after Import")
	}
}

// TestMixedExportImportSipHashSlot verifies an aescmac+siphash24
// mixed-mode encryptor at 128-bit width — exercises the per-slot
// PRF-key-empty-vs-bytes validation path that single-primitive
// blobs never hit.
func TestMixedExportImportSipHashSlot(t *testing.T) {
	spec := easy.MixedSpec{
		PrimitiveN: "aescmac",
		PrimitiveD: "siphash24",
		PrimitiveS: "aescmac",
		KeyBits:    512,
		MACName:    "hmac-sha256",
	}
	sender := easy.NewMixed(spec)
	defer sender.Close()

	plaintext := []byte("mixed 128-bit aescmac+siphash24 mix")
	ct, err := sender.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob := sender.Export()

	receiver := easy.NewMixed(spec)
	defer receiver.Close()
	if err := receiver.Import(blob); err != nil {
		t.Fatalf("Import: %v", err)
	}

	pt, err := receiver.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch after Import")
	}
}

// TestMixedImportShapeMismatch verifies that a mixed blob landing
// on a single-primitive [New] receiver — and the reverse — is
// rejected with ErrMismatch{Field: "primitive"} rather than
// silently accepted.
func TestMixedImportShapeMismatch(t *testing.T) {
	mixedSpec := easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake3",
		KeyBits:    1024,
		MACName:    "kmac256",
	}
	mixedSender := easy.NewMixed(mixedSpec)
	defer mixedSender.Close()
	mixedBlob := mixedSender.Export()

	// Mixed blob → single receiver: rejected.
	singleReceiver := easy.New("blake3", 1024, "kmac256")
	defer singleReceiver.Close()
	if err := singleReceiver.Import(mixedBlob); err == nil {
		t.Fatal("single receiver accepted mixed blob")
	}

	// Single blob → mixed receiver: rejected.
	singleSender := easy.New("blake3", 1024, "kmac256")
	defer singleSender.Close()
	singleBlob := singleSender.Export()

	mixedReceiver := easy.NewMixed(mixedSpec)
	defer mixedReceiver.Close()
	if err := mixedReceiver.Import(singleBlob); err == nil {
		t.Fatal("mixed receiver accepted single blob")
	}
}

// TestMixedImportPrimitiveMismatch verifies that a mixed blob with
// per-slot primitives differing from the receiver's bound spec is
// rejected.
func TestMixedImportPrimitiveMismatch(t *testing.T) {
	senderSpec := easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake3",
		KeyBits:    1024,
		MACName:    "kmac256",
	}
	receiverSpec := easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "areion256", // ← differs from sender
		PrimitiveS: "blake3",
		KeyBits:    1024,
		MACName:    "kmac256",
	}

	sender := easy.NewMixed(senderSpec)
	defer sender.Close()
	blob := sender.Export()

	receiver := easy.NewMixed(receiverSpec)
	defer receiver.Close()
	if err := receiver.Import(blob); err == nil {
		t.Fatal("mixed receiver accepted blob with primitive mismatch")
	}
}

// contains is a tiny fmt-free substring helper for the mixed-width
// panic test, avoiding the strings import for a single call site.
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
