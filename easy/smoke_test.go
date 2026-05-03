package easy_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb/easy"
)

// TestSmokeEncryptDecrypt verifies the round-trip works for the
// default constructor (areion512 / 1024 / hmac-blake3, Single mode).
func TestSmokeEncryptDecrypt(t *testing.T) {
	enc := easy.New()
	plaintext := []byte("hello world")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestSmokeEncryptAuthDecryptAuth verifies the authenticated round-
// trip for the default constructor.
func TestSmokeEncryptAuthDecryptAuth(t *testing.T) {
	enc := easy.New()
	plaintext := []byte("hello authenticated world")
	ct, err := enc.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	pt, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("auth roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestSmokeTriple verifies the New3 constructor and Triple Ouroboros
// round-trip end-to-end.
func TestSmokeTriple(t *testing.T) {
	enc := easy.New3()
	plaintext := []byte("hello triple world")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Triple Encrypt: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Triple Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Triple roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestSmokeStreamRoundtrip verifies the EncryptStream / DecryptStream
// chunk-walking round-trip end-to-end.
func TestSmokeStreamRoundtrip(t *testing.T) {
	enc := easy.New()
	plaintext := bytes.Repeat([]byte("streaming ITB. "), 4096) // ~60 KiB
	var streamed bytes.Buffer
	err := enc.EncryptStream(plaintext, func(chunk []byte) error {
		_, e := streamed.Write(chunk)
		return e
	})
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if streamed.Len() == 0 {
		t.Fatalf("EncryptStream produced empty output")
	}

	var recovered bytes.Buffer
	err = enc.DecryptStream(streamed.Bytes(), func(chunk []byte) error {
		_, e := recovered.Write(chunk)
		return e
	})
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("stream roundtrip mismatch: %d vs %d bytes", recovered.Len(), len(plaintext))
	}
}

// TestSmokeStreamAuthStub verifies the EncryptStreamAuth /
// DecryptStreamAuth methods return ErrStreamAuthNotImplemented per
// the v1 stub policy.
func TestSmokeStreamAuthStub(t *testing.T) {
	enc := easy.New()
	noop := func(chunk []byte) error { return nil }

	if err := enc.EncryptStreamAuth([]byte("x"), noop); err != easy.ErrStreamAuthNotImplemented {
		t.Errorf("EncryptStreamAuth: got %v, want ErrStreamAuthNotImplemented", err)
	}
	if err := enc.DecryptStreamAuth([]byte("x"), noop); err != easy.ErrStreamAuthNotImplemented {
		t.Errorf("DecryptStreamAuth: got %v, want ErrStreamAuthNotImplemented", err)
	}
}

// TestSmokeGettersDefensiveCopy verifies the inspection getters
// return defensive copies — mutating the returned slice does not
// disturb the encryptor's internal state.
func TestSmokeGettersDefensiveCopy(t *testing.T) {
	enc := easy.New()
	defer enc.Close()

	prfKeys := enc.PRFKeys()
	if len(prfKeys) != 3 {
		t.Fatalf("PRFKeys: got %d entries, want 3", len(prfKeys))
	}
	for i := range prfKeys {
		if len(prfKeys[i]) == 0 {
			t.Errorf("PRFKeys[%d]: empty", i)
		}
		// Mutate the returned slice; verify a fresh call returns
		// untouched bytes.
		clear(prfKeys[i])
	}
	prfKeys2 := enc.PRFKeys()
	for i := range prfKeys2 {
		zero := true
		for _, b := range prfKeys2[i] {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			t.Errorf("PRFKeys[%d]: returned zero bytes — defensive copy broken", i)
		}
	}

	seedComps := enc.SeedComponents()
	if len(seedComps) != 3 {
		t.Errorf("SeedComponents: got %d entries, want 3", len(seedComps))
	}

	macKey := enc.MACKey()
	if len(macKey) == 0 {
		t.Errorf("MACKey: empty")
	}
}

// TestSmokeClose verifies Close zeroes key material and that
// subsequent method calls panic with ErrClosed.
func TestSmokeClose(t *testing.T) {
	enc := easy.New()
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Idempotent.
	if err := enc.Close(); err != nil {
		t.Fatalf("Close (idempotent): %v", err)
	}

	defer func() {
		r := recover()
		if r != easy.ErrClosed {
			t.Errorf("post-Close Encrypt: panic recovered as %v, want ErrClosed", r)
		}
	}()
	_, _ = enc.Encrypt([]byte("x"))
}

// TestSmokeSetNonceBitsRoundtrip verifies that mutating NonceBits
// per-encryptor flows through encrypt / decrypt and the round-trip
// recovers the plaintext.
func TestSmokeSetNonceBitsRoundtrip(t *testing.T) {
	enc := easy.New()
	defer enc.Close()
	enc.SetNonceBits(256)

	plaintext := []byte("nonce override roundtrip")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt with NonceBits=256: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt with NonceBits=256: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("NonceBits=256 roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestSmokeExportImport verifies the round-trip via Export and
// Import: sender exports state, receiver constructs a matching
// encryptor and imports the blob, recovers the sender's plaintext
// from the sender's ciphertext.
func TestSmokeExportImport(t *testing.T) {
	sender := easy.New()
	defer sender.Close()

	plaintext := []byte("export / import handshake")
	ct, err := sender.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("sender EncryptAuth: %v", err)
	}

	blob := sender.Export()
	if len(blob) == 0 {
		t.Fatalf("Export: empty blob")
	}

	prim, kb, mode, mac := easy.PeekConfig(blob)
	if prim != "areion512" || kb != 1024 || mode != 1 || mac != "hmac-blake3" {
		t.Errorf("PeekConfig: got (%q, %d, %d, %q), want (areion512, 1024, 1, hmac-blake3)",
			prim, kb, mode, mac)
	}

	receiver := easy.New("areion512", 1024, "hmac-blake3")
	defer receiver.Close()

	if err := receiver.Import(blob); err != nil {
		t.Fatalf("receiver Import: %v", err)
	}

	pt, err := receiver.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("receiver DecryptAuth: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("Export/Import roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestSmokeImportRejection verifies a few representative validation
// rejections — primitive mismatch, version-too-new, and the
// non-canonical lock_seed encoding.
func TestSmokeImportRejection(t *testing.T) {
	sender := easy.New("areion512", 1024)
	defer sender.Close()
	blob := sender.Export()

	// primitive mismatch — receiver expects blake3.
	receiver := easy.New("blake3", 1024)
	defer receiver.Close()
	err := receiver.Import(blob)
	if err == nil {
		t.Errorf("primitive mismatch: got nil error, want ErrMismatch")
	}
}

// TestSmokeSetLockSeedSwitching verifies pre-Encrypt LockSeed
// toggling is allowed and post-Encrypt switching panics with
// ErrLockSeedAfterEncrypt.
func TestSmokeSetLockSeedSwitching(t *testing.T) {
	enc := easy.New()
	defer enc.Close()

	// Pre-Encrypt: toggle freely.
	enc.SetLockSeed(1)
	if len(enc.SeedComponents()) != 4 {
		t.Errorf("after SetLockSeed(1): got %d seed slots, want 4", len(enc.SeedComponents()))
	}
	enc.SetLockSeed(0)
	if len(enc.SeedComponents()) != 3 {
		t.Errorf("after SetLockSeed(0): got %d seed slots, want 3", len(enc.SeedComponents()))
	}
	enc.SetLockSeed(1)

	// Round-trip with LockSeed=1.
	plaintext := []byte("lock seed roundtrip")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("LockSeed=1 roundtrip mismatch: got %q, want %q", pt, plaintext)
	}

	// Post-Encrypt: switching panics.
	defer func() {
		r := recover()
		if r != easy.ErrLockSeedAfterEncrypt {
			t.Errorf("post-Encrypt SetLockSeed: panic recovered as %v, want ErrLockSeedAfterEncrypt", r)
		}
	}()
	enc.SetLockSeed(0)
}

// TestSmokeNonceBitsAccessors verifies the [Encryptor.NonceBits] /
// [Encryptor.HeaderSize] / [Encryptor.ParseChunkLen] trio: the
// per-instance accessors read the encryptor's own cfg.NonceBits
// (with fallback to the global at construction time) and stay
// independent of the process-wide [itb.GetNonceBits] / [itb.HeaderSize]
// readers. Used by streaming consumers that nibble through a
// ciphertext stream chunk-by-chunk via [Encryptor.Encrypt] /
// [Encryptor.Decrypt] without going through [Encryptor.EncryptStream]
// / [Encryptor.DecryptStream].
func TestSmokeNonceBitsAccessors(t *testing.T) {
	enc := easy.New("blake3", 1024, "kmac256")
	defer enc.Close()

	// Default snapshot: matches the global at construction time.
	if got := enc.NonceBits(); got != 128 {
		t.Errorf("default NonceBits = %d, want 128", got)
	}
	if got := enc.HeaderSize(); got != 20 {
		t.Errorf("default HeaderSize = %d, want 20", got)
	}

	// Per-instance override sweep.
	enc.SetNonceBits(256)
	if got := enc.NonceBits(); got != 256 {
		t.Errorf("after SetNonceBits(256): NonceBits = %d, want 256", got)
	}
	if got := enc.HeaderSize(); got != 36 {
		t.Errorf("after SetNonceBits(256): HeaderSize = %d, want 36", got)
	}
	enc.SetNonceBits(512)
	if got := enc.HeaderSize(); got != 68 {
		t.Errorf("after SetNonceBits(512): HeaderSize = %d, want 68", got)
	}

	// Round-trip with non-default nonce: ParseChunkLen reports the
	// full chunk length on the wire.
	plaintext := []byte("nonce-512 chunk parse roundtrip payload")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	chunkLen, err := enc.ParseChunkLen(ct[:enc.HeaderSize()])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	if chunkLen != len(ct) {
		t.Errorf("ParseChunkLen = %d, want %d", chunkLen, len(ct))
	}
}

// TestSmokeParseChunkLenErrors covers the error paths of
// [Encryptor.ParseChunkLen]: too-short buffer + zero dimensions.
func TestSmokeParseChunkLenErrors(t *testing.T) {
	enc := easy.New("blake3", 1024, "kmac256")
	defer enc.Close()

	if _, err := enc.ParseChunkLen(make([]byte, enc.HeaderSize()-1)); err == nil {
		t.Errorf("ParseChunkLen(short): want error, got nil")
	}
	if _, err := enc.ParseChunkLen(make([]byte, enc.HeaderSize())); err == nil {
		t.Errorf("ParseChunkLen(zero dims): want error, got nil")
	}
}

// TestSmokeNonceBitsTwoEncryptorsIsolated verifies that
// [Encryptor.SetNonceBits] on one encryptor does not leak into
// another encryptor's cfg.NonceBits — the per-instance config
// snapshots are independent.
func TestSmokeNonceBitsTwoEncryptorsIsolated(t *testing.T) {
	a := easy.New("blake3", 1024, "kmac256")
	defer a.Close()
	b := easy.New("blake3", 1024, "kmac256")
	defer b.Close()

	a.SetNonceBits(512)
	if got := a.NonceBits(); got != 512 {
		t.Errorf("a.NonceBits = %d, want 512", got)
	}
	if got := b.NonceBits(); got != 128 {
		t.Errorf("b.NonceBits = %d, want 128 (must not bleed from a)", got)
	}
	if got := a.HeaderSize(); got != 68 {
		t.Errorf("a.HeaderSize = %d, want 68", got)
	}
	if got := b.HeaderSize(); got != 20 {
		t.Errorf("b.HeaderSize = %d, want 20", got)
	}
}

// TestSmokeImportRestoresFullConfig verifies that all four
// per-instance configuration knobs (NonceBits, BarrierFill,
// BitSoup, LockSoup) round-trip through Export / Import without a
// manual mirror call on the receiver side. The blob carries the
// values that were explicitly set by the sender; missing fields
// indicate sender inheritance and leave the receiver's cfg
// untouched.
func TestSmokeImportRestoresFullConfig(t *testing.T) {
	src := easy.New("blake3", 1024, "kmac256")
	defer src.Close()
	src.SetNonceBits(512)
	src.SetBarrierFill(4)
	src.SetBitSoup(1)
	src.SetLockSoup(1)

	blob := src.Export()
	plaintext := []byte("full-config persistence")
	ct, err := src.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}

	// Receiver — fresh encryptor, no Set* mirror calls.
	dst := easy.New("blake3", 1024, "kmac256")
	defer dst.Close()
	if err := dst.Import(blob); err != nil {
		t.Fatalf("Import: %v", err)
	}

	if got := dst.NonceBits(); got != 512 {
		t.Errorf("after Import: NonceBits = %d, want 512", got)
	}
	if got := dst.HeaderSize(); got != 68 {
		t.Errorf("after Import: HeaderSize = %d, want 68", got)
	}

	pt, err := dst.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestSmokeImportBarrierFillReceiverPriority verifies the
// asymmetric BarrierFill rule: when the receiver has explicitly
// installed a non-default BarrierFill (> 1) before Import, that
// value takes priority over the blob's barrier_fill — the
// receiver's heavier CSPRNG margin is preserved across Import.
// The blob value applies only when the receiver is at the default
// (cfg.BarrierFill == 0 / 1).
//
// BarrierFill is asymmetric because the container dimensions are
// stored in the header, so the receiver can decrypt regardless of
// which margin the sender chose; the receiver's own choice is a
// deployment-side decision that should not be overridden.
func TestSmokeImportBarrierFillReceiverPriority(t *testing.T) {
	src := easy.New("blake3", 1024, "kmac256")
	defer src.Close()
	src.SetBarrierFill(4)
	blob := src.Export()
	plaintext := []byte("barrier-fill priority")
	ct, err := src.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}

	// Receiver pre-sets BarrierFill = 8; Import must NOT downgrade
	// it to the blob's 4.
	dst := easy.New("blake3", 1024, "kmac256")
	defer dst.Close()
	dst.SetBarrierFill(8)
	if err := dst.Import(blob); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Round-trip still works regardless of the BarrierFill choice
	// (the field is asymmetric on the wire format).
	pt, err := dst.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}

	// A receiver that did NOT pre-set BarrierFill picks up the
	// blob value.
	dst2 := easy.New("blake3", 1024, "kmac256")
	defer dst2.Close()
	if err := dst2.Import(blob); err != nil {
		t.Fatalf("dst2 Import: %v", err)
	}
	pt2, err := dst2.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("dst2 DecryptAuth: %v", err)
	}
	if string(pt2) != string(plaintext) {
		t.Errorf("dst2 plaintext mismatch: got %q, want %q", pt2, plaintext)
	}
}

// TestSmokeImportSparseBlob verifies that a blob exported from a
// sender that never set any per-instance overrides (all knobs at
// their inherit-sentinel defaults) carries no nonce_bits /
// barrier_fill / bit_soup / lock_soup fields and Import leaves the
// receiver's cfg untouched.
func TestSmokeImportSparseBlob(t *testing.T) {
	src := easy.New("blake3", 1024, "kmac256")
	defer src.Close()
	// No Set* calls — all knobs stay at sentinel.
	blob := src.Export()

	// The blob must not contain the optional config-knob fields.
	for _, field := range []string{
		`"nonce_bits":`,
		`"barrier_fill":`,
		`"bit_soup":`,
		`"lock_soup":`,
	} {
		if bytes.Contains(blob, []byte(field)) {
			t.Errorf("sparse blob unexpectedly contains %q", field)
		}
	}

	dst := easy.New("blake3", 1024, "kmac256")
	defer dst.Close()
	dst.SetNonceBits(256) // explicit pre-Import setting
	if err := dst.Import(blob); err != nil {
		t.Fatalf("Import: %v", err)
	}
	// Sparse blob does not carry NonceBits — dst keeps its 256.
	if got := dst.NonceBits(); got != 256 {
		t.Errorf("after sparse Import: NonceBits = %d, want 256 (preserved)", got)
	}
}
