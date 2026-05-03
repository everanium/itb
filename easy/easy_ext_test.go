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

// TestEasyMixedSingleRoundtripExt — Single-Ouroboros 4-slot mixed
// encryptor (BLAKE3 noise / BLAKE2s data / BLAKE2b-256 start /
// Areion-SoEM-256 lockSeed) plus KMAC256 MAC at 1024-bit ITB key
// width, plain Encrypt / Decrypt round-trip on a 4 MB CSPRNG
// payload. KMAC256 is bound at construction (the encryptor still
// allocates the MAC closure even when only the plain Encrypt path
// is exercised). Confirms the four 256-bit PRF-grade primitives
// can co-exist on one Single Ouroboros instance through the
// high-level surface.
func TestEasyMixedSingleRoundtripExt(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake2b256",
		PrimitiveL: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
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
		t.Fatalf("Single mixed roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestEasyMixedSingleAuthRoundtripExt — same shape as the no-MAC
// counterpart, exercises EncryptAuth / DecryptAuth so the embedded
// 32-byte KMAC256 tag is verified across the round-trip.
func TestEasyMixedSingleAuthRoundtripExt(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake2b256",
		PrimitiveL: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
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
		t.Fatalf("Single mixed auth roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestEasyMixedTripleRoundtripExt — Triple-Ouroboros 8-slot mixed
// encryptor: 1 noise + 3 data + 3 start + 1 lockSeed, with the
// four 256-bit primitives cycled across the seven main slots and
// the lockSeed pinned to Areion-SoEM-256. 1024-bit ITB key,
// KMAC256 MAC bound at construction, plain Encrypt3x / Decrypt3x
// round-trip on 4 MB CSPRNG payload.
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

// TestEasyMixedTripleAuthRoundtripExt — Triple-Ouroboros mirror of
// the authenticated Single test. EncryptAuth / DecryptAuth across
// the 8-slot mixed configuration with the embedded KMAC256 tag
// verified end-to-end.
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

// ─── Auto-couple regression tests ────────────────────────────────────
//
// The following four tests verify that [Encryptor.SetBitSoup](0) and
// [Encryptor.SetLockSoup](0) do not silently leave a dedicated
// lockSeed orphaned without an engaged bit-permutation overlay. The
// build-PRF closure inside bitsoup.go panics with
// itb.ErrLockSeedOverlayOff when the lockSeed handle is non-nil but
// both BitSoup and LockSoup are off — Easy Mode therefore overrides
// mode == 0 to mode == 1 on those two setters when LockSeed == 1.

// TestEasySetBitSoupZeroOverridenWhenLockSeedActive exercises the
// auto-couple guard on SetBitSoup. SetLockSeed(1) activates the
// lockSeed (which itself auto-engages BitSoup=1 + LockSoup=1);
// SetBitSoup(0) then attempts to disable bit-soup. Encrypt should
// succeed because the auto-couple guard kept BitSoup == 1.
func TestEasySetBitSoupZeroOverridenWhenLockSeedActive(t *testing.T) {
	enc := easy.New("blake3", 1024, "kmac256")
	defer enc.Close()

	enc.SetLockSeed(1)
	enc.SetBitSoup(0)
	enc.SetLockSoup(0)

	plaintext := []byte("auto-couple regression payload")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt after disabling overlay: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestEasyMixedConstructorSetBitSoupZeroOverriden verifies the same
// guard fires for encryptors built via [NewMixed] with a non-empty
// PrimitiveL: the dedicated lockSeed slot is allocated by the
// constructor, cfg.LockSeed = 1 is set, and a subsequent
// SetBitSoup(0) does not slip through.
func TestEasyMixedConstructorSetBitSoupZeroOverriden(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake2b256",
		PrimitiveL: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer enc.Close()

	enc.SetBitSoup(0)
	enc.SetLockSoup(0)

	plaintext := []byte("auto-couple via NewMixed regression payload")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt after disabling overlay: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestEasyMixed3ConstructorSetLockSoupZeroOverriden — Triple-mode
// counterpart. Both setters are exercised; the lockSeed allocation
// is the 8th slot in the seven-seed Triple shape.
func TestEasyMixed3ConstructorSetLockSoupZeroOverriden(t *testing.T) {
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

	enc.SetLockSoup(0)
	enc.SetBitSoup(0)

	plaintext := []byte("auto-couple via NewMixed3 Triple regression")
	ct, err := enc.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth after disabling overlay: %v", err)
	}
	pt, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestEasySetBitSoupZeroAfterSetLockSeedZero — once the lockSeed is
// dropped via SetLockSeed(0), the auto-couple guard releases and
// SetBitSoup(0) is honoured. This pins the boundary condition that
// lets a caller transition from a lockSeed-active configuration to
// a fully-overlay-off one without going through a panic intermediate.
func TestEasySetBitSoupZeroAfterSetLockSeedZero(t *testing.T) {
	enc := easy.New("blake3", 1024, "kmac256")
	defer enc.Close()

	enc.SetLockSeed(1)
	// LockSeed not yet used in encrypt — drop is allowed.
	enc.SetLockSeed(0)
	enc.SetBitSoup(0)
	enc.SetLockSoup(0)

	plaintext := []byte("post-lockSeed-drop overlay-off payload")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt with overlay fully off: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestEasyMixedSetLockSeedZeroDetachesNoiseSeedLock — Mixed-mode
// constructor wires noiseSeed.AttachLockSeed(ls) at construction.
// SetLockSeed(0) must symmetrically detach via DetachLockSeed,
// otherwise the build-PRF overlay-off guard panics on Encrypt
// when both BitSoup and LockSoup are subsequently disabled. Pre-
// fix sequence in this test reproduced the third-pass T1 finding.
func TestEasyMixedSetLockSeedZeroDetachesNoiseSeedLock(t *testing.T) {
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake2b256",
		PrimitiveL: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer enc.Close()

	enc.SetLockSeed(0)
	enc.SetBitSoup(0)
	enc.SetLockSoup(0)

	plaintext := []byte("Mixed lockSeed drop + overlay-off payload")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt after SetLockSeed(0)+overlay-off on Mixed: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestEasyMixed3SetLockSeedZeroDetachesNoiseSeedLock — Triple-mode
// counterpart of the Mixed/Single detach test. Same precondition
// (NewMixed3 with PrimitiveL attaches at construction); same drop
// sequence (SetLockSeed(0) + overlay-off); Encrypt must not panic.
func TestEasyMixed3SetLockSeedZeroDetachesNoiseSeedLock(t *testing.T) {
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

	enc.SetLockSeed(0)
	enc.SetBitSoup(0)
	enc.SetLockSoup(0)

	plaintext := []byte("Mixed3 lockSeed drop + overlay-off payload")
	ct, err := enc.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth after SetLockSeed(0)+overlay-off on Mixed3: %v", err)
	}
	pt, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestEasyMixedSetLockSeedZeroPrimitivesShrunk — after SetLockSeed(0)
// on a Mixed encryptor, the per-slot primitives slice must shrink
// alongside the seeds slice so a subsequent Export emits a blob
// with consistent len(Primitives) == len(Seeds). Pre-fix Export
// produced a length-mismatch blob that any matching receiver
// rejected with ErrMismatch{"primitive"}.
func TestEasyMixedSetLockSeedZeroPrimitivesShrunk(t *testing.T) {
	sender := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake2b256",
		PrimitiveL: "areion256",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer sender.Close()

	sender.SetLockSeed(0)

	plaintext := []byte("Mixed Export after SetLockSeed(0)")
	ct, err := sender.EncryptAuth(plaintext)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	blob := sender.Export()

	// Receiver must construct a 3-slot mixed encryptor (no
	// PrimitiveL), since SetLockSeed(0) shrunk the sender's slot
	// count from 4 to 3.
	receiver := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "blake2b256",
		KeyBits:    1024,
		MACName:    "kmac256",
	})
	defer receiver.Close()

	if err := receiver.Import(blob); err != nil {
		t.Fatalf("Import after sender SetLockSeed(0): %v", err)
	}
	pt, err := receiver.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("DecryptAuth on receiver: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}
