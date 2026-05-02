// Package easy_test (external) — comprehensive round-trip matrix and
// cross-encryptor scenarios for the [easy.Encryptor] surface.
//
// The matrix mirrors the primitive / width coverage of
// itb_ext_test.go's bench cohort: every PRF-grade primitive at
// widths 512 / 1024 / 2048 bits, with both Single and Triple
// Ouroboros modes, exercised through Encrypt / Decrypt,
// EncryptAuth / DecryptAuth, and EncryptStream / DecryptStream.
// Small-payload bytes.Equal round-trip — total ~162 sub-tests
// complete in a few seconds.
//
// Cross-encryptor scenarios cover the LockSeed wire-format
// invariants documented in .EASY.md: a receiver that explicitly
// disables LockSeed cannot decrypt a sender's LockSeed=1 ciphertext
// (the bit-permutation path differs), and Import of a blob with
// lock_seed:true silently elevates a default-LockSeed=0 receiver so
// the round-trip succeeds without any pre-Import setter call on
// the receiver side.
package easy_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb/easy"
)

// generateDataEasy fills an n-byte slice with crypto/rand bytes for
// test plaintext. The "Easy" suffix mirrors the "Ext" suffix used by
// itb_ext_test.go's helpers — both denote the in-package-test
// counterpart of an internal helper, the Easy variant living in
// the github.com/everanium/itb/easy sub-package.
func generateDataEasy(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// primitiveSpec lists every shipped (primitive name, key_bits
// widths) combination the round-trip matrix exercises. The
// universally-valid {512, 1024, 2048} triple is used across all
// nine primitives — the lower 256-bit key_bits corner is omitted
// because the Seed{128,256,512} constructors in the itb root
// require bits >= 512 (see itb/seed{128,256,512}.go), so a
// theoretical "9 × 4 widths × 2 modes = 72" matrix degrades to a
// runtime-valid 54 per matrix function. The 512-bit floor mirrors
// the bench coverage of itb_ext_test.go.
var primitiveSpec = []struct {
	name   string
	widths []int
}{
	{"areion256", []int{512, 1024, 2048}},
	{"areion512", []int{512, 1024, 2048}},
	{"siphash24", []int{512, 1024, 2048}},
	{"aescmac", []int{512, 1024, 2048}},
	{"blake2b256", []int{512, 1024, 2048}},
	{"blake2b512", []int{512, 1024, 2048}},
	{"blake2s", []int{512, 1024, 2048}},
	{"blake3", []int{512, 1024, 2048}},
	{"chacha20", []int{512, 1024, 2048}},
}

// modes lists the two Ouroboros shapes in canonical order.
var modes = []struct {
	name string
	mode int
}{
	{"Single", 1},
	{"Triple", 3},
}

// newEncryptorFor builds a fresh encryptor for the given primitive
// name, key_bits, and Mode (1 = Single via [easy.New], 3 = Triple
// via [easy.New3]).
func newEncryptorFor(primitive string, keyBits, mode int) *easy.Encryptor {
	if mode == 3 {
		return easy.New3(primitive, keyBits)
	}
	return easy.New(primitive, keyBits)
}

// TestEasyRoundtripMatrix exercises plain Encrypt → Decrypt on every
// (primitive, key_bits, mode) combination at a 1 KiB payload.
func TestEasyRoundtripMatrix(t *testing.T) {
	plaintext := generateDataEasy(1024)
	for _, ps := range primitiveSpec {
		for _, kb := range ps.widths {
			for _, m := range modes {
				name := fmt.Sprintf("%s_%dbit_%s", ps.name, kb, m.name)
				t.Run(name, func(t *testing.T) {
					enc := newEncryptorFor(ps.name, kb, m.mode)
					defer enc.Close()
					ct, err := enc.Encrypt(plaintext)
					if err != nil {
						t.Fatalf("Encrypt: %v", err)
					}
					pt, err := enc.Decrypt(ct)
					if err != nil {
						t.Fatalf("Decrypt: %v", err)
					}
					if !bytes.Equal(pt, plaintext) {
						t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(pt), len(plaintext))
					}
				})
			}
		}
	}
}

// TestEasyAuthRoundtripMatrix exercises EncryptAuth → DecryptAuth on
// the same matrix as [TestEasyRoundtripMatrix].
func TestEasyAuthRoundtripMatrix(t *testing.T) {
	plaintext := generateDataEasy(1024)
	for _, ps := range primitiveSpec {
		for _, kb := range ps.widths {
			for _, m := range modes {
				name := fmt.Sprintf("%s_%dbit_%s", ps.name, kb, m.name)
				t.Run(name, func(t *testing.T) {
					enc := newEncryptorFor(ps.name, kb, m.mode)
					defer enc.Close()
					ct, err := enc.EncryptAuth(plaintext)
					if err != nil {
						t.Fatalf("EncryptAuth: %v", err)
					}
					pt, err := enc.DecryptAuth(ct)
					if err != nil {
						t.Fatalf("DecryptAuth: %v", err)
					}
					if !bytes.Equal(pt, plaintext) {
						t.Errorf("auth roundtrip mismatch: got %d bytes, want %d", len(pt), len(plaintext))
					}
				})
			}
		}
	}
}

// TestEasyStreamRoundtripMatrix exercises EncryptStream → DecryptStream
// on the same matrix at a slightly larger 4 KiB payload (small enough
// to remain a single chunk under the auto-detect heuristic but still
// exercises the chunk-walking decode path).
func TestEasyStreamRoundtripMatrix(t *testing.T) {
	plaintext := generateDataEasy(4096)
	for _, ps := range primitiveSpec {
		for _, kb := range ps.widths {
			for _, m := range modes {
				name := fmt.Sprintf("%s_%dbit_%s", ps.name, kb, m.name)
				t.Run(name, func(t *testing.T) {
					enc := newEncryptorFor(ps.name, kb, m.mode)
					defer enc.Close()
					var streamed bytes.Buffer
					err := enc.EncryptStream(plaintext, func(chunk []byte) error {
						_, e := streamed.Write(chunk)
						return e
					})
					if err != nil {
						t.Fatalf("EncryptStream: %v", err)
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
						t.Errorf("stream roundtrip mismatch: got %d bytes, want %d",
							recovered.Len(), len(plaintext))
					}
				})
			}
		}
	}
}

// TestEasyCrossLockSeedMismatch verifies that a receiver which
// explicitly disables LockSeed cannot reconstruct a sender's
// LockSeed=1 plaintext correctly. Inverse-permutation differs
// between LockSeed=0 (derives from noiseSeed) and LockSeed=1
// (derives from the dedicated lockSeed): the bit-permutation reverse
// applies the wrong table on decrypt and produces bytes-different
// output even though the per-pixel hash machinery and (in Auth
// mode) the MAC over the permuted payload still verify. LockSoup=1
// engages the bit-permutation overlay on both sides; the test runs
// for Single and Triple Ouroboros via the modes table.
//
// MAC behaviour on Auth mode is intentionally not asserted here —
// the MAC is computed over the COBS-encoded permuted payload, which
// the receiver recovers identically because the noise / data /
// start seeds match; the LockSeed difference only manifests in the
// reverse-permutation step that runs after MAC verification. The
// observable effect is a length / byte mismatch on the recovered
// plaintext, asserted via bytes.Equal.
func TestEasyCrossLockSeedMismatch(t *testing.T) {
	plaintext := []byte("LockSeed mismatch demonstration payload")

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			sender := newEncryptorFor("areion512", 1024, m.mode)
			defer sender.Close()
			sender.SetLockSoup(1)
			sender.SetLockSeed(1)

			ct, err := sender.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("sender Encrypt: %v", err)
			}
			blob := sender.Export()

			receiver := newEncryptorFor("areion512", 1024, m.mode)
			defer receiver.Close()
			receiver.SetLockSoup(1) // deployment config — must match sender

			if err := receiver.Import(blob); err != nil {
				t.Fatalf("receiver Import: %v", err)
			}

			// Sanity check — receiver with LockSeed=1 (adopted from
			// blob) successfully decrypts.
			pt, err := receiver.Decrypt(ct)
			if err != nil {
				t.Fatalf("receiver Decrypt (with adopted LockSeed=1): %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("receiver pre-mismatch sanity: roundtrip differs")
			}

			// Now disable LockSeed on the receiver — the lockSeed
			// handle is dropped; the inverse bit-permutation falls
			// back to noiseSeed-based derivation. Decrypt produces
			// bytes that no longer equal the original plaintext.
			receiver.SetLockSeed(0)
			ptMismatched, err := receiver.Decrypt(ct)
			if err != nil {
				// Plain Decrypt should not error on key mismatch
				// (non-Auth mode has no failure signal); a
				// structural error here would indicate a different
				// regression than the one this test is asserting.
				t.Fatalf("receiver Decrypt (with LockSeed disabled): unexpected error %v", err)
			}
			if bytes.Equal(ptMismatched, plaintext) {
				t.Errorf("receiver Decrypt (with LockSeed disabled): unexpectedly recovered plaintext exactly; LockSeed mismatch should produce different bytes")
			}
		})
	}
}

// TestEasyImportElevatesLockSeed verifies the wire-format invariant
// that the state blob's lock_seed flag is authoritative — a
// receiver that never calls SetLockSeed(1) before Import is silently
// elevated to LockSeed=1 by the imported blob, and decryption on
// the sender's ciphertext succeeds without any further LockSeed
// setter call on the receiver side. The test runs for Single and
// Triple Ouroboros via the modes table.
//
// LockSoup=1 is set on both sides as deployment config so the
// bit-permutation overlay is engaged on encrypt and decrypt; the
// elevation has no observable effect when the overlay is off.
//
// The scenario:
//
//  1. Sender constructs an encryptor with SetLockSoup(1) and
//     SetLockSeed(1), produces ciphertext + Exports the state blob
//     (which carries lock_seed: true and the dedicated lockSeed
//     material as the 4th / 8th seed entry).
//  2. Receiver constructs an encryptor of matching primitive /
//     key_bits / mac with SetLockSoup(1) (deployment config) but
//     NO receiver-side SetLockSeed call — receiver's pre-Import
//     LockSeed flag is 0 and it has only 3 (Single) / 7 (Triple)
//     seed slots.
//  3. Receiver Imports the blob — Import inspects lock_seed:true,
//     reconstructs the extra seed entry with the imported lockSeed
//     material, and updates cfg.LockSeed / cfg.LockSeedHandle so
//     the receiver effectively becomes LockSeed=1.
//  4. Receiver calls DecryptAuth — the bit-permutation path now
//     consults the imported lockSeed (matching the sender's
//     encrypt path) and decryption succeeds with bytes.Equal.
func TestEasyImportElevatesLockSeed(t *testing.T) {
	plaintext := []byte("Import elevation demonstration payload")

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			baseSeeds := 3
			if m.mode == 3 {
				baseSeeds = 7
			}

			// Sender — explicitly activates Lock Soup + LockSeed.
			sender := newEncryptorFor("areion512", 1024, m.mode)
			defer sender.Close()
			sender.SetLockSoup(1)
			sender.SetLockSeed(1)

			ct, err := sender.EncryptAuth(plaintext)
			if err != nil {
				t.Fatalf("sender EncryptAuth: %v", err)
			}
			blob := sender.Export()

			// Receiver — only Lock Soup is set (deployment config).
			// NO receiver-side SetLockSeed call.
			receiver := newEncryptorFor("areion512", 1024, m.mode)
			defer receiver.Close()
			receiver.SetLockSoup(1)

			// Pre-Import sanity: receiver has the base seed count.
			if got := len(receiver.SeedComponents()); got != baseSeeds {
				t.Fatalf("receiver pre-Import: got %d seed slots, want %d", got, baseSeeds)
			}

			// Import — adopts LockSeed=1 from the blob.
			if err := receiver.Import(blob); err != nil {
				t.Fatalf("receiver Import: %v", err)
			}

			// Post-Import: receiver now has one extra seed slot
			// (base + 1 dedicated lockSeed adopted from the blob).
			if got := len(receiver.SeedComponents()); got != baseSeeds+1 {
				t.Errorf("receiver post-Import: got %d seed slots, want %d (LockSeed elevated)",
					got, baseSeeds+1)
			}

			// DecryptAuth succeeds without any pre-Import
			// receiver-side SetLockSeed call.
			pt, err := receiver.DecryptAuth(ct)
			if err != nil {
				t.Fatalf("receiver DecryptAuth (after Import elevation): %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("Import-elevation roundtrip mismatch: got %d bytes, want %d",
					len(pt), len(plaintext))
			}
		})
	}
}
