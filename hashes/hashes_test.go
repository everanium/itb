package hashes

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb"
)

// TestRegistryRoundtrip exercises every (hash, ITB key width) pair
// shipped through this package. Eight of the nine primitives (every
// width except 128) have separate Triple Ouroboros tests in the main
// itb_test.go and redteam_test.go suites; here we cover the simple
// Single Ouroboros encrypt/decrypt round trip across all 9 × 3 = 27
// combinations to confirm:
//
//   - the canonical name in Registry maps to the right Make{N}
//     dispatcher;
//   - the returned closure is wire-compatible with the matching
//     itb.NewSeed{N} / itb.Encrypt{N} / itb.Decrypt{N} entry points;
//   - every supported ITB key width (512, 1024, 2048) round-trips
//     for every primitive in canonical order.
func TestRegistryRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for _, spec := range Registry {
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%dbit", spec.Name, keyBits), func(t *testing.T) {
				switch spec.Width {
				case W128:
					roundtrip128(t, spec.Name, keyBits, plaintext)
				case W256:
					roundtrip256(t, spec.Name, keyBits, plaintext)
				case W512:
					roundtrip512(t, spec.Name, keyBits, plaintext)
				default:
					t.Fatalf("unexpected width %d", spec.Width)
				}
			})
		}
	}
}

func roundtrip128(t *testing.T, name string, keyBits int, plaintext []byte) {
	t.Helper()
	ns, err := newSeed128(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed128 noise: %v", err)
	}
	ds, err := newSeed128(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed128 data: %v", err)
	}
	ss, err := newSeed128(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed128 start: %v", err)
	}
	encrypted, err := itb.Encrypt128(ns, ds, ss, plaintext)
	if err != nil {
		t.Fatalf("Encrypt128: %v", err)
	}
	decrypted, err := itb.Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatalf("Decrypt128: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("%s/%dbit: plaintext mismatch", name, keyBits)
	}
}

func roundtrip256(t *testing.T, name string, keyBits int, plaintext []byte) {
	t.Helper()
	ns, err := newSeed256(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed256 noise: %v", err)
	}
	ds, err := newSeed256(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed256 data: %v", err)
	}
	ss, err := newSeed256(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed256 start: %v", err)
	}
	encrypted, err := itb.Encrypt256(ns, ds, ss, plaintext)
	if err != nil {
		t.Fatalf("Encrypt256: %v", err)
	}
	decrypted, err := itb.Decrypt256(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatalf("Decrypt256: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("%s/%dbit: plaintext mismatch", name, keyBits)
	}
}

func roundtrip512(t *testing.T, name string, keyBits int, plaintext []byte) {
	t.Helper()
	ns, err := newSeed512(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed512 noise: %v", err)
	}
	ds, err := newSeed512(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed512 data: %v", err)
	}
	ss, err := newSeed512(name, keyBits)
	if err != nil {
		t.Fatalf("newSeed512 start: %v", err)
	}
	encrypted, err := itb.Encrypt512(ns, ds, ss, plaintext)
	if err != nil {
		t.Fatalf("Encrypt512: %v", err)
	}
	decrypted, err := itb.Decrypt512(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatalf("Decrypt512: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("%s/%dbit: plaintext mismatch", name, keyBits)
	}
}

func newSeed128(name string, keyBits int) (*itb.Seed128, error) {
	h, _, err := Make128(name)
	if err != nil {
		return nil, err
	}
	return itb.NewSeed128(keyBits, h)
}

func newSeed256(name string, keyBits int) (*itb.Seed256, error) {
	h, b, _, err := Make256Pair(name)
	if err != nil {
		return nil, err
	}
	s, err := itb.NewSeed256(keyBits, h)
	if err != nil {
		return nil, err
	}
	if b != nil {
		s.BatchHash = b
	}
	return s, nil
}

func newSeed512(name string, keyBits int) (*itb.Seed512, error) {
	h, b, _, err := Make512Pair(name)
	if err != nil {
		return nil, err
	}
	s, err := itb.NewSeed512(keyBits, h)
	if err != nil {
		return nil, err
	}
	if b != nil {
		s.BatchHash = b
	}
	return s, nil
}

// TestRegistryStable verifies that Registry ordering matches the
// canonical FFI contract (areion256, areion512, siphash24, aescmac,
// blake2b256, blake2b512, blake2s, blake3, chacha20). The order is
// stable because index 0..8 is exposed through ITB_HashName and any
// reordering is an ABI-breaking change.
func TestRegistryStable(t *testing.T) {
	want := []string{
		"areion256", "areion512", "siphash24", "aescmac",
		"blake2b256", "blake2b512", "blake2s", "blake3", "chacha20",
	}
	if len(Registry) != len(want) {
		t.Fatalf("Registry len = %d, want %d", len(Registry), len(want))
	}
	for i, n := range want {
		if Registry[i].Name != n {
			t.Errorf("Registry[%d] = %q, want %q", i, Registry[i].Name, n)
		}
	}
}
