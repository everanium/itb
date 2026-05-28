package hashes

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb"
)

// TestRegistryRoundtrip exercises every (hash, ITB key width) pair
// shipped through this package. Primitives have separate Triple Ouroboros
// tests in the main itb_test.go and redteam_test.go suites; here we cover
// the simple Single Ouroboros encrypt/decrypt round trip across all
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
// canonical FFI contract. The order is stable because index
// is exposed through ITB_HashName and any reordering is an
// ABI-breaking change.
func TestRegistryStable(t *testing.T) {
	want := []string{
		"areion256", "areion512", "blake2b256", "blake2b512",
		"blake2s", "blake3", "aescmac", "siphash24", "chacha20",
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

// TestFindKnownPrimitives asserts that Find returns the canonical Spec
// for every registry entry and reports (_, false) for unknown names.
// Find is the lookup primitive backing Make128 / Make256 / Make512's
// "unknown name vs wrong-width" disambiguation; both arms are exercised
// here in addition to the per-Make tests below.
func TestFindKnownPrimitives(t *testing.T) {
	for _, want := range Registry {
		got, ok := Find(want.Name)
		if !ok {
			t.Errorf("Find(%q): ok=false, want true", want.Name)
			continue
		}
		if got != want {
			t.Errorf("Find(%q) = %+v, want %+v", want.Name, got, want)
		}
	}
	if _, ok := Find("totally-unknown-primitive"); ok {
		t.Error("Find(\"totally-unknown-primitive\"): ok=true, want false")
	}
	if _, ok := Find(""); ok {
		t.Error("Find(\"\"): ok=true, want false")
	}
}

// TestMake128UnknownName confirms Make128 returns an error for a name
// absent from the registry — the final fall-through arm of the switch
// statement.
func TestMake128UnknownName(t *testing.T) {
	_, _, err := Make128("nonexistent-primitive")
	if err == nil {
		t.Error("Make128(unknown): nil error, want error")
	}
}

// TestMake256UnknownName confirms Make256 returns an error for a name
// absent from the registry.
func TestMake256UnknownName(t *testing.T) {
	_, _, err := Make256("nonexistent-primitive")
	if err == nil {
		t.Error("Make256(unknown): nil error, want error")
	}
}

// TestMake512UnknownName confirms Make512 returns an error for a name
// absent from the registry.
func TestMake512UnknownName(t *testing.T) {
	_, _, err := Make512("nonexistent-primitive")
	if err == nil {
		t.Error("Make512(unknown): nil error, want error")
	}
}

// TestMake128WrongWidth exercises the wrong-width arm of Make128: a
// known registry entry whose Spec.Width is not W128 must produce a
// "has width N, not 128" error distinguishable from the unknown-name
// path. Covers Make128Pair via the same dispatch.
func TestMake128WrongWidth(t *testing.T) {
	for _, name := range []string{"areion256", "areion512", "blake2b256", "blake2b512", "blake2s", "blake3", "chacha20"} {
		_, _, err := Make128(name)
		if err == nil {
			t.Errorf("Make128(%q): nil error, want wrong-width error", name)
		}
		_, _, _, err = Make128Pair(name)
		if err == nil {
			t.Errorf("Make128Pair(%q): nil error, want wrong-width error", name)
		}
	}
}

// TestMake256WrongWidth exercises the wrong-width arm of Make256: a
// known registry entry whose Spec.Width is not W256 must produce a
// "has width N, not 256" error distinguishable from the unknown-name
// path.
func TestMake256WrongWidth(t *testing.T) {
	for _, name := range []string{"areion512", "blake2b512", "aescmac", "siphash24"} {
		_, _, err := Make256(name)
		if err == nil {
			t.Errorf("Make256(%q): nil error, want wrong-width error", name)
		}
		_, _, _, err = Make256Pair(name)
		if err == nil {
			t.Errorf("Make256Pair(%q): nil error, want wrong-width error", name)
		}
	}
}

// TestMake512WrongWidth exercises the wrong-width arm of Make512: a
// known registry entry whose Spec.Width is not W512 must produce a
// "has width N, not 512" error distinguishable from the unknown-name
// path.
func TestMake512WrongWidth(t *testing.T) {
	for _, name := range []string{"areion256", "blake2b256", "blake2s", "blake3", "aescmac", "siphash24", "chacha20"} {
		_, _, err := Make512(name)
		if err == nil {
			t.Errorf("Make512(%q): nil error, want wrong-width error", name)
		}
		_, _, _, err = Make512Pair(name)
		if err == nil {
			t.Errorf("Make512Pair(%q): nil error, want wrong-width error", name)
		}
	}
}

// TestMake128SipHashRejectsKey verifies that the siphash24 arm of
// Make128 / Make128Pair refuses a caller-supplied fixed key. SipHash-2-4
// has no internal fixed key (keying material is the per-call seed
// components) so passing any key for "siphash24" must error.
func TestMake128SipHashRejectsKey(t *testing.T) {
	_, _, err := Make128("siphash24", make([]byte, 16))
	if err == nil {
		t.Error("Make128(siphash24, 16-byte key): nil error, want rejection")
	}
	_, _, _, err = Make128Pair("siphash24", make([]byte, 16))
	if err == nil {
		t.Error("Make128Pair(siphash24, 16-byte key): nil error, want rejection")
	}
}

// TestMake128AESCMACBadKeySize confirms Make128 / Make128Pair reject
// caller-supplied keys whose size does not match the AES-CMAC native
// 16-byte key length, exercising the validateKey error path.
func TestMake128AESCMACBadKeySize(t *testing.T) {
	_, _, err := Make128("aescmac", make([]byte, 15))
	if err == nil {
		t.Error("Make128(aescmac, 15-byte key): nil error, want size-mismatch error")
	}
	_, _, _, err = Make128Pair("aescmac", make([]byte, 17))
	if err == nil {
		t.Error("Make128Pair(aescmac, 17-byte key): nil error, want size-mismatch error")
	}
}

// TestMake256SingleArm iterates every 256-bit registry entry through
// the single-arm Make256 wrapper (not Make256Pair) and confirms a small
// plaintext roundtrips through Encrypt256 / Decrypt256. Make256 is the
// path FFI consumers hit when they want a HashFunc256 without paying
// for batched dispatch wiring; covering every primitive ensures every
// switch arm of Make256 returns a usable closure.
func TestMake256SingleArm(t *testing.T) {
	plaintext := make([]byte, 256)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	for _, spec := range Registry {
		if spec.Width != W256 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			h, retKey, err := Make256(spec.Name)
			if err != nil {
				t.Fatalf("Make256(%q): %v", spec.Name, err)
			}
			if h == nil {
				t.Fatalf("Make256(%q): nil closure", spec.Name)
			}
			if len(retKey) != 32 {
				t.Errorf("Make256(%q) returned key len = %d, want 32", spec.Name, len(retKey))
			}
			ns, err := itb.NewSeed256(1024, h)
			if err != nil {
				t.Fatalf("NewSeed256 noise: %v", err)
			}
			ds, err := itb.NewSeed256(1024, h)
			if err != nil {
				t.Fatalf("NewSeed256 data: %v", err)
			}
			ss, err := itb.NewSeed256(1024, h)
			if err != nil {
				t.Fatalf("NewSeed256 start: %v", err)
			}
			ct, err := itb.Encrypt256(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt256: %v", err)
			}
			pt, err := itb.Decrypt256(ns, ds, ss, ct)
			if err != nil {
				t.Fatalf("Decrypt256: %v", err)
			}
			if !bytes.Equal(plaintext, pt) {
				t.Fatalf("%s: plaintext mismatch", spec.Name)
			}
		})
	}
}

// TestMake512SingleArm iterates every 512-bit registry entry through
// the single-arm Make512 wrapper (not Make512Pair). Mirror of
// TestMake256SingleArm at width 512.
func TestMake512SingleArm(t *testing.T) {
	plaintext := make([]byte, 256)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	for _, spec := range Registry {
		if spec.Width != W512 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			h, retKey, err := Make512(spec.Name)
			if err != nil {
				t.Fatalf("Make512(%q): %v", spec.Name, err)
			}
			if h == nil {
				t.Fatalf("Make512(%q): nil closure", spec.Name)
			}
			if len(retKey) != 64 {
				t.Errorf("Make512(%q) returned key len = %d, want 64", spec.Name, len(retKey))
			}
			ns, err := itb.NewSeed512(1024, h)
			if err != nil {
				t.Fatalf("NewSeed512 noise: %v", err)
			}
			ds, err := itb.NewSeed512(1024, h)
			if err != nil {
				t.Fatalf("NewSeed512 data: %v", err)
			}
			ss, err := itb.NewSeed512(1024, h)
			if err != nil {
				t.Fatalf("NewSeed512 start: %v", err)
			}
			ct, err := itb.Encrypt512(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt512: %v", err)
			}
			pt, err := itb.Decrypt512(ns, ds, ss, ct)
			if err != nil {
				t.Fatalf("Decrypt512: %v", err)
			}
			if !bytes.Equal(plaintext, pt) {
				t.Fatalf("%s: plaintext mismatch", spec.Name)
			}
		})
	}
}

// TestMake256ExplicitKeyRoundtrip exercises the explicit-key arm of
// each Make256 case for cross-process persistence: the key is supplied
// twice, and the resulting closures must produce identical digests on
// the same seed + data. Covers the explicit-key branch of every Make256
// case statement (areion256, blake2b256, blake2s, blake3, chacha20).
func TestMake256ExplicitKeyRoundtrip(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	seed := [4]uint64{0xdead, 0xbeef, 0xcafe, 0xf00d}
	for _, spec := range Registry {
		if spec.Width != W256 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			h1, ret1, err := Make256(spec.Name, key[:])
			if err != nil {
				t.Fatalf("Make256(%q, key) attempt 1: %v", spec.Name, err)
			}
			if !bytes.Equal(ret1, key[:]) {
				t.Errorf("Make256(%q) returned key != supplied key", spec.Name)
			}
			h2, ret2, err := Make256(spec.Name, key[:])
			if err != nil {
				t.Fatalf("Make256(%q, key) attempt 2: %v", spec.Name, err)
			}
			if !bytes.Equal(ret2, key[:]) {
				t.Errorf("Make256(%q) returned key != supplied key on attempt 2", spec.Name)
			}
			if h1(data, seed) != h2(data, seed) {
				t.Errorf("Make256(%q): output diverges across two same-key calls", spec.Name)
			}
		})
	}
}

// TestMake512ExplicitKeyRoundtrip exercises the explicit-key arm of
// each Make512 case statement (areion512, blake2b512). Mirror of
// TestMake256ExplicitKeyRoundtrip at width 512.
func TestMake512ExplicitKeyRoundtrip(t *testing.T) {
	var key [64]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	seed := [8]uint64{0xdead, 0xbeef, 0xcafe, 0xf00d, 0xabcd, 0x1234, 0x5678, 0x9abc}
	for _, spec := range Registry {
		if spec.Width != W512 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			h1, ret1, err := Make512(spec.Name, key[:])
			if err != nil {
				t.Fatalf("Make512(%q, key) attempt 1: %v", spec.Name, err)
			}
			if !bytes.Equal(ret1, key[:]) {
				t.Errorf("Make512(%q) returned key != supplied key", spec.Name)
			}
			h2, ret2, err := Make512(spec.Name, key[:])
			if err != nil {
				t.Fatalf("Make512(%q, key) attempt 2: %v", spec.Name, err)
			}
			if !bytes.Equal(ret2, key[:]) {
				t.Errorf("Make512(%q) returned key != supplied key on attempt 2", spec.Name)
			}
			if h1(data, seed) != h2(data, seed) {
				t.Errorf("Make512(%q): output diverges across two same-key calls", spec.Name)
			}
		})
	}
}
