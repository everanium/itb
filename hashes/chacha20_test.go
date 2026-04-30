package hashes

import (
	"testing"

	"github.com/everanium/itb"
)

// TestChaCha20DigestDependsOnEveryByte locks in the fix for the
// previous-version bug where the ChaCha20 hash truncated input to
// the first 12 bytes (treating them as the cipher nonce). Under
// the new CBC-MAC-style absorb construction every input byte
// must contribute — flipping any single byte of `data` must
// produce a different digest. The test runs at three input
// lengths matching the buf shapes ITB uses internally with the
// 128 / 256 / 512-bit nonce configurations:
//
//	20 bytes  — default (16-byte nonce + 4-byte block index)
//	36 bytes  — SetNonceBits(256) (32-byte nonce + 4-byte block index)
//	68 bytes  — SetNonceBits(512) (64-byte nonce + 4-byte block index)
func TestChaCha20DigestDependsOnEveryByte(t *testing.T) {
	mac := ChaCha20WithKey([32]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	})
	seed := [4]uint64{0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0}

	for _, n := range []int{20, 36, 68} {
		base := make([]byte, n)
		for i := range base {
			base[i] = byte(i)
		}
		baseDigest := mac(base, seed)

		for i := 0; i < n; i++ {
			alt := append([]byte(nil), base...)
			alt[i] ^= 0x01
			altDigest := mac(alt, seed)
			if baseDigest == altDigest {
				t.Errorf("len=%d byte[%d] flip did not change digest "+
					"(base=%x, alt=%x) — input truncation regression",
					n, i, baseDigest, altDigest)
			}
		}
	}
}

// TestChaCha20EmptyVsShortDistinct guards against another
// truncation-class regression: the empty-input digest must differ
// from the digest of any single-byte input, and a length-only
// difference (zero-padded inputs of different lengths) must
// likewise diverge. The length-tag prefix in the initial state
// is what guarantees this.
func TestChaCha20EmptyVsShortDistinct(t *testing.T) {
	mac := ChaCha20WithKey([32]byte{0xAA, 0xBB, 0xCC, 0xDD})
	seed := [4]uint64{1, 2, 3, 4}

	d0 := mac([]byte{}, seed)
	d1 := mac([]byte{0x00}, seed)
	d2 := mac([]byte{0x00, 0x00}, seed)

	if d0 == d1 {
		t.Errorf("empty and 1-byte zero produced same digest %x", d0)
	}
	if d1 == d2 {
		t.Errorf("1-byte and 2-byte zero produced same digest %x", d1)
	}
	if d0 == d2 {
		t.Errorf("empty and 2-byte zero produced same digest %x", d0)
	}
}

// TestChaCha20Determinism: repeated calls with identical inputs
// produce identical outputs — the CBC-MAC chain is reset at the
// start of every invocation rather than carrying state across
// calls. Also confirms a seed change actually changes the digest.
func TestChaCha20Determinism(t *testing.T) {
	mac := ChaCha20WithKey([32]byte{0x11, 0x22, 0x33})
	seed := [4]uint64{42, 43, 44, 45}
	data := []byte("the quick brown fox jumps over the lazy dog")

	d1 := mac(data, seed)
	d2 := mac(data, seed)
	if d1 != d2 {
		t.Fatalf("non-deterministic digest: %x vs %x", d1, d2)
	}

	seedAlt := seed
	seedAlt[0] ^= 1
	dAlt := mac(data, seedAlt)
	if d1 == dAlt {
		t.Errorf("seed change did not change digest")
	}
}

// TestChaCha20EndToEndItb confirms the chain-rewritten ChaCha20
// factory still round-trips through the full ITB pipeline at every
// supported ITB key width — exercises the per-pixel hot path that
// called into the broken truncation in production. Mirrors
// TestAreionEndToEndItb / TestAESCMACEndToEndItb.
func TestChaCha20EndToEndItb(t *testing.T) {
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	for _, keyBits := range []int{512, 1024, 2048} {
		t.Run(itoa(keyBits), func(t *testing.T) {
			ns, ds, ss := mkChaCha20Trio(t, keyBits)
			ct, err := itb.Encrypt256(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt256: %v", err)
			}
			pt, err := itb.Decrypt256(ns, ds, ss, ct)
			if err != nil {
				t.Fatalf("Decrypt256: %v", err)
			}
			if string(pt) != string(plaintext) {
				t.Fatalf("plaintext mismatch")
			}
		})
	}
}

func mkChaCha20Trio(t *testing.T, keyBits int) (*itb.Seed256, *itb.Seed256, *itb.Seed256) {
	t.Helper()
	mk := func() *itb.Seed256 {
		fn, _ := ChaCha20()
		s, err := itb.NewSeed256(keyBits, fn)
		if err != nil {
			t.Fatalf("NewSeed256: %v", err)
		}
		return s
	}
	return mk(), mk(), mk()
}
