package hashes

import (
	"testing"

	"github.com/everanium/itb"
)

// TestAESCMACDigestDependsOnEveryByte locks in the contract that
// the AES-CMAC closure absorbs every byte of input through its
// CBC-MAC chain. The pre-fix variant only XOR'd seed components
// when len(data) >= 16, so for short inputs (< 16 bytes) the seed
// was silently dropped and the digest was constant. After the
// audit-driven fix the seed is loaded into the first block
// unconditionally, every byte of `data` is XOR'd into the chain
// state, and subsequent 16-byte blocks chain via CBC-MAC.
//
// The test runs at three input lengths matching the buf shapes
// ITB uses with each SetNonceBits configuration:
//
//	20 bytes  — default 128-bit nonce
//	36 bytes  — SetNonceBits(256)
//	68 bytes  — SetNonceBits(512)
func TestAESCMACDigestDependsOnEveryByte(t *testing.T) {
	hashFn := AESCMACWithKey([16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	})
	const seed0 uint64 = 0xDEADBEEFCAFEBABE
	const seed1 uint64 = 0x1234567890ABCDEF

	for _, n := range []int{20, 36, 68} {
		base := make([]byte, n)
		for i := range base {
			base[i] = byte(i)
		}
		baseLo, baseHi := hashFn(base, seed0, seed1)

		for i := 0; i < n; i++ {
			alt := append([]byte(nil), base...)
			alt[i] ^= 0x01
			altLo, altHi := hashFn(alt, seed0, seed1)
			if baseLo == altLo && baseHi == altHi {
				t.Errorf("AES-CMAC len=%d byte[%d] flip did not change digest "+
					"(base=%016x%016x, alt=%016x%016x) — input truncation regression",
					n, i, baseHi, baseLo, altHi, altLo)
			}
		}
	}
}

// TestAESCMACEmptyVsShortDistinct guards the seed-always-contributes
// fix: empty input, 1-byte input, and 2-byte input must all produce
// distinct digests. Pre-fix all three would collapse to AES_K(seed)
// because the seed XOR was gated on len(data) >= 16 and short data
// did not contribute either.
func TestAESCMACEmptyVsShortDistinct(t *testing.T) {
	hashFn := AESCMACWithKey([16]byte{0xAA, 0xBB, 0xCC, 0xDD})
	const seed0 uint64 = 1
	const seed1 uint64 = 2

	d0lo, d0hi := hashFn([]byte{}, seed0, seed1)
	d1lo, d1hi := hashFn([]byte{0x00}, seed0, seed1)
	d2lo, d2hi := hashFn([]byte{0x00, 0x00}, seed0, seed1)

	if d0lo == d1lo && d0hi == d1hi {
		t.Errorf("AES-CMAC empty and 1-byte zero produced same digest "+
			"%016x%016x", d0hi, d0lo)
	}
	if d1lo == d2lo && d1hi == d2hi {
		t.Errorf("AES-CMAC 1-byte and 2-byte zero produced same digest "+
			"%016x%016x", d1hi, d1lo)
	}
	if d0lo == d2lo && d0hi == d2hi {
		t.Errorf("AES-CMAC empty and 2-byte zero produced same digest "+
			"%016x%016x", d0hi, d0lo)
	}
}

// TestAESCMACDeterminism: repeated calls with identical inputs
// produce identical outputs (the closure is stateless across
// invocations modulo the cached cipher.Block — Reset is implicit
// through the local b1 stack frame).
func TestAESCMACDeterminism(t *testing.T) {
	hashFn := AESCMACWithKey([16]byte{0x11, 0x22, 0x33, 0x44})
	const seed0 uint64 = 42
	const seed1 uint64 = 43
	data := []byte("the quick brown fox jumps over the lazy dog")

	a0, a1 := hashFn(data, seed0, seed1)
	b0, b1 := hashFn(data, seed0, seed1)
	if a0 != b0 || a1 != b1 {
		t.Fatalf("non-deterministic digest: %016x%016x vs %016x%016x",
			a1, a0, b1, b0)
	}

	// Different seed must change the digest (sanity).
	c0, c1 := hashFn(data, seed0^1, seed1)
	if a0 == c0 && a1 == c1 {
		t.Errorf("seed change did not change digest")
	}
}

// TestAESCMACEndToEndItb confirms the AES-CMAC factory still
// round-trips through the full ITB pipeline at every supported
// ITB key width — exercises the per-pixel hot path at the
// realistic input sizes ITB feeds (20-byte buf at default nonce
// config). Mirrors TestAreionEndToEndItb / the ChaCha20 ITB
// round-trip pattern.
func TestAESCMACEndToEndItb(t *testing.T) {
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	for _, keyBits := range []int{512, 1024, 2048} {
		t.Run(itoa(keyBits), func(t *testing.T) {
			ns, ds, ss := mkAESCMACTrio(t, keyBits)
			ct, err := itb.Encrypt128(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt128: %v", err)
			}
			pt, err := itb.Decrypt128(ns, ds, ss, ct)
			if err != nil {
				t.Fatalf("Decrypt128: %v", err)
			}
			if string(pt) != string(plaintext) {
				t.Fatalf("plaintext mismatch")
			}
		})
	}
}

func mkAESCMACTrio(t *testing.T, keyBits int) (*itb.Seed128, *itb.Seed128, *itb.Seed128) {
	t.Helper()
	mk := func() *itb.Seed128 {
		s, err := itb.NewSeed128(keyBits, AESCMAC())
		if err != nil {
			t.Fatalf("NewSeed128: %v", err)
		}
		return s
	}
	return mk(), mk(), mk()
}
