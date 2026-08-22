package itb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"testing"
)

// deterministicPlaintext returns a 4 KiB pseudo-random plaintext seeded
// by the SHA-256 of a fixed marker bytestring. The same plaintext is
// emitted on every test invocation so failures reproduce.
func deterministicPlaintext() []byte {
	digest := sha256.Sum256([]byte("itb-aliases-roundtrip-fixture-v1"))
	seed := int64(binary.LittleEndian.Uint64(digest[:8]))
	r := rand.New(rand.NewSource(seed))
	out := make([]byte, 4096)
	for i := range out {
		out[i] = byte(r.Intn(256))
	}
	return out
}

// aliasFixture3x128 builds a deterministic Triple Ouroboros 128-bit seed
// septuple. The 7 seeds must be distinct pointers; NewSeed128 returns
// independent allocations per call.
func aliasFixture3x128(t *testing.T) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed128) {
	t.Helper()
	ns, _ = NewSeed128(1024, sipHash128)
	ds1, _ = NewSeed128(1024, sipHash128)
	ds2, _ = NewSeed128(1024, sipHash128)
	ds3, _ = NewSeed128(1024, sipHash128)
	ss1, _ = NewSeed128(1024, sipHash128)
	ss2, _ = NewSeed128(1024, sipHash128)
	ss3, _ = NewSeed128(1024, sipHash128)
	if ns == nil || ds1 == nil || ds2 == nil || ds3 == nil || ss1 == nil || ss2 == nil || ss3 == nil {
		t.Fatalf("aliasFixture3x128: nil seed")
	}
	return
}

// aliasFixture3x256 builds a deterministic Triple Ouroboros 256-bit seed
// septuple. All seven seeds share a single BLAKE3 hash factory but each
// is allocated independently so the pointers compare unequal.
func aliasFixture3x256(t *testing.T) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256) {
	t.Helper()
	h := makeBlake3Hash256()
	ns, _ = NewSeed256(1024, h)
	ds1, _ = NewSeed256(1024, h)
	ds2, _ = NewSeed256(1024, h)
	ds3, _ = NewSeed256(1024, h)
	ss1, _ = NewSeed256(1024, h)
	ss2, _ = NewSeed256(1024, h)
	ss3, _ = NewSeed256(1024, h)
	if ns == nil || ds1 == nil || ds2 == nil || ds3 == nil || ss1 == nil || ss2 == nil || ss3 == nil {
		t.Fatalf("aliasFixture3x256: nil seed")
	}
	return
}

// aliasFixture3x512 builds a deterministic Triple Ouroboros 512-bit seed
// septuple via BLAKE2b-512.
func aliasFixture3x512(t *testing.T) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed512) {
	t.Helper()
	h := makeBlake2bHash512()
	ns, _ = NewSeed512(1024, h)
	ds1, _ = NewSeed512(1024, h)
	ds2, _ = NewSeed512(1024, h)
	ds3, _ = NewSeed512(1024, h)
	ss1, _ = NewSeed512(1024, h)
	ss2, _ = NewSeed512(1024, h)
	ss3, _ = NewSeed512(1024, h)
	if ns == nil || ds1 == nil || ds2 == nil || ds3 == nil || ss1 == nil || ss2 == nil || ss3 == nil {
		t.Fatalf("aliasFixture3x512: nil seed")
	}
	return
}

// TestAliasesRoundtrip exercises every short-name alias over a 4 KiB
// deterministic plaintext. The tampering-resistance side is covered by
// TestAliasesTampered.
func TestAliasesRoundtrip(t *testing.T) {
	pt := deterministicPlaintext()

	// --- 128-bit Triple ---
	t.Run("EncryptAuth3x128_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x128(t)
		ct, err := EncryptAuth3x128(ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x128: %v", err)
		}
		got, err := DecryptAuth3x128(ns, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc)
		if err != nil {
			t.Fatalf("DecryptAuth3x128: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	t.Run("EncryptAuth3x128Cfg_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x128(t)
		cfg := SnapshotGlobals()
		ct, err := EncryptAuth3x128Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x128Cfg: %v", err)
		}
		got, err := DecryptAuth3x128Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc)
		if err != nil {
			t.Fatalf("DecryptAuth3x128Cfg: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	// --- 256-bit Triple ---
	t.Run("EncryptAuth3x256_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x256(t)
		ct, err := EncryptAuth3x256(ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x256: %v", err)
		}
		got, err := DecryptAuth3x256(ns, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc)
		if err != nil {
			t.Fatalf("DecryptAuth3x256: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	t.Run("EncryptAuth3x256Cfg_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x256(t)
		cfg := SnapshotGlobals()
		ct, err := EncryptAuth3x256Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x256Cfg: %v", err)
		}
		got, err := DecryptAuth3x256Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc)
		if err != nil {
			t.Fatalf("DecryptAuth3x256Cfg: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	// --- 512-bit Triple ---
	t.Run("EncryptAuth3x512_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x512(t)
		ct, err := EncryptAuth3x512(ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x512: %v", err)
		}
		got, err := DecryptAuth3x512(ns, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc)
		if err != nil {
			t.Fatalf("DecryptAuth3x512: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	t.Run("EncryptAuth3x512Cfg_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x512(t)
		cfg := SnapshotGlobals()
		ct, err := EncryptAuth3x512Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x512Cfg: %v", err)
		}
		got, err := DecryptAuth3x512Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc)
		if err != nil {
			t.Fatalf("DecryptAuth3x512Cfg: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})
}

// flipMidByte returns a copy of ct with one byte at offset len(ct)/2
// flipped (XOR 0xFF). The deterministic offset keeps tampering failures
// reproducible across test runs.
func flipMidByte(ct []byte) []byte {
	out := make([]byte, len(ct))
	copy(out, ct)
	if len(out) == 0 {
		return out
	}
	out[len(out)/2] ^= 0xFF
	return out
}

// TestAliasesTampered verifies that every encrypt-side alias produces a
// ciphertext whose mid-byte flip is rejected by the matching decrypt
// alias. Each subtest exercises one (encrypt, decrypt) alias pair.
func TestAliasesTampered(t *testing.T) {
	pt := deterministicPlaintext()

	// --- 128-bit Triple ---
	t.Run("EncryptAuth3x128_Tampered", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x128(t)
		ct, err := EncryptAuth3x128(ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x128: %v", err)
		}
		if _, err := DecryptAuth3x128(ns, d1, d2, d3, s1, s2, s3, flipMidByte(ct), simpleMACFunc); err == nil {
			t.Fatalf("DecryptAuth3x128: expected error on tampered ciphertext")
		}
	})

	t.Run("EncryptAuth3x128Cfg_Tampered", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x128(t)
		cfg := SnapshotGlobals()
		ct, err := EncryptAuth3x128Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x128Cfg: %v", err)
		}
		if _, err := DecryptAuth3x128Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, flipMidByte(ct), simpleMACFunc); err == nil {
			t.Fatalf("DecryptAuth3x128Cfg: expected error on tampered ciphertext")
		}
	})

	// --- 256-bit Triple ---
	t.Run("EncryptAuth3x256_Tampered", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x256(t)
		ct, err := EncryptAuth3x256(ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x256: %v", err)
		}
		if _, err := DecryptAuth3x256(ns, d1, d2, d3, s1, s2, s3, flipMidByte(ct), simpleMACFunc); err == nil {
			t.Fatalf("DecryptAuth3x256: expected error on tampered ciphertext")
		}
	})

	t.Run("EncryptAuth3x256Cfg_Tampered", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x256(t)
		cfg := SnapshotGlobals()
		ct, err := EncryptAuth3x256Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x256Cfg: %v", err)
		}
		if _, err := DecryptAuth3x256Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, flipMidByte(ct), simpleMACFunc); err == nil {
			t.Fatalf("DecryptAuth3x256Cfg: expected error on tampered ciphertext")
		}
	})

	// --- 512-bit Triple ---
	t.Run("EncryptAuth3x512_Tampered", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x512(t)
		ct, err := EncryptAuth3x512(ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x512: %v", err)
		}
		if _, err := DecryptAuth3x512(ns, d1, d2, d3, s1, s2, s3, flipMidByte(ct), simpleMACFunc); err == nil {
			t.Fatalf("DecryptAuth3x512: expected error on tampered ciphertext")
		}
	})

	t.Run("EncryptAuth3x512Cfg_Tampered", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x512(t)
		cfg := SnapshotGlobals()
		ct, err := EncryptAuth3x512Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt, simpleMACFunc)
		if err != nil {
			t.Fatalf("EncryptAuth3x512Cfg: %v", err)
		}
		if _, err := DecryptAuth3x512Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, flipMidByte(ct), simpleMACFunc); err == nil {
			t.Fatalf("DecryptAuth3x512Cfg: expected error on tampered ciphertext")
		}
	})
}

// TestEncrypt3xCfgRoundtrip exercises the non-authenticated *Cfg encrypt
// + decrypt helpers across all three widths in Triple Ouroboros mode.
// The companion EncryptAuth*Cfg helpers are already covered by
// TestAliasesRoundtrip; this test closes the parallel set for the
// plain (no-MAC) Triple Ouroboros API.
func TestEncrypt3xCfgRoundtrip(t *testing.T) {
	pt := deterministicPlaintext()

	// --- 128-bit Triple ---
	t.Run("Encrypt3x128Cfg_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x128(t)
		cfg := SnapshotGlobals()
		ct, err := Encrypt3x128Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg: %v", err)
		}
		got, err := Decrypt3x128Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatalf("Decrypt3x128Cfg: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	// --- 256-bit Triple ---
	t.Run("Encrypt3x256Cfg_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x256(t)
		cfg := SnapshotGlobals()
		ct, err := Encrypt3x256Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatalf("Encrypt3x256Cfg: %v", err)
		}
		got, err := Decrypt3x256Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatalf("Decrypt3x256Cfg: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})

	// --- 512-bit Triple ---
	t.Run("Encrypt3x512Cfg_Roundtrip", func(t *testing.T) {
		ns, d1, d2, d3, s1, s2, s3 := aliasFixture3x512(t)
		cfg := SnapshotGlobals()
		ct, err := Encrypt3x512Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatalf("Encrypt3x512Cfg: %v", err)
		}
		got, err := Decrypt3x512Cfg(cfg, ns, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatalf("Decrypt3x512Cfg: %v", err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("plaintext mismatch (len got=%d want=%d)", len(got), len(pt))
		}
	})
}
