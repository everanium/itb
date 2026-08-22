package itb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	crand "crypto/rand"
	"math/rand"
	"sync"
	"testing"

	"github.com/dchest/siphash"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

// sipHash128 is a HashFunc128 wrapper around the SipHash-2-4 primitive.
// Used by the alias roundtrip fixtures as the 128-bit reference hash.
func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

// simpleMACFunc is a deterministic ~64-bit MAC over the input. Not
// cryptographic; used only as a fixture in the alias-forwarding tests
// where the tag round-trip is the assertion, not the MAC's own
// strength.
func simpleMACFunc(data []byte) []byte {
	h := uint64(0x736f6d6570736575)
	for _, b := range data {
		h = h*131 + uint64(b)
	}
	tag := make([]byte, 8)
	binary.LittleEndian.PutUint64(tag, h)
	return tag
}

// makeBlake3Hash256 returns a HashFunc256 backed by BLAKE3 in keyed
// mode. Used by the 256-bit alias fixtures.
func makeBlake3Hash256() HashFunc256 {
	var key [32]byte
	if _, err := crand.Read(key[:]); err != nil {
		panic(err)
	}
	template, _ := blake3.NewKeyed(key[:])
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		h := template.Clone()
		const seedInjectBytes = 32
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		for i := 0; i < 4; i++ {
			off := i * 8
			binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
		}
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)
		var buf [32]byte
		h.Sum(buf[:0])
		return [4]uint64{
			binary.LittleEndian.Uint64(buf[0:]),
			binary.LittleEndian.Uint64(buf[8:]),
			binary.LittleEndian.Uint64(buf[16:]),
			binary.LittleEndian.Uint64(buf[24:]),
		}
	}
}

// testHash256 wraps SipHash-2-4 into a 256-bit interface for testing.
func testHash256(data []byte, seed [4]uint64) [4]uint64 {
	lo0, hi0 := siphash.Hash128(seed[0], seed[1], data)
	lo1, hi1 := siphash.Hash128(seed[2], seed[3], data)
	return [4]uint64{lo0, hi0, lo1, hi1}
}

// testHash512 wraps SipHash-2-4 into a 512-bit interface for testing.
func testHash512(data []byte, seed [8]uint64) [8]uint64 {
	lo0, hi0 := siphash.Hash128(seed[0], seed[1], data)
	lo1, hi1 := siphash.Hash128(seed[2], seed[3], data)
	lo2, hi2 := siphash.Hash128(seed[4], seed[5], data)
	lo3, hi3 := siphash.Hash128(seed[6], seed[7], data)
	return [8]uint64{lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3}
}

// generateData returns n bytes of crypto/rand output — the shared
// plaintext-fabrication helper the root-package tests rely on.
func generateData(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// makeTripleSeed128 constructs 3 independent 128-bit seeds sharing one
// hash function. Legacy 3-seed fixture used by pre-Triple test code.
func makeTripleSeed128(bits int, h HashFunc128) (noise, data, start *Seed128) {
	noise, _ = NewSeed128(bits, h)
	data, _ = NewSeed128(bits, h)
	start, _ = NewSeed128(bits, h)
	return
}

// makeTripleSeed256 — 256-bit counterpart of [makeTripleSeed128].
func makeTripleSeed256(bits int, h HashFunc256) (noise, data, start *Seed256) {
	noise, _ = NewSeed256(bits, h)
	data, _ = NewSeed256(bits, h)
	start, _ = NewSeed256(bits, h)
	return
}

// makeTripleSeed512 — 512-bit counterpart of [makeTripleSeed128].
func makeTripleSeed512(bits int, h HashFunc512) (noise, data, start *Seed512) {
	noise, _ = NewSeed512(bits, h)
	data, _ = NewSeed512(bits, h)
	start, _ = NewSeed512(bits, h)
	return
}

// makeAreionSoEM256 returns the single-call HashFunc256 built from the
// Areion-SoEM-256 primitive. Kept for legacy test fixtures that
// pre-date the batched dispatch and only need a single-arm hash.
func makeAreionSoEM256() HashFunc256 {
	h, _, _ := MakeAreionSoEM256Hash()
	return h
}

// makeAreionSoEM512 is the 512-bit counterpart of [makeAreionSoEM256].
func makeAreionSoEM512() HashFunc512 {
	h, _, _ := MakeAreionSoEM512Hash()
	return h
}

// withLockSoup engages the process-global Lock Soup overlay for the
// duration of the test / subtest, restoring the prior mode via
// t.Cleanup. Preferred over manual defer because it composes with
// t.Run subtests.
func withLockSoup(t testing.TB) {
	t.Helper()
	prev := GetLockSoup()
	SetLockSoup(1)
	t.Cleanup(func() {
		SetLockSoup(prev)
	})
}

// newHMACBlake3Bench returns a keyed-BLAKE3 [MACFunc] backed by a
// process-scoped 32-byte fixed key. Used by streaming AEAD benchmark
// harnesses that need a stable MAC without a per-iteration setup
// cost.
func newHMACBlake3Bench(key []byte) MACFunc {
	if len(key) != 32 {
		panic("newHMACBlake3Bench: key must be 32 bytes")
	}
	template, err := blake3.NewKeyed(key)
	if err != nil {
		panic(err)
	}
	return func(data []byte) []byte {
		h := template.Clone()
		h.Write(data)
		var out [32]byte
		h.Sum(out[:0])
		return append([]byte(nil), out[:]...)
	}
}

// makeAreionSoEM512Pair returns both the single-call and 4-way batched
// closures for the Areion-SoEM-512 primitive. Test fixtures that need
// the batched arm (BatchHash slot on Seed512) call this instead of
// [makeAreionSoEM512].
func makeAreionSoEM512Pair() (HashFunc512, BatchHashFunc512) {
	h, b, _ := MakeAreionSoEM512Hash()
	return h, b
}

// makeBlake2bHash512 returns a HashFunc512 backed by BLAKE2b-512 in
// keyed mode. Used by the 512-bit alias fixtures.
func makeBlake2bHash512() HashFunc512 {
	var key [64]byte
	if _, err := crand.Read(key[:]); err != nil {
		panic(err)
	}
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [8]uint64) [8]uint64 {
		h, err := blake2b.New512(key[:])
		if err != nil {
			panic(err)
		}
		const seedInjectBytes = 64
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		for i := 0; i < 8; i++ {
			off := i * 8
			binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
		}
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)
		var buf [64]byte
		h.Sum(buf[:0])
		var out [8]uint64
		for i := 0; i < 8; i++ {
			out[i] = binary.LittleEndian.Uint64(buf[i*8:])
		}
		return out
	}
}

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
