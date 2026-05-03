package hashes

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/chacha20asm"
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

// TestChaCha20256BatchedParityWithSingle confirms that the 4-way
// batched dispatch returned by ChaCha20256Pair produces the same
// digest as four single-call dispatches across all three ITB
// SetNonceBits buf shapes (20 / 36 / 68 bytes). Mirrors
// TestBLAKE3256BatchedParityWithSingle — the chain-absorb step has
// to run in lock-step between the two dispatch paths, and any
// divergence (different per-call key XOR, different state init,
// different absorb sequence, different keystream consumption order
// across compression boundaries) would surface here.
func TestChaCha20256BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := ChaCha20256Pair()
	if batched == nil {
		t.Skip("batched arm unavailable")
	}

	seeds := [4][4]uint64{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{0xA, 0xB, 0xC, 0xD},
		{0x1234, 0x5678, 0x9ABC, 0xDEF0},
	}

	for _, dataLen := range []int{20, 36, 68} {
		var data [4][]byte
		for lane := 0; lane < 4; lane++ {
			buf := make([]byte, dataLen)
			for i := range buf {
				buf[i] = byte(lane*100 + i)
			}
			data[lane] = buf
		}

		gotBatched := batched(&data, seeds)
		for lane := 0; lane < 4; lane++ {
			gotSingle := single(data[lane], seeds[lane])
			if gotBatched[lane] != gotSingle {
				t.Errorf("len=%d lane=%d batched/single mismatch:\n  batched=%x\n  single =%x",
					dataLen, lane, gotBatched[lane], gotSingle)
			}
		}
	}
}

// TestChaCha20MakePairBatchedFollowsAsmEngagement verifies the
// asm-conditional contract of Make256Pair for chacha20 — non-nil
// batched when AVX-512 fused chain-absorb is engaged, nil batched
// when the asm path is not reachable so process_cgo's nil-fallback
// drives 4 single-call dispatches through the underlying ChaCha20
// stream-cipher path directly.
func TestChaCha20MakePairBatchedFollowsAsmEngagement(t *testing.T) {
	_, b, _, err := Make256Pair("chacha20")
	if err != nil {
		t.Fatalf("Make256Pair(chacha20): %v", err)
	}
	if chacha20asm.HasAVX512Fused {
		if b == nil {
			t.Fatal("Make256Pair(chacha20) returned nil batched arm despite asm engaged — FFI will fall back to per-pixel dispatch")
		}
	} else {
		if b != nil {
			t.Fatal("Make256Pair(chacha20) returned non-nil batched arm without asm engaged — the scalar 4-lane wrapper is slower than process_cgo's nil-fallback")
		}
	}
}

// TestChaCha20MakePairParity checks that the single and batched arms
// returned by Make256Pair, both bound to the same fixed key, produce
// bit-exact identical digests when the batched arm is fed four
// copies of the same per-lane input.
func TestChaCha20MakePairParity(t *testing.T) {
	single, batched, _, err := Make256Pair("chacha20")
	if err != nil {
		t.Fatalf("Make256Pair: %v", err)
	}
	if batched == nil {
		t.Skip("batched arm unavailable")
	}
	seeds := [4][4]uint64{
		{0x11, 0x22, 0x33, 0x44},
		{0x55, 0x66, 0x77, 0x88},
		{0x99, 0xAA, 0xBB, 0xCC},
		{0xDD, 0xEE, 0xFF, 0x00},
	}
	for _, dataLen := range []int{20, 36, 68} {
		var data [4][]byte
		for lane := 0; lane < 4; lane++ {
			buf := make([]byte, dataLen)
			for i := range buf {
				buf[i] = byte(0xc0 + lane*0x10 + i)
			}
			data[lane] = buf
		}
		gotBatched := batched(&data, seeds)
		for lane := 0; lane < 4; lane++ {
			gotSingle := single(data[lane], seeds[lane])
			if gotBatched[lane] != gotSingle {
				t.Errorf("len=%d lane=%d Make256Pair single/batched mismatch:\n  batched=%x\n  single =%x",
					dataLen, lane, gotBatched[lane], gotSingle)
			}
		}
	}
}

// TestChaCha20MakePairExplicitKey verifies that Make256Pair accepts
// an explicit caller-supplied key and that the returned pair is
// bit-exact deterministic — calling Make256Pair twice with the
// same key produces identical digests (the persistence-restore
// contract the FFI layer surfaces as ITB_HashRestore).
func TestChaCha20MakePairExplicitKey(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	s1, b1, retKey1, err := Make256Pair("chacha20", key[:])
	if err != nil {
		t.Fatalf("Make256Pair attempt 1: %v", err)
	}
	if !bytes.Equal(retKey1, key[:]) {
		t.Fatalf("returned key != supplied key (got %x, want %x)", retKey1, key[:])
	}
	s2, b2, retKey2, err := Make256Pair("chacha20", key[:])
	if err != nil {
		t.Fatalf("Make256Pair attempt 2: %v", err)
	}
	if !bytes.Equal(retKey2, key[:]) {
		t.Fatalf("attempt-2 returned key != supplied key")
	}

	seed := [4]uint64{0xabcd, 0x1234, 0x5678, 0x9abc}
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	if s1(data, seed) != s2(data, seed) {
		t.Error("single-arm output diverges across two same-key Make256Pair calls")
	}

	if b1 != nil && b2 != nil {
		seeds := [4][4]uint64{seed, seed, seed, seed}
		d := [4][]byte{data, data, data, data}
		r1 := b1(&d, seeds)
		r2 := b2(&d, seeds)
		if r1 != r2 {
			t.Error("batched-arm output diverges across two same-key Make256Pair calls")
		}
	}
}

// TestChaCha20MakePairBadKeySize confirms Make256Pair rejects
// caller-supplied keys whose size does not match the ChaCha20
// native 32-byte key length.
func TestChaCha20MakePairBadKeySize(t *testing.T) {
	_, _, _, err := Make256Pair("chacha20", make([]byte, 31))
	if err == nil {
		t.Error("Make256Pair(chacha20, 31-byte key) should fail; got nil error")
	}
	_, _, _, err = Make256Pair("chacha20", make([]byte, 33))
	if err == nil {
		t.Error("Make256Pair(chacha20, 33-byte key) should fail; got nil error")
	}
}

// TestChaCha20MakePairITBRoundtrip exercises the full Make256Pair →
// Seed256.BatchHash → Encrypt/Decrypt path on a non-trivial
// plaintext. The Seed.BatchHash field is populated from the
// Make256Pair batched arm; itb.processChunk routes through the
// batched dispatch when both noiseSeed.BatchHash and
// dataSeed.BatchHash are non-nil. A successful roundtrip with
// byte-equal plaintext confirms (a) the registry dispatch wires
// the batched arm into the seed correctly, and (b) the batched
// arm produces lane-correct outputs at every chunk boundary.
func TestChaCha20MakePairITBRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ns, err := newSeed256("chacha20", 1024)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := newSeed256("chacha20", 1024)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := newSeed256("chacha20", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if ns.BatchHash == nil || ds.BatchHash == nil {
		t.Skip("batched arm unavailable on this host")
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
		t.Fatal("plaintext mismatch after Encrypt256/Decrypt256 via chacha20 batched dispatch")
	}
}
