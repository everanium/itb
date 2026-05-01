package hashes

import (
	"bytes"
	"crypto/rand"
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
		fn, _ := AESCMAC()
		s, err := itb.NewSeed128(keyBits, fn)
		if err != nil {
			t.Fatalf("NewSeed128: %v", err)
		}
		return s
	}
	return mk(), mk(), mk()
}

// TestAESCMAC128BatchedParityWithSingle confirms that the 4-way
// batched dispatch returned by AESCMACPair produces the same digest
// as four single-call dispatches across all three ITB SetNonceBits
// buf shapes (20 / 36 / 68 bytes). Mirrors the W256 ports'
// equivalent test — the AES-CMAC chain has to run in lock-step
// between the two dispatch paths, and any divergence (different
// state init, different lenTag fold, different per-round absorb
// order) would surface here.
func TestAESCMAC128BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := AESCMACPair()
	if batched == nil {
		t.Skip("batched arm unavailable")
	}

	seeds := [4][2]uint64{
		{1, 2},
		{3, 4},
		{0xA, 0xB},
		{0x1234, 0x5678},
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
			lo, hi := single(data[lane], seeds[lane][0], seeds[lane][1])
			if gotBatched[lane][0] != lo || gotBatched[lane][1] != hi {
				t.Errorf("len=%d lane=%d batched/single mismatch:\n  batched=%x\n  single =(%x,%x)",
					dataLen, lane, gotBatched[lane], lo, hi)
			}
		}
	}
}

// TestAESCMACMakePairReturnsBatched verifies that the FFI-facing
// Make128Pair entry point returns a non-nil batched arm for
// aescmac. Without this wire-up, the C ABI / Python FFI / Go
// callers would fall back to per-pixel dispatch even though the
// ZMM-batched VAES kernel is available.
func TestAESCMACMakePairReturnsBatched(t *testing.T) {
	_, b, _, err := Make128Pair("aescmac")
	if err != nil {
		t.Fatalf("Make128Pair(aescmac): %v", err)
	}
	if b == nil {
		t.Fatal("Make128Pair(aescmac) returned nil batched arm — FFI will fall back to per-pixel dispatch")
	}
}

// TestAESCMACMakePairParity checks that the single and batched arms
// returned by Make128Pair, both bound to the same fixed key,
// produce bit-exact identical digests.
func TestAESCMACMakePairParity(t *testing.T) {
	single, batched, _, err := Make128Pair("aescmac")
	if err != nil {
		t.Fatalf("Make128Pair: %v", err)
	}
	if batched == nil {
		t.Skip("batched arm unavailable")
	}
	seeds := [4][2]uint64{
		{0x11, 0x22},
		{0x33, 0x44},
		{0x55, 0x66},
		{0x77, 0x88},
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
			lo, hi := single(data[lane], seeds[lane][0], seeds[lane][1])
			if gotBatched[lane][0] != lo || gotBatched[lane][1] != hi {
				t.Errorf("len=%d lane=%d Make128Pair single/batched mismatch:\n  batched=%x\n  single =(%x,%x)",
					dataLen, lane, gotBatched[lane], lo, hi)
			}
		}
	}
}

// TestAESCMACMakePairExplicitKey verifies that Make128Pair accepts
// an explicit caller-supplied key and that the returned pair is
// bit-exact deterministic — calling Make128Pair twice with the
// same key produces identical digests (the persistence-restore
// contract the FFI layer surfaces as ITB_HashRestore).
func TestAESCMACMakePairExplicitKey(t *testing.T) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	s1, b1, retKey1, err := Make128Pair("aescmac", key[:])
	if err != nil {
		t.Fatalf("Make128Pair attempt 1: %v", err)
	}
	if !bytes.Equal(retKey1, key[:]) {
		t.Fatalf("returned key != supplied key (got %x, want %x)", retKey1, key[:])
	}
	s2, b2, retKey2, err := Make128Pair("aescmac", key[:])
	if err != nil {
		t.Fatalf("Make128Pair attempt 2: %v", err)
	}
	if !bytes.Equal(retKey2, key[:]) {
		t.Fatalf("attempt-2 returned key != supplied key")
	}

	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	lo1, hi1 := s1(data, 0xabcd, 0x1234)
	lo2, hi2 := s2(data, 0xabcd, 0x1234)
	if lo1 != lo2 || hi1 != hi2 {
		t.Error("single-arm output diverges across two same-key Make128Pair calls")
	}

	if b1 != nil && b2 != nil {
		seeds := [4][2]uint64{{0xabcd, 0x1234}, {0xabcd, 0x1234}, {0xabcd, 0x1234}, {0xabcd, 0x1234}}
		d := [4][]byte{data, data, data, data}
		r1 := b1(&d, seeds)
		r2 := b2(&d, seeds)
		if r1 != r2 {
			t.Error("batched-arm output diverges across two same-key Make128Pair calls")
		}
	}
}

// TestAESCMACMakePairBadKeySize confirms Make128Pair rejects
// caller-supplied keys whose size does not match the AES-128 native
// 16-byte key length.
func TestAESCMACMakePairBadKeySize(t *testing.T) {
	_, _, _, err := Make128Pair("aescmac", make([]byte, 15))
	if err == nil {
		t.Error("Make128Pair(aescmac, 15-byte key) should fail; got nil error")
	}
	_, _, _, err = Make128Pair("aescmac", make([]byte, 17))
	if err == nil {
		t.Error("Make128Pair(aescmac, 17-byte key) should fail; got nil error")
	}
}

// TestAESCMACMakePairITBRoundtrip exercises the full Make128Pair →
// Seed128.BatchHash → Encrypt128/Decrypt128 path on a non-trivial
// plaintext. The Seed.BatchHash field is populated from the
// Make128Pair batched arm; itb.processChunk128 routes through the
// batched dispatch when both noiseSeed.BatchHash and
// dataSeed.BatchHash are non-nil. A successful roundtrip with
// byte-equal plaintext confirms (a) the registry dispatch wires
// the batched arm into the seed correctly, (b) the W128 batched
// scaffolding routes the dispatch correctly, and (c) the batched
// arm produces lane-correct outputs at every chunk boundary.
func TestAESCMACMakePairITBRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	mkSeed := func() *itb.Seed128 {
		h, b, _, err := Make128Pair("aescmac")
		if err != nil {
			t.Fatal(err)
		}
		s, err := itb.NewSeed128(1024, h)
		if err != nil {
			t.Fatal(err)
		}
		if b != nil {
			s.BatchHash = b
		}
		return s
	}
	ns := mkSeed()
	ds := mkSeed()
	ss := mkSeed()
	if ns.BatchHash == nil || ds.BatchHash == nil {
		t.Skip("batched arm unavailable on this host")
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
		t.Fatal("plaintext mismatch after Encrypt128/Decrypt128 via aescmac batched dispatch")
	}
}
