package hashes

import (
	"testing"

	"github.com/everanium/itb"
)

// TestAreion256DigestDependsOnEveryByte locks in the CBC-MAC chained
// absorb fix for Areion-SoEM-256. The previous closure copy-truncated
// `data` to the SoEM-256 input width (32 bytes), so anything past byte
// 31 was silently dropped. Under SetNonceBits(256) the resulting buf
// shape is 36 bytes (4 blockIdx + 32 nonce) — the last 4 nonce bytes
// were lost. Under SetNonceBits(512) the resulting buf shape is 68
// bytes — 36 nonce bytes were lost. The new chained absorb feeds
// every input byte into the digest regardless of length.
//
// The test runs at three input lengths matching the three
// nonce-bit configurations and confirms that flipping any single
// byte changes the digest.
func TestAreion256DigestDependsOnEveryByte(t *testing.T) {
	hashFn, _, _ := Areion256Pair()
	seed := [4]uint64{0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0}

	for _, n := range []int{20, 36, 68} {
		base := make([]byte, n)
		for i := range base {
			base[i] = byte(i)
		}
		baseDigest := hashFn(base, seed)

		for i := 0; i < n; i++ {
			alt := append([]byte(nil), base...)
			alt[i] ^= 0x01
			altDigest := hashFn(alt, seed)
			if baseDigest == altDigest {
				t.Errorf("Areion-SoEM-256 len=%d byte[%d] flip did not "+
					"change digest (base=%x, alt=%x) — input truncation regression",
					n, i, baseDigest, altDigest)
			}
		}
	}
}

// TestAreion512DigestDependsOnEveryByte: same regression test for the
// 512-bit variant. SoEM-512 input width is 64 bytes; pre-fix this
// silently dropped bytes past offset 64 (so SetNonceBits(512) lost
// the last 4 nonce bytes). The new chained absorb covers every byte
// at every nonce-bit configuration.
func TestAreion512DigestDependsOnEveryByte(t *testing.T) {
	hashFn, _, _ := Areion512Pair()
	seed := [8]uint64{
		0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0,
		0x0FEDCBA9, 0x87654321, 0xBABEFACE, 0xFEEDFACE,
	}

	for _, n := range []int{20, 36, 68} {
		base := make([]byte, n)
		for i := range base {
			base[i] = byte(i)
		}
		baseDigest := hashFn(base, seed)

		for i := 0; i < n; i++ {
			alt := append([]byte(nil), base...)
			alt[i] ^= 0x01
			altDigest := hashFn(alt, seed)
			if baseDigest == altDigest {
				t.Errorf("Areion-SoEM-512 len=%d byte[%d] flip did not "+
					"change digest (base=%x, alt=%x) — input truncation regression",
					n, i, baseDigest, altDigest)
			}
		}
	}
}

// TestAreion256BatchedParityWithSingle confirms that the 4-way
// batched dispatch produces the same digest as four single-call
// dispatches across a non-trivial input. The chain step has to
// run in lock-step between the single and batched code paths;
// any divergence (different chunk size, different state init,
// different round count) would surface here.
func TestAreion256BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := Areion256Pair()
	if batched == nil {
		t.Skip("batched arm unavailable")
	}

	seeds := [4][4]uint64{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{0xA, 0xB, 0xC, 0xD},
		{0x1234, 0x5678, 0x9ABC, 0xDEF0},
	}
	// 36-byte input — exercises the 2-round chain.
	var data [4][]byte
	for lane := 0; lane < 4; lane++ {
		buf := make([]byte, 36)
		for i := range buf {
			buf[i] = byte(lane*100 + i)
		}
		data[lane] = buf
	}

	gotBatched := batched(&data, seeds)
	for lane := 0; lane < 4; lane++ {
		gotSingle := single(data[lane], seeds[lane])
		if gotBatched[lane] != gotSingle {
			t.Errorf("lane %d batched/single mismatch:\n  batched=%x\n  single=%x",
				lane, gotBatched[lane], gotSingle)
		}
	}
}

// TestAreion512BatchedParityWithSingle: same parity check for the
// 512-bit variant at 68-byte input, exercising the 2-round chain
// (only the 512-bit nonce config triggers >1 round on Areion-512).
func TestAreion512BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := Areion512Pair()
	if batched == nil {
		t.Skip("batched arm unavailable")
	}

	seeds := [4][8]uint64{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
		{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		{0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0xFEED, 0xFACE, 0xC0DE, 0xBABE},
	}
	var data [4][]byte
	for lane := 0; lane < 4; lane++ {
		buf := make([]byte, 68)
		for i := range buf {
			buf[i] = byte((lane * 200) + i)
		}
		data[lane] = buf
	}

	gotBatched := batched(&data, seeds)
	for lane := 0; lane < 4; lane++ {
		gotSingle := single(data[lane], seeds[lane])
		if gotBatched[lane] != gotSingle {
			t.Errorf("lane %d batched/single mismatch:\n  batched=%x\n  single=%x",
				lane, gotBatched[lane], gotSingle)
		}
	}
}

// TestAreionEmptyVsShortDistinct: empty input, 1-byte input, and
// 2-byte input must produce distinct digests. The length-tag prefix
// in the initial state is what guarantees this; without it,
// (empty, 1-byte zero, 2-byte zero) would all encrypt the same
// initial-state-of-zeros and collide.
func TestAreionEmptyVsShortDistinct(t *testing.T) {
	hash256, _, _ := Areion256Pair()
	seed := [4]uint64{0x42, 0x43, 0x44, 0x45}

	d0 := hash256([]byte{}, seed)
	d1 := hash256([]byte{0}, seed)
	d2 := hash256([]byte{0, 0}, seed)
	if d0 == d1 || d1 == d2 || d0 == d2 {
		t.Errorf("Areion-256 length tag missing: empty=%x 1byte=%x 2byte=%x",
			d0, d1, d2)
	}

	hash512, _, _ := Areion512Pair()
	seed8 := [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	d0v := hash512([]byte{}, seed8)
	d1v := hash512([]byte{0}, seed8)
	d2v := hash512([]byte{0, 0}, seed8)
	if d0v == d1v || d1v == d2v || d0v == d2v {
		t.Errorf("Areion-512 length tag missing: empty=%x 1byte=%x 2byte=%x",
			d0v, d1v, d2v)
	}
}

// TestAreionEndToEndItb confirms the chain-rewritten Areion factories
// still round-trip through the full ITB pipeline (Encrypt → Decrypt)
// at every supported ITB key width, exercising the per-pixel hot path
// that called into the broken truncation in production.
func TestAreionEndToEndItb(t *testing.T) {
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	for _, name := range []string{"areion256", "areion512"} {
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(name+"/"+itoa(keyBits), func(t *testing.T) {
				switch name {
				case "areion256":
					ns, ds, ss := mkAreion256Trio(t, keyBits)
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
				case "areion512":
					ns, ds, ss := mkAreion512Trio(t, keyBits)
					ct, err := itb.Encrypt512(ns, ds, ss, plaintext)
					if err != nil {
						t.Fatalf("Encrypt512: %v", err)
					}
					pt, err := itb.Decrypt512(ns, ds, ss, ct)
					if err != nil {
						t.Fatalf("Decrypt512: %v", err)
					}
					if string(pt) != string(plaintext) {
						t.Fatalf("plaintext mismatch")
					}
				}
			})
		}
	}
}

func mkAreion256Trio(t *testing.T, keyBits int) (*itb.Seed256, *itb.Seed256, *itb.Seed256) {
	t.Helper()
	mk := func() *itb.Seed256 {
		h, b, _ := Areion256Pair()
		s, err := itb.NewSeed256(keyBits, h)
		if err != nil {
			t.Fatalf("NewSeed256: %v", err)
		}
		s.BatchHash = b
		return s
	}
	return mk(), mk(), mk()
}

func mkAreion512Trio(t *testing.T, keyBits int) (*itb.Seed512, *itb.Seed512, *itb.Seed512) {
	t.Helper()
	mk := func() *itb.Seed512 {
		h, b, _ := Areion512Pair()
		s, err := itb.NewSeed512(keyBits, h)
		if err != nil {
			t.Fatalf("NewSeed512: %v", err)
		}
		s.BatchHash = b
		return s
	}
	return mk(), mk(), mk()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}
