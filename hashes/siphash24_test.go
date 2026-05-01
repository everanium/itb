package hashes

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
)

// TestSipHash24BatchedParityWithSingle confirms that the 4-way
// batched dispatch returned by SipHash24Pair produces the same
// digest as four single-call dispatches across all three ITB
// SetNonceBits buf shapes (20 / 36 / 68 bytes). Mirrors the
// AES-CMAC equivalent — the SipHash chain has to run in lock-step
// between the two dispatch paths, and any divergence (different
// state init, different lenTag fold in the padded final block,
// different finalization XOR sequence) would surface here.
func TestSipHash24BatchedParityWithSingle(t *testing.T) {
	single, batched := SipHash24Pair()
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

// TestSipHash24MakePairReturnsBatched verifies that the FFI-facing
// Make128Pair entry point returns a non-nil batched arm for
// siphash24. Without this wire-up, the C ABI / Python FFI / Go
// callers would fall back to per-pixel dispatch even though the
// ZMM-batched ARX kernel is available.
func TestSipHash24MakePairReturnsBatched(t *testing.T) {
	_, b, _, err := Make128Pair("siphash24")
	if err != nil {
		t.Fatalf("Make128Pair(siphash24): %v", err)
	}
	if b == nil {
		t.Fatal("Make128Pair(siphash24) returned nil batched arm — FFI will fall back to per-pixel dispatch")
	}
}

// TestSipHash24MakePairParity checks that the single and batched
// arms returned by Make128Pair produce bit-exact identical digests
// when the batched arm is fed four copies of the same per-lane
// input.
func TestSipHash24MakePairParity(t *testing.T) {
	single, batched, _, err := Make128Pair("siphash24")
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

// TestSipHash24MakePairRejectsKey verifies that Make128Pair rejects
// any caller-supplied fixed key for siphash24 — SipHash has no
// internal fixed key (its keying material is the per-call seed
// components), so passing a key is an error. Same contract as
// Make128("siphash24", key) which already rejects.
func TestSipHash24MakePairRejectsKey(t *testing.T) {
	_, _, _, err := Make128Pair("siphash24", make([]byte, 16))
	if err == nil {
		t.Error("Make128Pair(siphash24, key) should fail; got nil error")
	}
}

// TestSipHash24MakePairITBRoundtrip exercises the full Make128Pair
// → Seed128.BatchHash → Encrypt128/Decrypt128 path on a non-trivial
// plaintext. The Seed.BatchHash field is populated from the
// Make128Pair batched arm; itb.processChunk128 routes through the
// batched dispatch when both noiseSeed.BatchHash and
// dataSeed.BatchHash are non-nil. A successful roundtrip with
// byte-equal plaintext confirms (a) the registry dispatch wires
// the batched arm into the seed correctly, (b) the W128 batched
// scaffolding routes the dispatch correctly, and (c) the batched
// arm produces lane-correct outputs at every chunk boundary.
func TestSipHash24MakePairITBRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	mkSeed := func() *itb.Seed128 {
		h, b, _, err := Make128Pair("siphash24")
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
		t.Fatal("plaintext mismatch after Encrypt128/Decrypt128 via siphash24 batched dispatch")
	}
}
