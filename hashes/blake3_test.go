package hashes

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake3asm"
)

// TestBLAKE3256BatchedParityWithSingle confirms that the 4-way
// batched dispatch returned by BLAKE3256Pair produces the same
// digest as four single-call dispatches across all three ITB
// SetNonceBits buf shapes (20 / 36 / 68 bytes). Mirrors
// TestBLAKE2s256BatchedParityWithSingle — the chain-absorb step
// has to run in lock-step between the two dispatch paths, and any
// divergence (different mixed-buffer packing, different state init,
// different round count, different output mixing) would surface
// here.
func TestBLAKE3256BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := BLAKE3256Pair()
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

// TestBLAKE3MakePairBatchedFollowsAsmEngagement verifies the
// asm-conditional contract of the FFI-facing Make256Pair entry
// point for blake3. When the AVX-512 fused chain-absorb path is
// engaged on the host (blake3asm.HasAVX512Fused == true), the
// batched arm must be non-nil so the C ABI / Python FFI layers
// drive per-pixel hashing through the ZMM-batched kernel. When
// the asm path is not engaged (purego build, non-amd64 host, or
// amd64 without AVX-512+VL) the batched arm must be nil so
// process_cgo.go's nil-fallback drives 4 single-call dispatches
// through the upstream zeebo/blake3 path — measurably faster
// than the scalar 4-lane chain-absorb wrapper would be.
func TestBLAKE3MakePairBatchedFollowsAsmEngagement(t *testing.T) {
	_, b, _, err := Make256Pair("blake3")
	if err != nil {
		t.Fatalf("Make256Pair(blake3): %v", err)
	}
	if blake3asm.HasAVX512Fused {
		if b == nil {
			t.Fatal("Make256Pair(blake3) returned nil batched arm despite AVX-512+VL asm engaged — FFI will fall back to per-pixel dispatch")
		}
	} else {
		if b != nil {
			t.Fatal("Make256Pair(blake3) returned non-nil batched arm without asm engaged — the scalar 4-lane wrapper costs more than process_cgo's nil-fallback through 4 single calls")
		}
	}
}

// TestBLAKE3MakePairParity checks that the single and batched arms
// returned by Make256Pair, both bound to the same fixed key,
// produce bit-exact identical digests when the batched arm is fed
// four copies of the same per-lane input.
func TestBLAKE3MakePairParity(t *testing.T) {
	single, batched, _, err := Make256Pair("blake3")
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

// TestBLAKE3MakePairExplicitKey verifies that Make256Pair accepts
// an explicit caller-supplied key and that the returned pair is
// bit-exact deterministic — calling Make256Pair twice with the
// same key produces identical digests (the persistence-restore
// contract the FFI layer surfaces as ITB_HashRestore).
func TestBLAKE3MakePairExplicitKey(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	s1, b1, retKey1, err := Make256Pair("blake3", key[:])
	if err != nil {
		t.Fatalf("Make256Pair attempt 1: %v", err)
	}
	if !bytes.Equal(retKey1, key[:]) {
		t.Fatalf("returned key != supplied key (got %x, want %x)", retKey1, key[:])
	}
	s2, b2, retKey2, err := Make256Pair("blake3", key[:])
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

// TestBLAKE3MakePairBadKeySize confirms Make256Pair rejects
// caller-supplied keys whose size does not match the BLAKE3 native
// 32-byte key length.
func TestBLAKE3MakePairBadKeySize(t *testing.T) {
	_, _, _, err := Make256Pair("blake3", make([]byte, 31))
	if err == nil {
		t.Error("Make256Pair(blake3, 31-byte key) should fail; got nil error")
	}
	_, _, _, err = Make256Pair("blake3", make([]byte, 33))
	if err == nil {
		t.Error("Make256Pair(blake3, 33-byte key) should fail; got nil error")
	}
}

// TestBLAKE3MakePairITBRoundtrip exercises the full Make256Pair →
// Seed256.BatchHash → Encrypt/Decrypt path on a non-trivial
// plaintext. The Seed.BatchHash field is populated from the
// Make256Pair batched arm; itb.processChunk routes through the
// batched dispatch when both noiseSeed.BatchHash and
// dataSeed.BatchHash are non-nil. A successful roundtrip with
// byte-equal plaintext confirms (a) the registry dispatch wires
// the batched arm into the seed correctly, and (b) the batched
// arm produces lane-correct outputs at every chunk boundary.
func TestBLAKE3MakePairITBRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ns, err := newSeed256("blake3", 1024)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := newSeed256("blake3", 1024)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := newSeed256("blake3", 1024)
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
		t.Fatal("plaintext mismatch after Encrypt256/Decrypt256 via blake3 batched dispatch")
	}
}
