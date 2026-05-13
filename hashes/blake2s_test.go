package hashes

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake2sasm"
)

// TestBLAKE2s256BatchedParityWithSingle confirms that the 4-way
// batched dispatch returned by BLAKE2s256Pair produces the same digest
// as four single-call dispatches across all three ITB SetNonceBits buf
// shapes (20 / 36 / 68 bytes). Mirrors TestBLAKE2b256BatchedParityWithSingle
// — the chain-absorb step has to run in lock-step between the two
// dispatch paths, and any divergence (different buf packing, different
// state init, different round count, different output fold) would
// surface here.
func TestBLAKE2s256BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := BLAKE2s256Pair()
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

// TestBLAKE2sMakePairBatchedFollowsAsmEngagement verifies the
// asm-conditional contract of Make256Pair for blake2s — non-nil
// batched when AVX-512 fused chain-absorb is engaged, nil batched
// when the asm path is not reachable so process_cgo's nil-fallback
// drives 4 single-call dispatches through the upstream
// golang.org/x/crypto BLAKE2s asm directly.
func TestBLAKE2sMakePairBatchedFollowsAsmEngagement(t *testing.T) {
	_, b, _, err := Make256Pair("blake2s")
	if err != nil {
		t.Fatalf("Make256Pair(blake2s): %v", err)
	}
	if blake2sasm.HasAVX512Fused {
		if b == nil {
			t.Fatal("Make256Pair(blake2s) returned nil batched arm despite asm engaged — FFI will fall back to per-pixel dispatch")
		}
	} else {
		if b != nil {
			t.Fatal("Make256Pair(blake2s) returned non-nil batched arm without asm engaged — the scalar 4-lane wrapper is slower than process_cgo's nil-fallback")
		}
	}
}

// TestBLAKE2sMakePairParity checks that the single and batched arms
// returned by Make256Pair, both bound to the same fixed key, produce
// bit-exact identical digests when the batched arm is fed four copies
// of the same per-lane input. This is the parity invariant required
// by itb.BatchHashFunc256: every consumer (notably itb.processChunk
// via Seed.BatchHash) assumes single and batched are functionally
// indistinguishable.
func TestBLAKE2sMakePairParity(t *testing.T) {
	single, batched, _, err := Make256Pair("blake2s")
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

// TestBLAKE2sMakePairExplicitKey verifies that Make256Pair accepts an
// explicit caller-supplied key and that the returned pair is bit-exact
// deterministic — calling Make256Pair twice with the same key produces
// identical digests (the persistence-restore contract the FFI layer
// surfaces as ITB_HashRestore).
func TestBLAKE2sMakePairExplicitKey(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	s1, b1, retKey1, err := Make256Pair("blake2s", key[:])
	if err != nil {
		t.Fatalf("Make256Pair attempt 1: %v", err)
	}
	if !bytes.Equal(retKey1, key[:]) {
		t.Fatalf("returned key != supplied key (got %x, want %x)", retKey1, key[:])
	}
	s2, b2, retKey2, err := Make256Pair("blake2s", key[:])
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

// TestBLAKE2sMakePairBadKeySize confirms Make256Pair rejects
// caller-supplied keys whose size does not match the primitive's
// native key length (32 bytes for blake2s). This guards the FFI-
// surfaced ITB_HashRestore path against silent acceptance of
// mismatched persisted keys.
func TestBLAKE2sMakePairBadKeySize(t *testing.T) {
	_, _, _, err := Make256Pair("blake2s", make([]byte, 31))
	if err == nil {
		t.Error("Make256Pair(blake2s, 31-byte key) should fail; got nil error")
	}
	_, _, _, err = Make256Pair("blake2s", make([]byte, 33))
	if err == nil {
		t.Error("Make256Pair(blake2s, 33-byte key) should fail; got nil error")
	}
}

// TestBLAKE2sMakePairITBRoundtrip exercises the full Make256Pair →
// Seed256.BatchHash → Encrypt/Decrypt path on a non-trivial plaintext.
// The Seed.BatchHash field is populated from the Make256Pair batched
// arm; itb.processChunk routes through the batched dispatch when both
// noiseSeed.BatchHash and dataSeed.BatchHash are non-nil. A successful
// roundtrip with byte-equal plaintext confirms (a) the registry
// dispatch wires the batched arm into the seed correctly, and (b) the
// batched arm produces lane-correct outputs at every chunk boundary.
func TestBLAKE2sMakePairITBRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ns, err := newSeed256("blake2s", 1024)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := newSeed256("blake2s", 1024)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := newSeed256("blake2s", 1024)
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
		t.Fatal("plaintext mismatch after Encrypt256/Decrypt256 via blake2s batched dispatch")
	}
}

// TestBLAKE2sSingleArmDirect exercises the BLAKE2s() entry point that
// returns only the single-arm closure (no batched dispatch). Calling
// BLAKE2s(key) followed by BLAKE2s(key) with the same explicit key must
// produce bit-exact identical digests, and the resulting closure must
// be parity-equivalent to lane 0 of BLAKE2s256Pair(key)'s single arm.
func TestBLAKE2sSingleArmDirect(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	h1, retKey1 := BLAKE2s(key)
	if retKey1 != key {
		t.Errorf("BLAKE2s(key) returned key %x, want %x", retKey1, key)
	}
	h2, retKey2 := BLAKE2s(key)
	if retKey2 != key {
		t.Errorf("BLAKE2s(key) attempt 2 returned key %x, want %x", retKey2, key)
	}

	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	seed := [4]uint64{0xabcd, 0x1234, 0x5678, 0x9abc}
	out1 := h1(data, seed)
	out2 := h2(data, seed)
	if out1 != out2 {
		t.Error("BLAKE2s(key): output diverges across two same-key direct calls")
	}

	pairSingle, _, _ := BLAKE2s256Pair(key)
	if out1 != pairSingle(data, seed) {
		t.Error("BLAKE2s(key) and BLAKE2s256Pair(key) single arm produce divergent digests")
	}

	// Random-key path: no argument generates a fresh key and the
	// closure must remain functional.
	hRand, randKey := BLAKE2s()
	if randKey == ([32]byte{}) {
		t.Error("BLAKE2s() returned zero key — random generation failed silently")
	}
	if hRand == nil {
		t.Fatal("BLAKE2s() returned nil closure")
	}
	_ = hRand(data, seed)
}
