package hashes

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake2basm"
)

// TestBLAKE2b256BatchedParityWithSingle confirms that the 4-way
// batched dispatch returned by BLAKE2b256Pair produces the same digest
// as four single-call dispatches across all three ITB SetNonceBits buf
// shapes (20 / 36 / 68 bytes). Mirrors TestAreion256BatchedParityWithSingle
// — the chain-absorb step has to run in lock-step between the two
// dispatch paths, and any divergence (different buf packing, different
// state init, different round count, different output fold) would
// surface here.
func TestBLAKE2b256BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := BLAKE2b256Pair()
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

// TestBLAKE2b512BatchedParityWithSingle: same parity check at the
// 512-bit width. The 68-byte buf shape exercises the two-compression
// path (132-byte buf > 128); 20- and 36-byte are single-compression.
func TestBLAKE2b512BatchedParityWithSingle(t *testing.T) {
	single, batched, _ := BLAKE2b512Pair()
	if batched == nil {
		t.Skip("batched arm unavailable")
	}

	seeds := [4][8]uint64{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
		{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		{0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0xFEED, 0xFACE, 0xC0DE, 0xBABE},
	}

	for _, dataLen := range []int{20, 36, 68} {
		var data [4][]byte
		for lane := 0; lane < 4; lane++ {
			buf := make([]byte, dataLen)
			for i := range buf {
				buf[i] = byte((lane * 200) + i)
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

// TestBLAKE2bMakePairBatchedFollowsAsmEngagement verifies the
// asm-conditional contract of Make256Pair / Make512Pair for the
// blake2b{256,512} primitives — non-nil batched when AVX-512 fused
// chain-absorb is engaged, nil batched when the asm path is not
// reachable so process_cgo's nil-fallback drives 4 single-call
// dispatches through the upstream golang.org/x/crypto BLAKE2b
// asm directly.
func TestBLAKE2bMakePairBatchedFollowsAsmEngagement(t *testing.T) {
	t.Run("blake2b256", func(t *testing.T) {
		_, b, _, err := Make256Pair("blake2b256")
		if err != nil {
			t.Fatalf("Make256Pair(blake2b256): %v", err)
		}
		if blake2basm.HasAVX512Fused {
			if b == nil {
				t.Fatal("Make256Pair(blake2b256) returned nil batched arm despite asm engaged — FFI will fall back to per-pixel dispatch")
			}
		} else {
			if b != nil {
				t.Fatal("Make256Pair(blake2b256) returned non-nil batched arm without asm engaged — the scalar 4-lane wrapper is slower than process_cgo's nil-fallback")
			}
		}
	})
	t.Run("blake2b512", func(t *testing.T) {
		_, b, _, err := Make512Pair("blake2b512")
		if err != nil {
			t.Fatalf("Make512Pair(blake2b512): %v", err)
		}
		if blake2basm.HasAVX512Fused {
			if b == nil {
				t.Fatal("Make512Pair(blake2b512) returned nil batched arm despite asm engaged — FFI will fall back to per-pixel dispatch")
			}
		} else {
			if b != nil {
				t.Fatal("Make512Pair(blake2b512) returned non-nil batched arm without asm engaged — the scalar 4-lane wrapper is slower than process_cgo's nil-fallback")
			}
		}
	})
}

// TestBLAKE2bMakePairParity checks that the single and batched arms
// returned by Make{256,512}Pair, both bound to the same fixed key,
// produce bit-exact identical digests when the batched arm is fed
// four copies of the same per-lane input. This is the parity
// invariant required by itb.BatchHashFunc{256,512}: every consumer
// (notably itb.processChunk via Seed.BatchHash) assumes single and
// batched are functionally indistinguishable.
func TestBLAKE2bMakePairParity(t *testing.T) {
	t.Run("blake2b256", func(t *testing.T) {
		single, batched, _, err := Make256Pair("blake2b256")
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
	})

	t.Run("blake2b512", func(t *testing.T) {
		single, batched, _, err := Make512Pair("blake2b512")
		if err != nil {
			t.Fatalf("Make512Pair: %v", err)
		}
		if batched == nil {
			t.Skip("batched arm unavailable")
		}
		seeds := [4][8]uint64{
			{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			{0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00},
			{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
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
					t.Errorf("len=%d lane=%d Make512Pair single/batched mismatch:\n  batched=%x\n  single =%x",
						dataLen, lane, gotBatched[lane], gotSingle)
				}
			}
		}
	})
}

// TestBLAKE2bMakePairExplicitKey verifies that Make{256,512}Pair
// accepts an explicit caller-supplied key and that the returned pair
// is bit-exact deterministic — calling Make*Pair twice with the same
// key produces identical digests (the persistence-restore contract
// the FFI layer surfaces as ITB_HashRestore).
func TestBLAKE2bMakePairExplicitKey(t *testing.T) {
	t.Run("blake2b256", func(t *testing.T) {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		s1, b1, retKey1, err := Make256Pair("blake2b256", key[:])
		if err != nil {
			t.Fatalf("Make256Pair attempt 1: %v", err)
		}
		if !bytes.Equal(retKey1, key[:]) {
			t.Fatalf("returned key != supplied key (got %x, want %x)", retKey1, key[:])
		}
		s2, b2, retKey2, err := Make256Pair("blake2b256", key[:])
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
	})

	t.Run("blake2b512", func(t *testing.T) {
		var key [64]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		s1, b1, retKey1, err := Make512Pair("blake2b512", key[:])
		if err != nil {
			t.Fatalf("Make512Pair attempt 1: %v", err)
		}
		if !bytes.Equal(retKey1, key[:]) {
			t.Fatalf("returned key != supplied key (got %x, want %x)", retKey1, key[:])
		}
		s2, b2, retKey2, err := Make512Pair("blake2b512", key[:])
		if err != nil {
			t.Fatalf("Make512Pair attempt 2: %v", err)
		}
		if !bytes.Equal(retKey2, key[:]) {
			t.Fatalf("attempt-2 returned key != supplied key")
		}

		seed := [8]uint64{0xabcd, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x1111, 0x2222, 0x3333}
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
		if s1(data, seed) != s2(data, seed) {
			t.Error("single-arm output diverges across two same-key Make512Pair calls")
		}

		if b1 != nil && b2 != nil {
			seeds := [4][8]uint64{seed, seed, seed, seed}
			d := [4][]byte{data, data, data, data}
			r1 := b1(&d, seeds)
			r2 := b2(&d, seeds)
			if r1 != r2 {
				t.Error("batched-arm output diverges across two same-key Make512Pair calls")
			}
		}
	})
}

// TestBLAKE2bMakePairBadKeySize confirms Make{256,512}Pair rejects
// caller-supplied keys whose size does not match the primitive's
// native key length. This guards the FFI-surfaced ITB_HashRestore
// path against silent acceptance of mismatched persisted keys.
func TestBLAKE2bMakePairBadKeySize(t *testing.T) {
	t.Run("blake2b256", func(t *testing.T) {
		_, _, _, err := Make256Pair("blake2b256", make([]byte, 31))
		if err == nil {
			t.Error("Make256Pair(blake2b256, 31-byte key) should fail; got nil error")
		}
		_, _, _, err = Make256Pair("blake2b256", make([]byte, 33))
		if err == nil {
			t.Error("Make256Pair(blake2b256, 33-byte key) should fail; got nil error")
		}
	})
	t.Run("blake2b512", func(t *testing.T) {
		_, _, _, err := Make512Pair("blake2b512", make([]byte, 63))
		if err == nil {
			t.Error("Make512Pair(blake2b512, 63-byte key) should fail; got nil error")
		}
		_, _, _, err = Make512Pair("blake2b512", make([]byte, 65))
		if err == nil {
			t.Error("Make512Pair(blake2b512, 65-byte key) should fail; got nil error")
		}
	})
}

// TestBLAKE2bMakePairITBRoundtrip exercises the full Make*Pair →
// Seed*.BatchHash → Encrypt/Decrypt path on a non-trivial plaintext.
// The Seed.BatchHash field is populated from the Make*Pair batched
// arm; itb.processChunk routes through the batched dispatch when both
// noiseSeed.BatchHash and dataSeed.BatchHash are non-nil. A successful
// roundtrip with byte-equal plaintext confirms (a) the registry
// dispatch wires the batched arm into the seed correctly, and (b) the
// batched arm produces lane-correct outputs at every chunk boundary.
func TestBLAKE2bMakePairITBRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	t.Run("blake2b256", func(t *testing.T) {
		ns, err := newSeed256("blake2b256", 1024)
		if err != nil {
			t.Fatal(err)
		}
		ds, err := newSeed256("blake2b256", 1024)
		if err != nil {
			t.Fatal(err)
		}
		ss, err := newSeed256("blake2b256", 1024)
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
			t.Fatal("plaintext mismatch after Encrypt256/Decrypt256 via blake2b256 batched dispatch")
		}
	})

	t.Run("blake2b512", func(t *testing.T) {
		ns, err := newSeed512("blake2b512", 1024)
		if err != nil {
			t.Fatal(err)
		}
		ds, err := newSeed512("blake2b512", 1024)
		if err != nil {
			t.Fatal(err)
		}
		ss, err := newSeed512("blake2b512", 1024)
		if err != nil {
			t.Fatal(err)
		}
		if ns.BatchHash == nil || ds.BatchHash == nil {
			t.Skip("batched arm unavailable on this host")
		}
		encrypted, err := itb.Encrypt512(ns, ds, ss, plaintext)
		if err != nil {
			t.Fatalf("Encrypt512: %v", err)
		}
		decrypted, err := itb.Decrypt512(ns, ds, ss, encrypted)
		if err != nil {
			t.Fatalf("Decrypt512: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatal("plaintext mismatch after Encrypt512/Decrypt512 via blake2b512 batched dispatch")
		}
	})
}
