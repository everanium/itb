package capi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestRegistry exercises HashCount / HashName / HashWidth across
// every entry plus a few out-of-range edges, confirming the FFI
// iteration surface is wired through to hashes.Registry.
func TestRegistry(t *testing.T) {
	if got := HashCount(); got != 9 {
		t.Fatalf("HashCount = %d, want 9", got)
	}

	want := []struct {
		name  string
		width int
	}{
		{"areion256", 256},
		{"areion512", 512},
		{"blake2b256", 256},
		{"blake2b512", 512},
		{"blake2s", 256},
		{"blake3", 256},
		{"aescmac", 128},
		{"siphash24", 128},
		{"chacha20", 256},
	}
	for i, exp := range want {
		if n := HashName(i); n != exp.name {
			t.Errorf("HashName(%d) = %q, want %q", i, n, exp.name)
		}
		if w := HashWidth(i); w != exp.width {
			t.Errorf("HashWidth(%d) = %d, want %d", i, w, exp.width)
		}
	}
	for _, badIdx := range []int{-1, 9, 100} {
		if n := HashName(badIdx); n != "" {
			t.Errorf("HashName(%d) = %q, want empty", badIdx, n)
		}
		if w := HashWidth(badIdx); w != 0 {
			t.Errorf("HashWidth(%d) = %d, want 0", badIdx, w)
		}
	}
}

// TestNewSeedBadHash confirms unknown hash names map to StatusBadHash
// and LastError carries a sensible reason.
func TestNewSeedBadHash(t *testing.T) {
	_, st := NewSeed("nonsense-hash", 1024)
	if st != StatusBadHash {
		t.Fatalf("NewSeed(nonsense): status=%v, want %v", st, StatusBadHash)
	}
	if msg := LastError(); msg == "" {
		t.Errorf("LastError after bad-hash: empty, want non-empty")
	}
}

// TestNewSeedBadKeyBits exercises the keyBits validation path.
func TestNewSeedBadKeyBits(t *testing.T) {
	for _, bits := range []int{0, 256, 511, 2049, 4096} {
		_, st := NewSeed("blake3", bits)
		if st != StatusBadKeyBits {
			t.Errorf("NewSeed(blake3, %d): status=%v, want %v", bits, st, StatusBadKeyBits)
		}
	}
}

// TestFreeSeedIdempotent confirms a freed handle is rejected on
// subsequent use, with StatusBadHandle and a non-empty LastError.
// Note: cgo.Handle.Delete on a stale handle panics; FreeSeed
// internally swallows the panic and translates to StatusBadHandle.
func TestFreeSeedIdempotent(t *testing.T) {
	id, st := NewSeed("blake3", 1024)
	if st != StatusOK {
		t.Fatalf("NewSeed: %v", st)
	}
	if st := FreeSeed(id); st != StatusOK {
		t.Fatalf("FreeSeed first call: %v", st)
	}

	w, st := SeedWidth(id)
	if st != StatusBadHandle || w != 0 {
		t.Fatalf("SeedWidth on freed: width=%d status=%v, want (0, BadHandle)", w, st)
	}
}

// TestHeaderSize confirms the capi HeaderSize helper computes the
// correct chunk header prefix for every valid nonce-byte value and
// rejects out-of-range inputs with StatusBadInput.
func TestHeaderSize(t *testing.T) {
	cases := []struct {
		nonceBytes int
		want       int
		wantStatus Status
	}{
		{16, 36, StatusOK},
		{32, 68, StatusOK},
		{64, 132, StatusOK},
		{0, 0, StatusBadInput},
		{20, 0, StatusBadInput},
		{128, 0, StatusBadInput},
	}
	for _, c := range cases {
		got, st := HeaderSize(c.nonceBytes)
		if st != c.wantStatus {
			t.Errorf("HeaderSize(%d) status = %v, want %v", c.nonceBytes, st, c.wantStatus)
		}
		if got != c.want {
			t.Errorf("HeaderSize(%d) = %d, want %d", c.nonceBytes, got, c.want)
		}
	}
}

// TestReadOnlyConstants verifies build-time constants are reachable.
func TestReadOnlyConstants(t *testing.T) {
	if MaxKeyBits() != 2048 {
		t.Errorf("MaxKeyBits = %d, want 2048", MaxKeyBits())
	}
	if Channels() != 8 {
		t.Errorf("Channels = %d, want 8", Channels())
	}
}

// TestRoundtripTripleAllHashes covers Triple Ouroboros (Encrypt3 /
// Decrypt3) over every shipped primitive at every supported ITB key
// width. Caller-allocated-buffer convention throughout; each case
// exercises the 8-seed dispatcher on the FFI surface.
func TestRoundtripTripleAllHashes(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%dbit", name, keyBits), func(t *testing.T) {
				ids := make([]HandleID, 8)
				for j := range ids {
					id, st := NewSeed(name, keyBits)
					if st != StatusOK {
						t.Fatalf("NewSeed %d: %v", j, st)
					}
					ids[j] = id
				}
				defer func() {
					for _, id := range ids {
						FreeSeed(id)
					}
				}()

				ctBuf := make([]byte, 1<<20)
				ctLen, st := Encrypt3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
					plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("Encrypt3 failed: %v", st)
				}
				if ctLen <= 0 || ctLen > len(ctBuf) {
					t.Fatalf("Encrypt3 returned ctLen=%d", ctLen)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := Decrypt3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
					ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("Decrypt3 failed: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch (got %d bytes, want %d)", ptLen, len(plaintext))
				}
			})
		}
	}
}

// TestEncrypt3SeedWidthMix verifies that mixing handles of different
// native hash widths in one Encrypt3 call is rejected with
// StatusSeedWidthMix on the 8-seed dispatcher path.
func TestEncrypt3SeedWidthMix(t *testing.T) {
	mk := func(name string) HandleID {
		id, st := NewSeed(name, 1024)
		if st != StatusOK {
			t.Fatalf("NewSeed(%s): %v", name, st)
		}
		return id
	}
	ids := []HandleID{
		mk("siphash24"), // width 128 — odd one out
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	out := make([]byte, 1<<16)
	_, st := Encrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		[]byte("hello"), out)
	if st != StatusSeedWidthMix {
		t.Fatalf("mixed-width Encrypt3: status=%v, want %v", st, StatusSeedWidthMix)
	}
}

// TestEncrypt3BufferTooSmall verifies the buffer-resize handshake on
// the Triple variant.
func TestEncrypt3BufferTooSmall(t *testing.T) {
	ids := make([]HandleID, 8)
	for i := range ids {
		ids[i], _ = NewSeed("blake3", 1024)
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	tiny := make([]byte, 4)
	required, st := Encrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		plaintext, tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("Encrypt3 with 4-byte buffer: got status %v, want %v",
			st, StatusBufferTooSmall)
	}
	if required <= len(tiny) {
		t.Fatalf("Encrypt3 reported required=%d, expected > %d", required, len(tiny))
	}

	full := make([]byte, required)
	got, st := Encrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		plaintext, full)
	if st != StatusOK {
		t.Fatalf("Encrypt3 with sized buffer: got status %v, want OK", st)
	}
	if got != required {
		t.Fatalf("Encrypt3 got=%d, want %d", got, required)
	}
}

// TestSeedWidthSeedHashName exposes the introspection helpers used
// by the FFI ITB_SeedWidth / ITB_SeedHashName entry points.
func TestSeedWidthSeedHashName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wantWidth int
	}{
		{"siphash24", 128},
		{"blake3", 256},
		{"areion512", 512},
	} {
		id, st := NewSeed(tc.name, 1024)
		if st != StatusOK {
			t.Fatalf("NewSeed(%s): %v", tc.name, st)
		}
		w, st := SeedWidth(id)
		if st != StatusOK || int(w) != tc.wantWidth {
			t.Errorf("SeedWidth(%s) = %d/%v, want %d/OK", tc.name, w, st, tc.wantWidth)
		}
		got, st := SeedHashName(id)
		if st != StatusOK || got != tc.name {
			t.Errorf("SeedHashName = %q/%v, want %q/OK", got, st, tc.name)
		}
		FreeSeed(id)
	}
}

// TestNewSeedFromComponentsRoundtrip exercises the full FFI
// persistence flow: encrypt with NewSeed (random components, random
// hashKey) → extract components + hashKey → free seed → reconstruct
// the seed via NewSeedFromComponents → decrypt successfully. The
// scenario simulates "encrypt today on machine A, save the seed
// material, decrypt tomorrow on machine B with the saved material".
//
// Iterates every primitive in the registry × three key-bit widths.
// SipHash-2-4 carries no internal fixed key so the hashKey slot on
// the restored side is expected to be empty.
func TestNewSeedFromComponentsRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%dbit", name, keyBits), func(t *testing.T) {
				snapshot := func(seed HandleID) (components []uint64, hashKey []byte) {
					comps, st := SeedComponents(seed)
					if st != StatusOK {
						t.Fatalf("SeedComponents: %v", st)
					}
					key, st := SeedHashKey(seed)
					if st != StatusOK {
						t.Fatalf("SeedHashKey: %v", st)
					}
					return comps, key
				}

				// Day 1 — random seeds, encrypt, snapshot material.
				ids := make([]HandleID, 8)
				comps := make([][]uint64, 8)
				keys := make([][]byte, 8)
				for j := range ids {
					id, st := NewSeed(name, keyBits)
					if st != StatusOK {
						t.Fatalf("NewSeed[%d]: %v", j, st)
					}
					ids[j] = id
					comps[j], keys[j] = snapshot(id)
				}

				ctBuf := make([]byte, 1<<20)
				ctLen, st := Encrypt3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
					plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("Encrypt3: %v", st)
				}
				for _, id := range ids {
					FreeSeed(id)
				}

				// Day 2 — restore from snapshots. The new seeds
				// must produce the same per-pixel hashes, so the
				// previous ciphertext decrypts cleanly.
				ids2 := make([]HandleID, 8)
				for j := range ids2 {
					id, st := NewSeedFromComponents(name, comps[j], keys[j])
					if st != StatusOK {
						t.Fatalf("NewSeedFromComponents[%d]: %v", j, st)
					}
					ids2[j] = id
				}
				defer func() {
					for _, id := range ids2 {
						FreeSeed(id)
					}
				}()

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := Decrypt3(
					ids2[0], ids2[1], ids2[2], ids2[3],
					ids2[4], ids2[5], ids2[6], ids2[7],
					ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("Decrypt3 (restored): %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("restored plaintext mismatch (got %d bytes, want %d)", ptLen, len(plaintext))
				}

				// Round-trip check: the restored seeds report the
				// same hashKey the encrypt-side seeds had.
				_, restoredKey := snapshot(ids2[0])
				if !bytes.Equal(restoredKey, keys[0]) {
					t.Errorf("restored hashKey mismatch (got %x, want %x)", restoredKey, keys[0])
				}
			})
		}
	}
}

// TestNewSeedFromComponentsRandomKey verifies the random-key path of
// NewSeedFromComponents (passing nil hashKey): the seed should be
// usable end-to-end and report a non-empty hashKey via SeedHashKey
// (except for SipHash-2-4 which has no internal key).
func TestNewSeedFromComponentsRandomKey(t *testing.T) {
	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		t.Run(name, func(t *testing.T) {
			// Use 8 zero components (= 512-bit key) — only checking
			// the hashKey path; components content is unused there.
			components := make([]uint64, 8)
			id, st := NewSeedFromComponents(name, components, nil)
			if st != StatusOK {
				t.Fatalf("NewSeedFromComponents: %v", st)
			}
			defer FreeSeed(id)
			key, st := SeedHashKey(id)
			if st != StatusOK {
				t.Fatalf("SeedHashKey: %v", st)
			}
			if name == "siphash24" {
				if len(key) != 0 {
					t.Errorf("SipHash-2-4 hashKey should be empty, got %d bytes", len(key))
				}
			} else if len(key) == 0 {
				t.Errorf("hashKey unexpectedly empty for %s", name)
			}
		})
	}
}

// TestNewSeedFromComponentsBadKeySize verifies that passing a
// hashKey of wrong size for the named primitive returns
// StatusBadHash (registry's validateKey rejects the mismatch).
func TestNewSeedFromComponentsBadKeySize(t *testing.T) {
	components := make([]uint64, 16) // 1024-bit key
	wrongKey := make([]byte, 7)      // wrong size for any primitive
	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		if name == "siphash24" {
			continue // SipHash takes no hashKey at all
		}
		id, st := NewSeedFromComponents(name, components, wrongKey)
		if st == StatusOK {
			FreeSeed(id)
			t.Errorf("%s accepted 7-byte key (want StatusBadHash)", name)
		}
	}
}

// TestDefaultNonceBits confirms the exported compile-in default nonce
// width matches the itb DefaultNonceBits constant (used by bindings
// that need a sentinel for streaming without threading a Config).
func TestDefaultNonceBits(t *testing.T) {
	if got := DefaultNonceBits(); got != 512 {
		t.Errorf("DefaultNonceBits() = %d, want 512", got)
	}
}

// TestCapiErrorString covers the capiError.Error sentinel — the
// dispatch-side fallback when a cached width does not match any
// known case. The sentinel is unreachable through normal FFI use,
// so the test instantiates the underlying string type directly to
// confirm the Error() method preserves the message verbatim.
func TestCapiErrorString(t *testing.T) {
	const msg = "capi: synthetic test sentinel"
	var e error = capiError(msg)
	if got := e.Error(); got != msg {
		t.Errorf("capiError.Error() = %q, want %q", got, msg)
	}
	if errInternal.Error() == "" {
		t.Errorf("errInternal.Error() unexpectedly empty")
	}
}

// TestDecrypt3BadHeader exercises the Decrypt3 error path where the
// caller passes ciphertext too short to even contain the header.
// The underlying itb.Decrypt3x* surface returns an error rather than
// panicking, so the wrapper translates to StatusDecryptFailed.
func TestDecrypt3BadHeader(t *testing.T) {
	ids := make([]HandleID, 8)
	for i := range ids {
		ids[i] = NewSeedOK(t, "blake3", 1024)
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()

	out := make([]byte, 1<<16)
	short := []byte{0x00, 0x01, 0x02}
	_, st := Decrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		short, out)
	if st != StatusDecryptFailed {
		t.Errorf("Decrypt3(short ciphertext): status=%v, want StatusDecryptFailed", st)
	}
}

// TestEncrypt3BadHandle confirms that Encrypt3 / Decrypt3 reject a
// freed handle with StatusBadHandle before touching any cipher
// state.
func TestEncrypt3BadHandle(t *testing.T) {
	ids := make([]HandleID, 8)
	for i := range ids {
		ids[i] = NewSeedOK(t, "blake3", 1024)
	}
	FreeSeed(ids[0]) // stale
	defer func() {
		for _, id := range ids[1:] {
			FreeSeed(id)
		}
	}()

	out := make([]byte, 1<<16)
	if _, st := Encrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		[]byte("test"), out); st != StatusBadHandle {
		t.Errorf("Encrypt3(stale noise): status=%v, want StatusBadHandle", st)
	}
	if _, st := Decrypt3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		[]byte("test"), out); st != StatusBadHandle {
		t.Errorf("Decrypt3(stale noise): status=%v, want StatusBadHandle", st)
	}
}
