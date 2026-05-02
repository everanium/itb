package capi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestEasyRoundtripAllPrimitives runs the easy.Encryptor surface
// through every shipped PRF primitive at every supported ITB key
// width × both modes (Single, Triple) × both auth flavours (plain,
// authenticated). The defaults at the FFI boundary mirror the easy
// package defaults: empty primitive ("") = "areion512", keyBits == 0
// = 1024, empty mac ("") = "kmac256". This test passes explicit
// values throughout so every (name, keyBits, mode) tuple exercises
// the full constructor path.
func TestEasyRoundtripAllPrimitives(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		for _, keyBits := range []int{512, 1024, 2048} {
			width := HashWidth(i)
			if keyBits%width != 0 {
				continue // skip combinations that violate keyBits-vs-width invariant
			}
			for _, mode := range []int{1, 3} {
				t.Run(fmt.Sprintf("%s/%dbit/mode%d", name, keyBits, mode), func(t *testing.T) {
					id, st := NewEasy(name, keyBits, "kmac256", mode)
					if st != StatusOK {
						t.Fatalf("NewEasy: status=%v, last=%q", st, LastError())
					}
					defer FreeEasy(id)

					// Plain encrypt / decrypt.
					ctBuf := make([]byte, 1<<20)
					ctLen, st := EasyEncrypt(id, plaintext, ctBuf)
					if st != StatusOK {
						t.Fatalf("EasyEncrypt: status=%v", st)
					}

					ptBuf := make([]byte, len(plaintext)+1024)
					ptLen, st := EasyDecrypt(id, ctBuf[:ctLen], ptBuf)
					if st != StatusOK {
						t.Fatalf("EasyDecrypt: status=%v", st)
					}
					if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
						t.Fatalf("plaintext mismatch")
					}

					// Authenticated encrypt / decrypt.
					ctaBuf := make([]byte, 1<<20)
					ctaLen, st := EasyEncryptAuth(id, plaintext, ctaBuf)
					if st != StatusOK {
						t.Fatalf("EasyEncryptAuth: status=%v", st)
					}

					ptaBuf := make([]byte, len(plaintext)+1024)
					ptaLen, st := EasyDecryptAuth(id, ctaBuf[:ctaLen], ptaBuf)
					if st != StatusOK {
						t.Fatalf("EasyDecryptAuth: status=%v", st)
					}
					if !bytes.Equal(plaintext, ptaBuf[:ptaLen]) {
						t.Fatalf("auth plaintext mismatch")
					}
				})
			}
		}
	}
}

// TestEasyDefaults exercises the empty-string / zero-int default
// handling at the FFI boundary. Empty primitive ("") + keyBits == 0
// + empty mac ("") must produce the same encryptor as
// ("areion512", 1024, "kmac256"); the round-trip succeeds end-to-end.
func TestEasyDefaults(t *testing.T) {
	id, st := NewEasy("", 0, "", 1)
	if st != StatusOK {
		t.Fatalf("NewEasy(defaults): status=%v, last=%q", st, LastError())
	}
	defer FreeEasy(id)

	prim, _ := EasyPrimitive(id)
	if prim != "areion512" {
		t.Errorf("default primitive = %q, want areion512", prim)
	}
	keyBits, _ := EasyKeyBits(id)
	if keyBits != 1024 {
		t.Errorf("default keyBits = %d, want 1024", keyBits)
	}
	mac, _ := EasyMACName(id)
	if mac != "kmac256" {
		t.Errorf("default mac = %q, want kmac256", mac)
	}
	mode, _ := EasyMode(id)
	if mode != 1 {
		t.Errorf("Mode = %d, want 1", mode)
	}
}

// TestEasyBadInputs covers invalid mode, unknown primitive, unknown
// MAC, and bad keyBits at the FFI boundary.
func TestEasyBadInputs(t *testing.T) {
	if _, st := NewEasy("blake3", 1024, "kmac256", 2); st != StatusBadInput {
		t.Errorf("mode=2: status=%v, want StatusBadInput", st)
	}
	if _, st := NewEasy("nonsense", 1024, "kmac256", 1); st != StatusInternal {
		// easy.New panics on unknown primitive — recoverEasyPanic
		// translates to fallback (StatusInternal here).
		t.Errorf("nonsense primitive: status=%v, want StatusInternal", st)
	}
	if _, st := NewEasy("blake3", 1024, "nonsense", 1); st != StatusInternal {
		t.Errorf("nonsense MAC: status=%v, want StatusInternal", st)
	}
	if _, st := NewEasy("blake3", 999, "kmac256", 1); st != StatusInternal {
		t.Errorf("bad keyBits: status=%v, want StatusInternal", st)
	}
}

// TestEasyEncryptBufferTooSmall verifies the StatusBufferTooSmall
// probe path: encrypt with zero-cap output, confirm the returned
// length reports required capacity, then retry with the right size.
func TestEasyEncryptBufferTooSmall(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	required, st := EasyEncrypt(id, plaintext, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("zero-cap probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required <= 0 {
		t.Fatalf("required=%d, expected > 0", required)
	}

	full := make([]byte, required)
	got, st := EasyEncrypt(id, plaintext, full)
	if st != StatusOK {
		t.Fatalf("sized buffer: status=%v", st)
	}
	if got != required {
		t.Fatalf("got=%d, want %d", got, required)
	}
}

// TestEasySetters exercises all six per-instance setters and confirms
// that setting bad values returns StatusBadInput rather than tearing
// down the host process.
func TestEasySetters(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	// Valid cases.
	if st := EasySetNonceBits(id, 256); st != StatusOK {
		t.Errorf("SetNonceBits(256): status=%v", st)
	}
	if st := EasySetBarrierFill(id, 4); st != StatusOK {
		t.Errorf("SetBarrierFill(4): status=%v", st)
	}
	if st := EasySetBitSoup(id, 1); st != StatusOK {
		t.Errorf("SetBitSoup(1): status=%v", st)
	}
	if st := EasySetLockSoup(id, 1); st != StatusOK {
		t.Errorf("SetLockSoup(1): status=%v", st)
	}
	if st := EasySetLockSeed(id, 1); st != StatusOK {
		t.Errorf("SetLockSeed(1): status=%v", st)
	}
	if st := EasySetChunkSize(id, 1024); st != StatusOK {
		t.Errorf("SetChunkSize(1024): status=%v", st)
	}

	// Invalid cases.
	if st := EasySetNonceBits(id, 999); st != StatusBadInput {
		t.Errorf("SetNonceBits(999): status=%v, want StatusBadInput", st)
	}
	if st := EasySetBarrierFill(id, 3); st != StatusBadInput {
		t.Errorf("SetBarrierFill(3): status=%v, want StatusBadInput", st)
	}
	if st := EasySetLockSeed(id, 2); st != StatusBadInput {
		t.Errorf("SetLockSeed(2): status=%v, want StatusBadInput", st)
	}
}

// TestEasyLockSeedAfterEncrypt verifies that SetLockSeed is rejected
// after the first successful Encrypt with the dedicated
// StatusEasyLockSeedAfterEncrypt code (not generic StatusBadInput).
func TestEasyLockSeedAfterEncrypt(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	plaintext := make([]byte, 64)
	rand.Read(plaintext)

	out := make([]byte, 1<<16)
	if _, st := EasyEncrypt(id, plaintext, out); st != StatusOK {
		t.Fatalf("first Encrypt: status=%v", st)
	}

	if st := EasySetLockSeed(id, 1); st != StatusEasyLockSeedAfterEncrypt {
		t.Errorf("SetLockSeed after Encrypt: status=%v, want StatusEasyLockSeedAfterEncrypt", st)
	}
}

// TestEasyClose covers idempotency and post-Close error paths.
// Close → Encrypt should yield StatusEasyClosed via panic recovery,
// not tear down the host process.
func TestEasyClose(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)

	if st := EasyClose(id); st != StatusOK {
		t.Fatalf("first Close: status=%v", st)
	}
	if st := EasyClose(id); st != StatusOK {
		t.Errorf("second Close (idempotent): status=%v", st)
	}

	out := make([]byte, 1<<16)
	if _, st := EasyEncrypt(id, []byte("test"), out); st != StatusEasyClosed {
		t.Errorf("Encrypt after Close: status=%v, want StatusEasyClosed", st)
	}

	// FreeEasy on an already-closed encryptor still releases the
	// handle slot cleanly.
	if st := FreeEasy(id); st != StatusOK {
		t.Errorf("FreeEasy after Close: status=%v", st)
	}
}

// TestEasyFreeIdempotent confirms a freed handle is rejected on
// subsequent use, with StatusBadHandle. Mirrors TestFreeSeedIdempotent
// in capi_test.go.
func TestEasyFreeIdempotent(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	if st := FreeEasy(id); st != StatusOK {
		t.Fatalf("first Free: status=%v", st)
	}
	if st := FreeEasy(id); st != StatusBadHandle {
		t.Errorf("second Free: status=%v, want StatusBadHandle", st)
	}
}

// TestEasyMaterialGetters exercises SeedCount / SeedComponents /
// HasPRFKeys / PRFKey / MACKey across (Single, Triple) × (LockSeed
// off, on) and the SipHash special case (HasPRFKeys reports 0).
func TestEasyMaterialGetters(t *testing.T) {
	cases := []struct {
		primitive string
		mode      int
		lockSeed  int
		wantSeeds int
		wantPRF   int
	}{
		{"blake3", 1, 0, 3, 1},
		{"blake3", 1, 1, 4, 1},
		{"blake3", 3, 0, 7, 1},
		{"blake3", 3, 1, 8, 1},
		{"siphash24", 1, 0, 3, 0}, // SipHash has no fixed PRF keys
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/mode%d/lock%d", c.primitive, c.mode, c.lockSeed), func(t *testing.T) {
			id, st := NewEasy(c.primitive, 1024, "kmac256", c.mode)
			if st != StatusOK {
				t.Fatalf("NewEasy: status=%v, last=%q", st, LastError())
			}
			defer FreeEasy(id)

			if c.lockSeed == 1 {
				if st := EasySetLockSeed(id, 1); st != StatusOK {
					t.Fatalf("SetLockSeed: status=%v", st)
				}
			}

			n, st := EasySeedCount(id)
			if st != StatusOK {
				t.Fatalf("SeedCount: status=%v", st)
			}
			if n != c.wantSeeds {
				t.Errorf("SeedCount = %d, want %d", n, c.wantSeeds)
			}

			has, _ := EasyHasPRFKeys(id)
			if has != c.wantPRF {
				t.Errorf("HasPRFKeys = %d, want %d", has, c.wantPRF)
			}

			// SeedComponents per slot.
			for slot := 0; slot < n; slot++ {
				comps, st := EasySeedComponents(id, slot)
				if st != StatusOK {
					t.Errorf("SeedComponents(%d): status=%v", slot, st)
				}
				if len(comps) != 1024/64 {
					t.Errorf("SeedComponents(%d): len=%d, want %d", slot, len(comps), 1024/64)
				}
			}

			// Out-of-range slot.
			if _, st := EasySeedComponents(id, n); st != StatusBadInput {
				t.Errorf("SeedComponents(out-of-range): status=%v", st)
			}

			// PRFKey behaviour depends on primitive.
			if c.wantPRF == 1 {
				for slot := 0; slot < n; slot++ {
					key, st := EasyPRFKey(id, slot)
					if st != StatusOK {
						t.Errorf("PRFKey(%d): status=%v", slot, st)
					}
					if len(key) == 0 {
						t.Errorf("PRFKey(%d): zero-length key", slot)
					}
				}
			} else {
				if _, st := EasyPRFKey(id, 0); st != StatusBadInput {
					t.Errorf("PRFKey on no-PRF primitive: status=%v, want StatusBadInput", st)
				}
			}

			// MACKey is always present.
			mk, st := EasyMACKey(id)
			if st != StatusOK {
				t.Errorf("MACKey: status=%v", st)
			}
			if len(mk) == 0 {
				t.Errorf("MACKey: zero-length")
			}
		})
	}
}

// TestEasyExportImportRoundtrip writes the encryptor's full state to
// JSON, replaces a fresh encryptor's state with it, and confirms that
// the rebuilt encryptor produces a ciphertext the original encryptor
// can decrypt (and vice versa). This is the persistence-restore path
// FFI consumers rely on for encrypt-today / decrypt-tomorrow flows.
func TestEasyExportImportRoundtrip(t *testing.T) {
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	src, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(src)

	// Probe export size.
	required, st := EasyExport(src, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("Export probe: status=%v, want StatusBufferTooSmall", st)
	}
	blob := make([]byte, required)
	n, st := EasyExport(src, blob)
	if st != StatusOK {
		t.Fatalf("Export: status=%v", st)
	}
	blob = blob[:n]

	// Encrypt with src, decrypt via dst after Import.
	out := make([]byte, 1<<16)
	ctLen, _ := EasyEncryptAuth(src, plaintext, out)

	dst, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(dst)
	if st := EasyImport(dst, blob); st != StatusOK {
		t.Fatalf("Import: status=%v, last=%q", st, LastError())
	}

	pt := make([]byte, len(plaintext)+1024)
	ptLen, st := EasyDecryptAuth(dst, out[:ctLen], pt)
	if st != StatusOK {
		t.Fatalf("DecryptAuth after Import: status=%v", st)
	}
	if !bytes.Equal(plaintext, pt[:ptLen]) {
		t.Fatalf("plaintext mismatch after Import")
	}
}

// TestEasyImportMismatch covers ErrMismatch field capture: the
// Encryptor.Import path rejects a state blob whose primitive /
// key_bits / mode / mac disagree with the receiver, and the offending
// JSON field is recorded in lastMismatchField for retrieval via
// LastMismatchField.
func TestEasyImportMismatch(t *testing.T) {
	src, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(src)
	required, _ := EasyExport(src, nil)
	blob := make([]byte, required)
	n, _ := EasyExport(src, blob)
	blob = blob[:n]

	// Mismatch on primitive.
	dst, _ := NewEasy("blake2s", 1024, "kmac256", 1)
	defer FreeEasy(dst)
	if st := EasyImport(dst, blob); st != StatusEasyMismatch {
		t.Fatalf("Import primitive-mismatch: status=%v, want StatusEasyMismatch", st)
	}
	if got := LastMismatchField(); got != "primitive" {
		t.Errorf("LastMismatchField = %q, want %q", got, "primitive")
	}

	// Mismatch on key_bits.
	dst2, _ := NewEasy("blake3", 2048, "kmac256", 1)
	defer FreeEasy(dst2)
	if st := EasyImport(dst2, blob); st != StatusEasyMismatch {
		t.Fatalf("Import keyBits-mismatch: status=%v, want StatusEasyMismatch", st)
	}
	if got := LastMismatchField(); got != "key_bits" {
		t.Errorf("LastMismatchField = %q, want %q", got, "key_bits")
	}

	// Mismatch on mode.
	dst3, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(dst3)
	if st := EasyImport(dst3, blob); st != StatusEasyMismatch {
		t.Fatalf("Import mode-mismatch: status=%v, want StatusEasyMismatch", st)
	}
	if got := LastMismatchField(); got != "mode" {
		t.Errorf("LastMismatchField = %q, want %q", got, "mode")
	}

	// Mismatch on mac.
	dst4, _ := NewEasy("blake3", 1024, "hmac-sha256", 1)
	defer FreeEasy(dst4)
	if st := EasyImport(dst4, blob); st != StatusEasyMismatch {
		t.Fatalf("Import mac-mismatch: status=%v, want StatusEasyMismatch", st)
	}
	if got := LastMismatchField(); got != "mac" {
		t.Errorf("LastMismatchField = %q, want %q", got, "mac")
	}
}

// TestEasyImportMalformed exercises the StatusEasyMalformed path on
// truly broken JSON input.
func TestEasyImportMalformed(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	if st := EasyImport(id, []byte("not json")); st != StatusEasyMalformed {
		t.Errorf("Import garbage: status=%v, want StatusEasyMalformed", st)
	}
	if st := EasyImport(id, []byte(`{"v":99,"kind":"itb-easy"}`)); st != StatusEasyVersionTooNew {
		t.Errorf("Import too-new version: status=%v, want StatusEasyVersionTooNew", st)
	}
	if st := EasyImport(id, []byte(`{"v":1,"kind":"wrong"}`)); st != StatusEasyMalformed {
		t.Errorf("Import wrong-kind: status=%v, want StatusEasyMalformed", st)
	}
}

// TestEasyPeekConfig confirms PeekConfig parses a state blob's
// metadata without performing full validation, returning the four
// dimensions on success and StatusEasyMalformed on a broken blob.
func TestEasyPeekConfig(t *testing.T) {
	src, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(src)
	required, _ := EasyExport(src, nil)
	blob := make([]byte, required)
	n, _ := EasyExport(src, blob)
	blob = blob[:n]

	prim, kb, mode, mac, st := EasyPeekConfig(blob)
	if st != StatusOK {
		t.Fatalf("PeekConfig: status=%v", st)
	}
	if prim != "blake3" || kb != 1024 || mode != 1 || mac != "kmac256" {
		t.Errorf("PeekConfig = (%q, %d, %d, %q), want (blake3, 1024, 1, kmac256)",
			prim, kb, mode, mac)
	}

	// Malformed blob.
	if _, _, _, _, st := EasyPeekConfig([]byte("garbage")); st != StatusEasyMalformed {
		t.Errorf("PeekConfig garbage: status=%v, want StatusEasyMalformed", st)
	}
}

// TestEasyExportImportRoundtripWithLockSeed exercises the full
// persistence path with a dedicated lockSeed active on the sender.
// Regression-pinned: an earlier revision of Encryptor.Import set
// cfg.LockSeed = 1 + cfg.LockSeedHandle from the blob but did NOT
// couple cfg.LockSoup / cfg.BitSoup the way SetLockSeed does on the
// on-direction. The bit-permutation overlay therefore stayed
// disabled on the receiver, MAC verification passed (the MAC key
// survives the round-trip identically), and DecryptAuth returned
// random-looking bytes that compared unequal to the original
// plaintext. Asserting the equality here catches that regression
// directly.
func TestEasyExportImportRoundtripWithLockSeed(t *testing.T) {
	plaintext := []byte("lockseed persistence — auto-couple regression test")

	for _, mode := range []int{1, 3} {
		t.Run(fmt.Sprintf("mode%d", mode), func(t *testing.T) {
			src, _ := NewEasy("blake3", 1024, "kmac256", mode)
			defer FreeEasy(src)

			if st := EasySetLockSeed(src, 1); st != StatusOK {
				t.Fatalf("SetLockSeed: status=%v", st)
			}

			required, _ := EasyExport(src, nil)
			blob := make([]byte, required)
			n, _ := EasyExport(src, blob)
			blob = blob[:n]

			out := make([]byte, 1<<16)
			ctLen, st := EasyEncryptAuth(src, plaintext, out)
			if st != StatusOK {
				t.Fatalf("EncryptAuth: status=%v", st)
			}

			// Receiver starts without LockSeed + without overlay.
			// Import alone must restore both the dedicated seed
			// slot AND auto-couple LockSoup + BitSoup so the
			// bit-permutation-encoded ciphertext decodes correctly.
			dst, _ := NewEasy("blake3", 1024, "kmac256", mode)
			defer FreeEasy(dst)
			if st := EasyImport(dst, blob); st != StatusOK {
				t.Fatalf("Import: status=%v, last=%q", st, LastError())
			}

			pt := make([]byte, len(plaintext)+1024)
			ptLen, st := EasyDecryptAuth(dst, out[:ctLen], pt)
			if st != StatusOK {
				t.Fatalf("DecryptAuth after Import: status=%v", st)
			}
			if !bytes.Equal(plaintext, pt[:ptLen]) {
				t.Fatalf("plaintext mismatch after Import (overlay coupling regression)")
			}
		})
	}
}

// TestEasyMACFailure confirms a tampered ciphertext yields the
// distinct StatusMACFailure code (not generic StatusDecryptFailed)
// so bindings can map it onto a typed integrity-violation exception.
func TestEasyMACFailure(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	plaintext := []byte("authenticated payload")
	out := make([]byte, 1<<16)
	ctLen, _ := EasyEncryptAuth(id, plaintext, out)

	// Flip a byte deep inside the container.
	if ctLen > 100 {
		out[100] ^= 0xff
	}

	pt := make([]byte, len(plaintext)+1024)
	if _, st := EasyDecryptAuth(id, out[:ctLen], pt); st != StatusMACFailure {
		t.Errorf("tampered DecryptAuth: status=%v, want StatusMACFailure", st)
	}
}

// TestEasyNonceBitsAccessors covers the per-instance NonceBits /
// HeaderSize / ParseChunkLen capi wrappers: they read the
// encryptor's own cfg.NonceBits with fallback to the global, and
// stay independent of the process-wide HeaderSize() reader.
func TestEasyNonceBitsAccessors(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	if got, _ := EasyNonceBits(id); got != 128 {
		t.Errorf("default NonceBits = %d, want 128", got)
	}
	if got, _ := EasyHeaderSize(id); got != 20 {
		t.Errorf("default HeaderSize = %d, want 20", got)
	}

	for _, n := range []int{128, 256, 512} {
		if st := EasySetNonceBits(id, n); st != StatusOK {
			t.Fatalf("SetNonceBits(%d): status=%v", n, st)
		}
		if got, _ := EasyNonceBits(id); got != n {
			t.Errorf("after SetNonceBits(%d): NonceBits = %d", n, got)
		}
		if got, _ := EasyHeaderSize(id); got != n/8+4 {
			t.Errorf("after SetNonceBits(%d): HeaderSize = %d", n, got)
		}
	}
}

// TestEasyParseChunkLen verifies ParseChunkLen reports the full
// chunk length on the wire across all three nonce sizes.
func TestEasyParseChunkLen(t *testing.T) {
	for _, n := range []int{128, 256, 512} {
		t.Run(fmt.Sprintf("nonce%d", n), func(t *testing.T) {
			id, _ := NewEasy("blake3", 1024, "kmac256", 1)
			defer FreeEasy(id)
			if st := EasySetNonceBits(id, n); st != StatusOK {
				t.Fatalf("SetNonceBits(%d): status=%v", n, st)
			}

			plaintext := make([]byte, 4096)
			rand.Read(plaintext)
			out := make([]byte, 1<<16)
			ctLen, st := EasyEncrypt(id, plaintext, out)
			if st != StatusOK {
				t.Fatalf("Encrypt: status=%v", st)
			}

			h, _ := EasyHeaderSize(id)
			chunkLen, st := EasyParseChunkLen(id, out[:h])
			if st != StatusOK {
				t.Fatalf("ParseChunkLen: status=%v", st)
			}
			if chunkLen != ctLen {
				t.Errorf("ParseChunkLen = %d, want %d", chunkLen, ctLen)
			}

			// Too-short buffer.
			if _, st := EasyParseChunkLen(id, out[:h-1]); st != StatusBadInput {
				t.Errorf("ParseChunkLen(short): status=%v, want StatusBadInput", st)
			}
			// Zero dimensions.
			zero := make([]byte, h)
			if _, st := EasyParseChunkLen(id, zero); st != StatusBadInput {
				t.Errorf("ParseChunkLen(zero dims): status=%v, want StatusBadInput", st)
			}
		})
	}
}
