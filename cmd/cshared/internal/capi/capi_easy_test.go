package capi

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
)

// TestEasyRoundtripAllPrimitives runs the easy.Encryptor surface
// through every shipped PRF primitive at every supported ITB key
// width × both auth flavours (plain, authenticated). The defaults
// at the FFI boundary mirror the easy package defaults: empty
// primitive ("") = "areion512", keyBits == 0 = 1024, empty mac ("")
// = default MAC. Explicit values throughout so every (name,
// keyBits) tuple exercises the full constructor path.
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
			t.Run(fmt.Sprintf("%s/%dbit", name, keyBits), func(t *testing.T) {
				id, st := NewEasy(name, keyBits, "kmac256", 3)
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

// TestEasyDefaults exercises the empty-string / zero-int default
// handling at the FFI boundary. Empty primitive ("") + keyBits == 0
// + empty mac ("") must produce the same encryptor as the package
// defaults; the round-trip succeeds end-to-end.
func TestEasyDefaults(t *testing.T) {
	id, st := NewEasy("", 0, "", 3)
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
	// The default MAC on the easy package side is what the package
	// picks when no MAC arg is supplied; test only that the field
	// is populated (the concrete name is package-internal policy).
	if mac, _ := EasyMACName(id); mac == "" {
		t.Errorf("default mac is empty; want non-empty")
	}
	mode, _ := EasyMode(id)
	if mode != 3 {
		t.Errorf("Mode = %d, want 3", mode)
	}
}

// TestEasyBadInputs covers invalid mode, unknown primitive, unknown
// MAC, and bad keyBits at the FFI boundary.
func TestEasyBadInputs(t *testing.T) {
	if _, st := NewEasy("blake3", 1024, "kmac256", 2); st != StatusBadInput {
		t.Errorf("mode=2: status=%v, want StatusBadInput", st)
	}
	if _, st := NewEasy("nonsense", 1024, "kmac256", 3); st != StatusEasyUnknownPrimitive {
		// easy.New3 panics on unknown primitive — recoverEasyPanic
		// classifies the message and surfaces the dedicated
		// StatusEasyUnknownPrimitive code.
		t.Errorf("nonsense primitive: status=%v, want StatusEasyUnknownPrimitive", st)
	}
	if _, st := NewEasy("blake3", 1024, "nonsense", 3); st != StatusEasyUnknownPrimitive {
		// parseConstructorArgs cannot distinguish primitive vs MAC
		// at the unknown-name panic site — both registries are tried
		// per arg. classifyPanicMessage maps the shared "unknown
		// name" panic to StatusEasyUnknownPrimitive.
		t.Errorf("nonsense MAC: status=%v, want StatusEasyUnknownPrimitive", st)
	}
	if _, st := NewEasy("blake3", 999, "kmac256", 3); st != StatusEasyBadKeyBits {
		t.Errorf("bad keyBits: status=%v, want StatusEasyBadKeyBits", st)
	}
}

// TestEasyEncryptBufferTooSmall verifies the StatusBufferTooSmall
// probe path: encrypt with zero-cap output, confirm the returned
// length reports required capacity, then retry with the right size.
func TestEasyEncryptBufferTooSmall(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
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

// TestEasySetters exercises the per-instance setters and confirms
// that setting bad values returns StatusBadInput rather than tearing
// down the host process.
func TestEasySetters(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	// Valid cases.
	if st := EasySetNonceBits(id, 256); st != StatusOK {
		t.Errorf("SetNonceBits(256): status=%v", st)
	}
	if st := EasySetBarrierFill(id, 4); st != StatusOK {
		t.Errorf("SetBarrierFill(4): status=%v", st)
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
}

// TestEasyClose covers idempotency and post-Close error paths.
// Close → Encrypt should yield StatusEasyClosed via panic recovery,
// not tear down the host process.
func TestEasyClose(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)

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
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	if st := FreeEasy(id); st != StatusOK {
		t.Fatalf("first Free: status=%v", st)
	}
	if st := FreeEasy(id); st != StatusBadHandle {
		t.Errorf("second Free: status=%v, want StatusBadHandle", st)
	}
}

// TestEasyMaterialGetters exercises SeedCount / SeedComponents /
// HasPRFKeys / PRFKey / MACKey. Every Triple encryptor carries 8
// seed slots (noise + lockSeed + 3 data + 3 start); the PRF-key
// wire-up varies by primitive (siphash24 alone has no fixed key).
func TestEasyMaterialGetters(t *testing.T) {
	cases := []struct {
		primitive string
		wantPRF   int
	}{
		{"blake3", 1},
		{"siphash24", 0}, // SipHash has no fixed PRF keys
	}

	for _, c := range cases {
		t.Run(c.primitive, func(t *testing.T) {
			id, st := NewEasy(c.primitive, 1024, "kmac256", 3)
			if st != StatusOK {
				t.Fatalf("NewEasy: status=%v, last=%q", st, LastError())
			}
			defer FreeEasy(id)

			n, st := EasySeedCount(id)
			if st != StatusOK {
				t.Fatalf("SeedCount: status=%v", st)
			}
			if n != 8 {
				t.Errorf("SeedCount = %d, want 8", n)
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

	src, _ := NewEasy("blake3", 1024, "kmac256", 3)
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

	dst, _ := NewEasy("blake3", 1024, "kmac256", 3)
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
// key_bits / mac disagree with the receiver, and the offending JSON
// field is recorded in lastMismatchField for retrieval via
// LastMismatchField. Mode mismatch is not testable because only
// mode 3 (Triple Ouroboros) is supported.
func TestEasyImportMismatch(t *testing.T) {
	src, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(src)
	required, _ := EasyExport(src, nil)
	blob := make([]byte, required)
	n, _ := EasyExport(src, blob)
	blob = blob[:n]

	// Mismatch on primitive.
	dst, _ := NewEasy("blake2s", 1024, "kmac256", 3)
	defer FreeEasy(dst)
	if st := EasyImport(dst, blob); st != StatusEasyMismatch {
		t.Fatalf("Import primitive-mismatch: status=%v, want StatusEasyMismatch", st)
	}
	if got := LastMismatchField(); got != "primitive" {
		t.Errorf("LastMismatchField = %q, want %q", got, "primitive")
	}

	// Mismatch on key_bits.
	dst2, _ := NewEasy("blake3", 2048, "kmac256", 3)
	defer FreeEasy(dst2)
	if st := EasyImport(dst2, blob); st != StatusEasyMismatch {
		t.Fatalf("Import keyBits-mismatch: status=%v, want StatusEasyMismatch", st)
	}
	if got := LastMismatchField(); got != "key_bits" {
		t.Errorf("LastMismatchField = %q, want %q", got, "key_bits")
	}

	// Mismatch on mac.
	dst4, _ := NewEasy("blake3", 1024, "hmac-sha256", 3)
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
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
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
	src, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(src)
	required, _ := EasyExport(src, nil)
	blob := make([]byte, required)
	n, _ := EasyExport(src, blob)
	blob = blob[:n]

	prim, kb, mode, mac, st := EasyPeekConfig(blob)
	if st != StatusOK {
		t.Fatalf("PeekConfig: status=%v", st)
	}
	if prim != "blake3" || kb != 1024 || mode != 3 || mac != "kmac256" {
		t.Errorf("PeekConfig = (%q, %d, %d, %q), want (blake3, 1024, 3, kmac256)",
			prim, kb, mode, mac)
	}

	// Malformed blob.
	if _, _, _, _, st := EasyPeekConfig([]byte("garbage")); st != StatusEasyMalformed {
		t.Errorf("PeekConfig garbage: status=%v, want StatusEasyMalformed", st)
	}
}

// TestEasyMACFailure confirms a tampered ciphertext yields the
// distinct StatusMACFailure code (not generic StatusDecryptFailed)
// so bindings can map it onto a typed integrity-violation exception.
func TestEasyMACFailure(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
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
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
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
			id, _ := NewEasy("blake3", 1024, "kmac256", 3)
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

// TestEasyMixed3TripleExportImport exercises the NewEasyMixed3 path
// plus the state-blob round-trip on a Triple-mode mixed encryptor.
// The eight per-slot primitive positions map to the canonical seed
// order: N, D1, D2, D3, S1, S2, S3, L.
func TestEasyMixed3TripleExportImport(t *testing.T) {
	idSrc, st := NewEasyMixed3(
		"areion256",
		"blake3", "blake2s", "chacha20",
		"blake2b256", "blake3", "blake2s",
		"areion256",
		1024, "kmac256",
	)
	if st != StatusOK {
		t.Fatalf("NewEasyMixed3: status=%v, last=%q", st, LastError())
	}
	defer FreeEasy(idSrc)

	plaintext := []byte("capi mixed Triple round-trip payload")
	ctBuf := make([]byte, 1<<20)
	ctLen, st := EasyEncryptAuth(idSrc, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("EasyEncryptAuth: status=%v", st)
	}

	// Probe Export buffer size, allocate, then read.
	var probe [0]byte
	need, st := EasyExport(idSrc, probe[:])
	if st != StatusBufferTooSmall {
		t.Fatalf("Export probe: status=%v", st)
	}
	blob := make([]byte, need)
	n, st := EasyExport(idSrc, blob)
	if st != StatusOK {
		t.Fatalf("Export: status=%v", st)
	}
	blob = blob[:n]

	idDst, st := NewEasyMixed3(
		"areion256",
		"blake3", "blake2s", "chacha20",
		"blake2b256", "blake3", "blake2s",
		"areion256",
		1024, "kmac256",
	)
	if st != StatusOK {
		t.Fatalf("NewEasyMixed3 dst: status=%v", st)
	}
	defer FreeEasy(idDst)

	if st := EasyImport(idDst, blob); st != StatusOK {
		t.Fatalf("Import: status=%v, last=%q", st, LastError())
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	ptLen, st := EasyDecryptAuth(idDst, ctBuf[:ctLen], ptBuf)
	if st != StatusOK {
		t.Fatalf("EasyDecryptAuth on dst: status=%v", st)
	}
	if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
		t.Errorf("plaintext mismatch after Import")
	}
}

// TestEasyMixed3RejectMixedWidth verifies that mixing primitives
// across native widths surfaces as a non-OK status (not a panic
// across the cgo boundary).
func TestEasyMixed3RejectMixedWidth(t *testing.T) {
	_, st := NewEasyMixed3(
		"blake3",
		"areion512", "blake3", "blake3",
		"blake3", "blake3", "blake3",
		"",
		1024, "kmac256",
	)
	if st == StatusOK {
		t.Errorf("NewEasyMixed3 with mixed widths returned StatusOK; expected non-OK")
	}
}

// TestEasyMixed3NonMixedIsMixedZero verifies that NewEasy-built
// encryptors return EasyIsMixed = 0 and EasyPrimitiveAt = the same
// primitive across every slot.
func TestEasyMixed3NonMixedIsMixedZero(t *testing.T) {
	id, st := NewEasy("blake3", 1024, "kmac256", 3)
	if st != StatusOK {
		t.Fatalf("NewEasy: status=%v", st)
	}
	defer FreeEasy(id)
	if v, _ := EasyIsMixed(id); v != 0 {
		t.Errorf("EasyIsMixed = %d, want 0", v)
	}
	for i := 0; i < 8; i++ {
		got, _ := EasyPrimitiveAt(id, i)
		if got != "blake3" {
			t.Errorf("EasyPrimitiveAt(%d) = %q, want blake3", i, got)
		}
	}
}

// TestEasyGettersAfterCloseDoNotPanic verifies that every read-only
// getter on a closed encryptor either returns StatusEasyClosed via
// the recoverEasyPanic-translated path or — for the pure public-
// field getters that never call into the closed-guarded methods —
// returns StatusOK reading the metadata fields directly. In neither
// case does a Go panic unwind across the cgo boundary.
func TestEasyGettersAfterCloseDoNotPanic(t *testing.T) {
	id, st := NewEasy("blake3", 1024, "kmac256", 3)
	if st != StatusOK {
		t.Fatalf("NewEasy: status=%v", st)
	}
	if st := EasyClose(id); st != StatusOK {
		t.Fatalf("EasyClose: status=%v", st)
	}
	defer FreeEasy(id)

	// Pure public-field getters (read e.enc.Primitive / KeyBits /
	// Mode / MACName) do not consult the closed flag — the fields
	// stay readable post-Close (they carry metadata, not key
	// material). recoverEasyPanic is harmless here.
	if _, st := EasyPrimitive(id); st != StatusOK {
		t.Errorf("EasyPrimitive after Close: status=%v, want StatusOK", st)
	}
	if _, st := EasyKeyBits(id); st != StatusOK {
		t.Errorf("EasyKeyBits after Close: status=%v, want StatusOK", st)
	}
	if _, st := EasyMode(id); st != StatusOK {
		t.Errorf("EasyMode after Close: status=%v, want StatusOK", st)
	}
	if _, st := EasyMACName(id); st != StatusOK {
		t.Errorf("EasyMACName after Close: status=%v, want StatusOK", st)
	}

	// Method-backed getters call into Encryptor methods that panic
	// with ErrClosed post-Close. recoverEasyPanic translates the
	// panic into StatusEasyClosed.
	if _, st := EasyPrimitiveAt(id, 0); st != StatusEasyClosed {
		t.Errorf("EasyPrimitiveAt after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyIsMixed(id); st != StatusEasyClosed {
		t.Errorf("EasyIsMixed after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasySeedCount(id); st != StatusEasyClosed {
		t.Errorf("EasySeedCount after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasySeedComponents(id, 0); st != StatusEasyClosed {
		t.Errorf("EasySeedComponents after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyHasPRFKeys(id); st != StatusEasyClosed {
		t.Errorf("EasyHasPRFKeys after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyPRFKey(id, 0); st != StatusEasyClosed {
		t.Errorf("EasyPRFKey after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyMACKey(id); st != StatusEasyClosed {
		t.Errorf("EasyMACKey after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyNonceBits(id); st != StatusEasyClosed {
		t.Errorf("EasyNonceBits after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyHeaderSize(id); st != StatusEasyClosed {
		t.Errorf("EasyHeaderSize after Close: status=%v, want StatusEasyClosed", st)
	}
	if _, st := EasyParseChunkLen(id, make([]byte, 8)); st != StatusEasyClosed {
		t.Errorf("EasyParseChunkLen after Close: status=%v, want StatusEasyClosed", st)
	}
}

// TestPanicMessagePreserved verifies that the panic-message
// classifier in recoverEasyPanic preserves the underlying
// diagnostic in lastErr so binding callers can read it via
// LastError().
func TestPanicMessagePreserved(t *testing.T) {
	_, _ = NewEasy("no-such-primitive", 1024, "kmac256", 3)
	msg := LastError()
	// LastError carries "<status string>: <panic message>". The
	// status portion comes from the StatusEasyUnknownPrimitive
	// String() and the panic portion preserves the verbatim text
	// from easy.parseConstructorArgs.
	if msg == "" {
		t.Errorf("LastError empty after unknown-primitive panic; want diagnostic message")
	}
	// Must include the panic-message body, not just the generic
	// status string — otherwise the status-portion alone would
	// suffice and there'd be no regression coverage of the
	// preservation path.
	if msg == "internal error" {
		t.Errorf("LastError = %q (the pre-fix generic fallback); want the preserved panic body", msg)
	}
}

// TestParseChunkLenPixelCap verifies the maxTotalPixels cap that
// the upstream itb.ParseChunkLen enforces is also enforced at the
// FFI seam. Without the cap a malicious header announcing
// width × height ≈ 7 GB could drive a binding to allocate
// gigabytes before Decrypt rejects.
func TestParseChunkLenPixelCap(t *testing.T) {
	// Construct a header that claims width=10000, height=2000
	// (= 20M pixels, > 10M cap). Header layout: 16-byte nonce
	// (default) + 2-byte big-endian width + 2-byte big-endian
	// height = 20 bytes total.
	header := make([]byte, 20)
	// width = 10000 (0x2710)
	header[16] = 0x27
	header[17] = 0x10
	// height = 2000 (0x07D0)
	header[18] = 0x07
	header[19] = 0xD0
	if _, st := ParseChunkLen(header); st != StatusBadInput {
		t.Errorf("ParseChunkLen with totalPixels > maxTotalPixels: %v, want StatusBadInput", st)
	}
}

// TestEasyEncryptBufferTooSmallAuth exercises the auth-side
// StatusBufferTooSmall probe: encrypt with zero-cap output, confirm
// the returned length reports required capacity, then retry with
// the right size.
func TestEasyEncryptBufferTooSmallAuth(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	required, st := EasyEncryptAuth(id, plaintext, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("zero-cap probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required <= 0 {
		t.Fatalf("required=%d, expected > 0", required)
	}

	full := make([]byte, required)
	got, st := EasyEncryptAuth(id, plaintext, full)
	if st != StatusOK {
		t.Fatalf("sized buffer: status=%v", st)
	}
	if got != required {
		t.Fatalf("got=%d, want %d", got, required)
	}
}

// TestEasyDecryptBufferTooSmallAuth covers the auth-decrypt
// StatusBufferTooSmall path: encrypt a payload, then attempt to
// decrypt into a buffer too small for the recovered plaintext.
func TestEasyDecryptBufferTooSmallAuth(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EasyEncryptAuth(id, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("EncryptAuth: status=%v", st)
	}

	tiny := make([]byte, 4)
	required, st := EasyDecryptAuth(id, ctBuf[:ctLen], tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("decrypt probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required != len(plaintext) {
		t.Errorf("required=%d, want %d", required, len(plaintext))
	}

	full := make([]byte, required)
	got, st := EasyDecryptAuth(id, ctBuf[:ctLen], full)
	if st != StatusOK {
		t.Fatalf("sized buffer: status=%v", st)
	}
	if got != required {
		t.Errorf("got=%d, want %d", got, required)
	}
	if !bytes.Equal(plaintext, full[:got]) {
		t.Errorf("plaintext mismatch on resized retry")
	}
}

// TestEasyDecryptBufferTooSmallPlain covers the StatusBufferTooSmall
// path on the plain EasyDecrypt entry.
func TestEasyDecryptBufferTooSmallPlain(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EasyEncrypt(id, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("Encrypt: status=%v", st)
	}

	tiny := make([]byte, 4)
	required, st := EasyDecrypt(id, ctBuf[:ctLen], tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("decrypt probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required != len(plaintext) {
		t.Errorf("required=%d, want %d", required, len(plaintext))
	}
}

// TestEasyStreamAuthBufferTooSmall exercises the BUFFER_TOO_SMALL
// probe on the Streaming AEAD encrypt/decrypt entry points.
func TestEasyStreamAuthBufferTooSmall(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	var streamID [32]byte
	rand.Read(streamID[:])

	// Encrypt-side BUFFER_TOO_SMALL.
	required, st := EasyEncryptStreamAuth(id, plaintext, nil, streamID, 0, true)
	if st != StatusBufferTooSmall {
		t.Fatalf("stream encrypt probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required <= 0 {
		t.Fatalf("stream encrypt required=%d, expected > 0", required)
	}
	full := make([]byte, required)
	got, st := EasyEncryptStreamAuth(id, plaintext, full, streamID, 0, true)
	if st != StatusOK {
		t.Fatalf("stream encrypt sized: status=%v", st)
	}
	if got != required {
		t.Errorf("stream encrypt got=%d, want %d", got, required)
	}

	// Decrypt-side BUFFER_TOO_SMALL.
	tiny := make([]byte, 4)
	required2, _, st := EasyDecryptStreamAuth(id, full[:got], tiny, streamID, 0)
	if st != StatusBufferTooSmall {
		t.Fatalf("stream decrypt probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required2 != len(plaintext) {
		t.Errorf("stream decrypt required=%d, want %d", required2, len(plaintext))
	}
}

// TestEasyDecryptMACFailureFieldSet exercises the recoverEasyPanic
// MAC-failure classification: a tampered ciphertext produces
// StatusMACFailure via the errors.Is(itb.ErrMACFailure) path and
// LastError reports the MAC-failure reason string.
func TestEasyDecryptMACFailureFieldSet(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	plaintext := []byte("integrity-protected payload")
	out := make([]byte, 1<<16)
	ctLen, st := EasyEncryptAuth(id, plaintext, out)
	if st != StatusOK {
		t.Fatalf("EncryptAuth: %v", st)
	}

	// Flip a byte deep inside the container body (past header).
	if ctLen > 100 {
		out[100] ^= 0xff
	}

	pt := make([]byte, len(plaintext)+1024)
	if _, st := EasyDecryptAuth(id, out[:ctLen], pt); st != StatusMACFailure {
		t.Fatalf("tampered: status=%v, want StatusMACFailure", st)
	}
	if msg := LastError(); msg == "" {
		t.Errorf("LastError empty after MAC failure; want non-empty")
	}
}

// TestEasyStreamAuthMACFailure covers the MAC-failure classification
// on the stream-auth decrypt path.
func TestEasyStreamAuthMACFailure(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	plaintext := []byte("stream-protected payload")
	out := make([]byte, 1<<16)
	var streamID [32]byte
	rand.Read(streamID[:])

	ctLen, st := EasyEncryptStreamAuth(id, plaintext, out, streamID, 0, true)
	if st != StatusOK {
		t.Fatalf("stream encrypt: status=%v", st)
	}
	if ctLen > 100 {
		out[100] ^= 0xff
	}
	pt := make([]byte, len(plaintext)+1024)
	if _, _, st := EasyDecryptStreamAuth(id, out[:ctLen], pt, streamID, 0); st != StatusMACFailure {
		t.Errorf("tampered stream: status=%v, want StatusMACFailure", st)
	}
}

// TestEasyImportSentinelErrors crafts state blobs that trigger each
// of the sentinel branches in mapImportError: ErrUnknownPrimitive,
// ErrUnknownMAC, ErrBadKeyBits. Each blob carries valid version /
// kind so the parse reaches the matching validator inside
// Encryptor.Import.
func TestEasyImportSentinelErrors(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	defer FreeEasy(id)

	// Unknown primitive on Import.
	blob := map[string]any{
		"v":         1,
		"kind":      "itb-easy",
		"primitive": "nonsense-primitive",
		"key_bits":  1024,
		"mode":      "triple",
		"mac":       "kmac256",
		"prf_keys":  []string{"00", "00", "00", "00", "00", "00", "00", "00"},
		"seeds":     [][]string{{"0"}, {"0"}, {"0"}, {"0"}, {"0"}, {"0"}, {"0"}, {"0"}},
		"mac_key":   "",
	}
	data, _ := json.Marshal(blob)
	if st := EasyImport(id, data); st != StatusEasyUnknownPrimitive {
		t.Errorf("unknown primitive: status=%v, want StatusEasyUnknownPrimitive", st)
	}

	// Bad key_bits on Import — the value is not in {512, 1024, 2048}.
	blob["primitive"] = "blake3"
	blob["key_bits"] = 999
	data, _ = json.Marshal(blob)
	if st := EasyImport(id, data); st != StatusEasyBadKeyBits {
		t.Errorf("bad key_bits: status=%v, want StatusEasyBadKeyBits", st)
	}

	// Unknown MAC on Import.
	blob["key_bits"] = 1024
	blob["mac"] = "nonsense-mac"
	data, _ = json.Marshal(blob)
	if st := EasyImport(id, data); st != StatusEasyUnknownMAC {
		t.Errorf("unknown MAC: status=%v, want StatusEasyUnknownMAC", st)
	}
}

// TestEasyExportImportBadHandle covers the resolveEasy bad-handle
// branch on the two state-blob helpers.
func TestEasyExportImportBadHandle(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 3)
	FreeEasy(id)
	if _, st := EasyExport(id, nil); st != StatusBadHandle {
		t.Errorf("EasyExport(stale): %v, want StatusBadHandle", st)
	}
	if st := EasyImport(id, []byte("{}")); st != StatusBadHandle {
		t.Errorf("EasyImport(stale): %v, want StatusBadHandle", st)
	}
}

// TestEasyFreshSeedsAcrossPrimitives makes sure the SeedCount branch
// in easy_config lands at every primitive without accidentally
// undercounting slots on any width.
func TestEasyFreshSeedsAcrossPrimitives(t *testing.T) {
	for _, prim := range []string{"siphash24", "blake3", "areion512"} {
		t.Run(prim, func(t *testing.T) {
			id, st := NewEasy(prim, 1024, "kmac256", 3)
			if st != StatusOK {
				t.Fatalf("NewEasy: %v", st)
			}
			defer FreeEasy(id)
			n, _ := EasySeedCount(id)
			if n != 8 {
				t.Errorf("SeedCount = %d, want 8", n)
			}
		})
	}
}
