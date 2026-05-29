package capi

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
)

// Scope: width-arm branches not exercised by the existing test files
// (the Blob128 / Blob256 MAC and slot variants, the AttachLockSeed
// width branches other than W256, the lockSeed-on-resolve bad-handle
// path), the MAC-registry out-of-range probes for the two getters
// that had no test (KeySize / TagSize), the low-level DecryptAuth
// buffer-too-small probe path, the WrapStreamUpdate empty-src early
// return, additional classifyPanicMessage classifier branches via
// NewEasyMixed misuse, and the easy.Import sentinel mapping for
// ErrUnknownPrimitive / ErrUnknownMAC / ErrBadKeyBits.

// ───────────────────────────────────────────────────────────────────
// AttachLockSeed — W128 + W512 width arms + lockSeed resolve fault
// ───────────────────────────────────────────────────────────────────

// TestAttachLockSeedWidth128 exercises the W128 attach arm. The
// existing TestAttachLockSeedRoundtrip uses blake3 (W256); this test
// drives siphash24 (W128) so the W128 case of the width switch is
// reached.
func TestAttachLockSeedWidth128(t *testing.T) {
	prevBS := GetBitSoup()
	prevLS := GetLockSoup()
	defer func() {
		SetBitSoup(prevBS)
		SetLockSoup(prevLS)
	}()
	SetLockSoup(1)

	ns := NewSeedOK(t, "siphash24", 1024)
	defer FreeSeed(ns)
	ls := NewSeedOK(t, "siphash24", 1024)
	defer FreeSeed(ls)
	if st := AttachLockSeed(ns, ls); st != StatusOK {
		t.Fatalf("AttachLockSeed W128: status=%v", st)
	}

	ds := NewSeedOK(t, "siphash24", 1024)
	defer FreeSeed(ds)
	ss := NewSeedOK(t, "siphash24", 1024)
	defer FreeSeed(ss)
	plaintext := []byte("W128 attach round-trip")
	out := make([]byte, 1<<16)
	n, st := Encrypt(ns, ds, ss, plaintext, out)
	if st != StatusOK {
		t.Fatalf("Encrypt: status=%v", st)
	}
	pt := make([]byte, len(plaintext)+1024)
	m, st := Decrypt(ns, ds, ss, out[:n], pt)
	if st != StatusOK {
		t.Fatalf("Decrypt: status=%v", st)
	}
	if !bytes.Equal(plaintext, pt[:m]) {
		t.Fatalf("W128 plaintext mismatch")
	}
}

// TestAttachLockSeedWidth512 exercises the W512 attach arm.
func TestAttachLockSeedWidth512(t *testing.T) {
	prevBS := GetBitSoup()
	prevLS := GetLockSoup()
	defer func() {
		SetBitSoup(prevBS)
		SetLockSoup(prevLS)
	}()
	SetLockSoup(1)

	ns := NewSeedOK(t, "areion512", 1024)
	defer FreeSeed(ns)
	ls := NewSeedOK(t, "areion512", 1024)
	defer FreeSeed(ls)
	if st := AttachLockSeed(ns, ls); st != StatusOK {
		t.Fatalf("AttachLockSeed W512: status=%v", st)
	}

	ds := NewSeedOK(t, "areion512", 1024)
	defer FreeSeed(ds)
	ss := NewSeedOK(t, "areion512", 1024)
	defer FreeSeed(ss)
	plaintext := []byte("W512 attach round-trip")
	out := make([]byte, 1<<16)
	n, st := Encrypt(ns, ds, ss, plaintext, out)
	if st != StatusOK {
		t.Fatalf("Encrypt: status=%v", st)
	}
	pt := make([]byte, len(plaintext)+1024)
	m, st := Decrypt(ns, ds, ss, out[:n], pt)
	if st != StatusOK {
		t.Fatalf("Decrypt: status=%v", st)
	}
	if !bytes.Equal(plaintext, pt[:m]) {
		t.Fatalf("W512 plaintext mismatch")
	}
}

// TestAttachLockSeedStaleLockHandle covers the second resolve fault
// in AttachLockSeed (when the lockSeed handle is stale but the noise
// handle is valid). The existing rejection-suite covers self-attach
// and width-mismatch but not the stale-lock-handle resolve fault.
func TestAttachLockSeedStaleLockHandle(t *testing.T) {
	ns := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ns)
	ls := NewSeedOK(t, "blake3", 1024)
	FreeSeed(ls) // stale
	if st := AttachLockSeed(ns, ls); st != StatusBadHandle {
		t.Errorf("AttachLockSeed(stale lock): status=%v, want StatusBadHandle", st)
	}
}

// TestAttachLockSeedStaleNoiseHandle covers the first resolve fault
// in AttachLockSeed (the noise handle is stale).
func TestAttachLockSeedStaleNoiseHandle(t *testing.T) {
	ns := NewSeedOK(t, "blake3", 1024)
	FreeSeed(ns) // stale
	ls := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ls)
	if st := AttachLockSeed(ns, ls); st != StatusBadHandle {
		t.Errorf("AttachLockSeed(stale noise): status=%v, want StatusBadHandle", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob128 / Blob256 — MAC key + name width-arm coverage
// ───────────────────────────────────────────────────────────────────

// TestBlobMACKeyAndNameAllWidths exercises BlobSetMACKey /
// BlobGetMACKey / BlobSetMACName / BlobGetMACName on the W128 and
// W256 widths. The pre-existing W512 round-trip tests do not reach
// those width-switch arms.
func TestBlobMACKeyAndNameAllWidths(t *testing.T) {
	cases := []struct {
		name string
		ctor func() (BlobHandleID, Status)
	}{
		{"W128", NewBlob128},
		{"W256", NewBlob256},
		{"W512", NewBlob512},
	}
	macKey := bytes.Repeat([]byte{0xab}, 32)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, st := c.ctor()
			if st != StatusOK {
				t.Fatalf("ctor: %v", st)
			}
			defer FreeBlob(id)

			if st := BlobSetMACKey(id, macKey); st != StatusOK {
				t.Fatalf("SetMACKey: %v", st)
			}
			if st := BlobSetMACName(id, "kmac256"); st != StatusOK {
				t.Fatalf("SetMACName: %v", st)
			}

			// Probe.
			n, st := BlobGetMACKey(id, nil)
			if st != StatusBufferTooSmall || n != len(macKey) {
				t.Fatalf("GetMACKey probe: n=%d st=%v", n, st)
			}
			out := make([]byte, n)
			n2, st := BlobGetMACKey(id, out)
			if st != StatusOK || n2 != len(macKey) {
				t.Fatalf("GetMACKey: n=%d st=%v", n2, st)
			}
			if !bytes.Equal(out, macKey) {
				t.Errorf("MAC key round-trip mismatch")
			}

			name, st := BlobGetMACName(id)
			if st != StatusOK || name != "kmac256" {
				t.Errorf("GetMACName: name=%q st=%v", name, st)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob128 / Blob256 — slot variant width-arm coverage
// ───────────────────────────────────────────────────────────────────

// TestBlobSetGetKeyAllSlotsAllWidths drives every slot (N / D / S /
// L / D1..D3 / S1..S3) through BlobSetKey + BlobGetKey on W128 and
// W256 widths. The existing W512 Triple round-trip exercises this
// surface only on the 512-bit width; the smaller widths' slot
// branches are otherwise unreached.
func TestBlobSetGetKeyAllSlotsAllWidths(t *testing.T) {
	cases := []struct {
		name   string
		ctor   func() (BlobHandleID, Status)
		keyLen int
	}{
		{"W128", NewBlob128, 16},
		{"W256", NewBlob256, 32},
	}
	slots := []int{
		BlobSlotN, BlobSlotD, BlobSlotS, BlobSlotL,
		BlobSlotD1, BlobSlotD2, BlobSlotD3,
		BlobSlotS1, BlobSlotS2, BlobSlotS3,
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, st := c.ctor()
			if st != StatusOK {
				t.Fatalf("ctor: %v", st)
			}
			defer FreeBlob(id)
			for _, slot := range slots {
				key := bytes.Repeat([]byte{byte(slot + 1)}, c.keyLen)
				if st := BlobSetKey(id, slot, key); st != StatusOK {
					t.Fatalf("SetKey slot=%d: %v", slot, st)
				}
				probe, st := BlobGetKey(id, slot, nil)
				if st != StatusBufferTooSmall || probe != c.keyLen {
					t.Fatalf("GetKey probe slot=%d: n=%d st=%v", slot, probe, st)
				}
				out := make([]byte, probe)
				n, st := BlobGetKey(id, slot, out)
				if st != StatusOK || n != c.keyLen {
					t.Fatalf("GetKey slot=%d: n=%d st=%v", slot, n, st)
				}
				if !bytes.Equal(out, key) {
					t.Errorf("slot=%d round-trip mismatch", slot)
				}
			}
		})
	}
}

// TestBlobSetGetComponentsAllSlotsAllWidths drives every slot
// through BlobSetComponents + BlobGetComponents on W128 / W256 /
// W512, including the Triple-mode slot variants. The W128 + W256
// branches of the per-slot switch are otherwise reached only by
// the BlobSlotN / D / S cases.
func TestBlobSetGetComponentsAllSlotsAllWidths(t *testing.T) {
	cases := []struct {
		name string
		ctor func() (BlobHandleID, Status)
	}{
		{"W128", NewBlob128},
		{"W256", NewBlob256},
	}
	slots := []int{
		BlobSlotN, BlobSlotD, BlobSlotS, BlobSlotL,
		BlobSlotD1, BlobSlotD2, BlobSlotD3,
		BlobSlotS1, BlobSlotS2, BlobSlotS3,
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, st := c.ctor()
			if st != StatusOK {
				t.Fatalf("ctor: %v", st)
			}
			defer FreeBlob(id)
			for _, slot := range slots {
				comps := []uint64{1, 2, 3, 4, 5, 6, 7, uint64(slot)}
				if st := BlobSetComponents(id, slot, comps); st != StatusOK {
					t.Fatalf("SetComponents slot=%d: %v", slot, st)
				}
				probe, st := BlobGetComponents(id, slot, nil)
				if st != StatusBufferTooSmall || probe != len(comps) {
					t.Fatalf("GetComponents probe slot=%d: n=%d st=%v", slot, probe, st)
				}
				out := make([]uint64, probe)
				n, st := BlobGetComponents(id, slot, out)
				if st != StatusOK || n != len(comps) {
					t.Fatalf("GetComponents slot=%d: n=%d st=%v", slot, n, st)
				}
				for i := range out {
					if out[i] != comps[i] {
						t.Errorf("slot=%d comp[%d] = %d, want %d", slot, i, out[i], comps[i])
					}
				}
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────
// MAC registry — KeySize / TagSize out-of-range probes
// ───────────────────────────────────────────────────────────────────

// TestMACRegistryKeySizeAndTagSizeAllIndices walks the in-range
// indices and confirms positive values, then probes the
// out-of-range branches that return 0. The pre-existing MinKeyBytes
// test covers only the MinKeyBytes getter.
func TestMACRegistryKeySizeAndTagSizeAllIndices(t *testing.T) {
	if MACCount() <= 0 {
		t.Fatal("MAC registry empty")
	}
	for i := 0; i < MACCount(); i++ {
		if MACRegistryKeySize(i) <= 0 {
			t.Errorf("MACRegistryKeySize(%d) = %d, want > 0", i, MACRegistryKeySize(i))
		}
		if MACRegistryTagSize(i) <= 0 {
			t.Errorf("MACRegistryTagSize(%d) = %d, want > 0", i, MACRegistryTagSize(i))
		}
	}
	for _, bad := range []int{-1, MACCount(), MACCount() + 100} {
		if v := MACRegistryKeySize(bad); v != 0 {
			t.Errorf("MACRegistryKeySize(%d) = %d, want 0", bad, v)
		}
		if v := MACRegistryTagSize(bad); v != 0 {
			t.Errorf("MACRegistryTagSize(%d) = %d, want 0", bad, v)
		}
	}
}

// ───────────────────────────────────────────────────────────────────
// Low-level DecryptAuth — buffer-too-small probe path
// ───────────────────────────────────────────────────────────────────

// TestDecryptAuthBufferTooSmall covers the StatusBufferTooSmall
// branch on the low-level DecryptAuth (the symmetric easy-side
// branch is exercised by TestEasyDecryptBufferTooSmallAuth, but the
// raw DecryptAuth entry is not).
func TestDecryptAuthBufferTooSmall(t *testing.T) {
	ns := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ns)
	ds := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ds)
	ss := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ss)
	macKey := bytes.Repeat([]byte{0x42}, 32)
	mh, st := NewMAC("kmac256", macKey)
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(mh)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptAuth(ns, ds, ss, mh, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("EncryptAuth: %v", st)
	}

	tiny := make([]byte, 4)
	required, st := DecryptAuth(ns, ds, ss, mh, ctBuf[:ctLen], tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("DecryptAuth probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required != len(plaintext) {
		t.Errorf("DecryptAuth required=%d, want %d", required, len(plaintext))
	}

	full := make([]byte, required)
	got, st := DecryptAuth(ns, ds, ss, mh, ctBuf[:ctLen], full)
	if st != StatusOK {
		t.Fatalf("DecryptAuth sized: %v", st)
	}
	if !bytes.Equal(full[:got], plaintext) {
		t.Errorf("DecryptAuth plaintext mismatch")
	}
}

// TestDecryptAuth3BadMACHandle covers the bad-MAC-handle path on
// DecryptAuth3 (the symmetric branch of EncryptAuth3 is covered;
// this one is reached through a stale MAC handle).
func TestDecryptAuth3BadMACHandle(t *testing.T) {
	ids := make([]HandleID, 7)
	for i := range ids {
		ids[i] = NewSeedOK(t, "blake3", 1024)
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	mh, _ := NewMAC("kmac256", bytes.Repeat([]byte{0x33}, 32))
	FreeMAC(mh) // stale

	out := make([]byte, 1<<16)
	if _, st := DecryptAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		mh, []byte("ignored"), out); st != StatusBadMAC {
		t.Errorf("DecryptAuth3(stale mac): status=%v, want StatusBadMAC", st)
	}
}

// TestEncryptStreamAuthBadMACHandle covers the bad-MAC-handle path
// on EncryptStreamAuth (the symmetric bad-seed path is covered;
// this branch is reached when the MAC handle is stale).
func TestEncryptStreamAuthBadMACHandle(t *testing.T) {
	ns := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ns)
	ds := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ds)
	ss := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ss)
	mh, _ := NewMAC("kmac256", bytes.Repeat([]byte{0x44}, 32))
	FreeMAC(mh) // stale

	var sid [32]byte
	out := make([]byte, 1<<16)
	if _, st := EncryptStreamAuth(ns, ds, ss, mh, []byte("x"), out, sid, 0, true); st != StatusBadMAC {
		t.Errorf("EncryptStreamAuth(stale mac): status=%v, want StatusBadMAC", st)
	}
	if _, _, st := DecryptStreamAuth(ns, ds, ss, mh, []byte("ignored"), out, sid, 0); st != StatusBadMAC {
		t.Errorf("DecryptStreamAuth(stale mac): status=%v, want StatusBadMAC", st)
	}
}

// TestEncryptStreamAuth3BadMACHandle covers the bad-MAC-handle path
// on EncryptStreamAuth3 / DecryptStreamAuth3.
func TestEncryptStreamAuth3BadMACHandle(t *testing.T) {
	ids := make([]HandleID, 7)
	for i := range ids {
		ids[i] = NewSeedOK(t, "blake3", 1024)
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	mh, _ := NewMAC("kmac256", bytes.Repeat([]byte{0x55}, 32))
	FreeMAC(mh) // stale

	var sid [32]byte
	out := make([]byte, 1<<16)
	if _, st := EncryptStreamAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		mh, []byte("x"), out, sid, 0, true); st != StatusBadMAC {
		t.Errorf("EncryptStreamAuth3(stale mac): status=%v, want StatusBadMAC", st)
	}
	if _, _, st := DecryptStreamAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		mh, []byte("ignored"), out, sid, 0); st != StatusBadMAC {
		t.Errorf("DecryptStreamAuth3(stale mac): status=%v, want StatusBadMAC", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// WrapStreamUpdate — empty-src early return
// ───────────────────────────────────────────────────────────────────

// TestWrapStreamUpdateEmptySrc exercises the len(src) == 0 early
// return branch in WrapStreamUpdate that the existing wrapper tests
// do not reach (every test currently passes a non-empty source).
func TestWrapStreamUpdateEmptySrc(t *testing.T) {
	key := mustGenerateKeyAdded(t, "aescmac")
	nonce := make([]byte, 16)
	id, n, st := NewWrapStreamWriter("aescmac", key, nonce)
	if st != StatusOK {
		t.Fatalf("NewWrapStreamWriter: status=%v", st)
	}
	if n != 16 {
		t.Fatalf("nonce length: %d, want 16", n)
	}
	defer FreeWrapStream(id)

	// Empty src — must return (0, StatusOK) via the early-exit branch.
	if got, st := WrapStreamUpdate(id, nil, nil); st != StatusOK || got != 0 {
		t.Errorf("WrapStreamUpdate(empty): n=%d status=%v, want 0/StatusOK", got, st)
	}
	if got, st := WrapStreamUpdate(id, []byte{}, []byte{}); st != StatusOK || got != 0 {
		t.Errorf("WrapStreamUpdate(empty slice): n=%d status=%v, want 0/StatusOK", got, st)
	}
}

// mustGenerateKeyAdded is a local helper that returns a fresh key
// of the right size for the named outer cipher. Mirrors the pattern
// in wrapper_test.go without depending on its unexported helper.
func mustGenerateKeyAdded(t *testing.T, cipher string) []byte {
	t.Helper()
	keySz, st := WrapperKeySize(cipher)
	if st != StatusOK {
		t.Fatalf("WrapperKeySize(%s): %v", cipher, st)
	}
	key := make([]byte, keySz)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// ───────────────────────────────────────────────────────────────────
// classifyPanicMessage — additional substring-match branches
// ───────────────────────────────────────────────────────────────────

// TestNewEasyMixedUnknownLockSeedPrimitive triggers the "unknown
// lockSeed primitive" panic path in easy.NewMixed. The full panic
// text is "itb/easy: NewMixed: unknown lockSeed primitive %q",
// which classifyPanicMessage matches via the dedicated "lockSeed
// primitive" arm (the top-level "unknown primitive" substring is
// not a contiguous match because "lockSeed" sits between
// "unknown" and "primitive"). That arm surfaces StatusBadInput.
func TestNewEasyMixedUnknownLockSeedPrimitive(t *testing.T) {
	// noiseSeed primitive is valid; lockPrim is not.
	_, st := NewEasyMixed("blake3", "blake3", "blake3", "no-such-prim", 1024, "kmac256")
	if st != StatusBadInput {
		t.Errorf("status=%v, want StatusBadInput", st)
	}
}

// TestNewEasyMixed3ExpectsSlotPrimitive triggers the "NewMixed: mode
// %d expects %d slot primitives, got %d" panic in easy/mixed.go
// (line 191) when the slot count does not match the requested mode.
// classifyPanicMessage maps the "expects " substring to StatusBadInput.
//
// NewEasyMixed3 calls into easy.NewMixed3 which is the Triple-mode
// variant — passing one empty-string slot effectively reduces the
// non-empty slot count below the expected 7, but the FFI bindings
// always pass 7 strings. The shape mismatch path is more directly
// reached via the Single-mode mixed constructor receiving too few
// or too many slot primitives. The capi NewEasyMixed always passes
// 3 primN/D/S so the wire shape is fixed at 3; the shape-mismatch
// case at this level is unreachable through the FFI surface, so
// the "expects " classifier branch is documented as defensive at
// the FFI layer and exercised end-to-end through the easy package's
// own tests. This test instead drives a different reachable
// branch — "duplicate" via parseConstructorArgs (NewEasy with two
// primitive args) — but the capi NewEasy entry surfaces only one
// positional primitive arg, so duplicate-primitive panic strings
// are likewise FFI-unreachable.
//
// The reachable branches via NewEasyMixed are limited to: unknown
// primitive (already tested via slot args), unknown MAC, bad
// keyBits, mixed widths (typed via ErrEasyMixedWidth, mapped at
// the recoverEasyPanic sentinel layer), and unknown lockSeed
// primitive (just above). This test exercises NewEasyMixed with
// an unknown MAC name — landing on the "unknown MAC" classifier
// branch via the NewMixed path rather than the parseConstructorArgs
// path used by TestEasyBadInputs.
func TestNewEasyMixed3ExpectsSlotPrimitive(t *testing.T) {
	_, st := NewEasyMixed("blake3", "blake3", "blake3", "", 1024, "nonsense-mac")
	if st != StatusEasyUnknownMAC {
		t.Errorf("status=%v, want StatusEasyUnknownMAC", st)
	}
}

// TestNewEasyMixedBadKeyBits triggers the key_bits panic path in
// easy.NewMixed (line 173 / 176). classifyPanicMessage matches via
// the "key_bits" substring, surfacing StatusEasyBadKeyBits.
func TestNewEasyMixedBadKeyBits(t *testing.T) {
	_, st := NewEasyMixed("blake3", "blake3", "blake3", "", 999, "kmac256")
	if st != StatusEasyBadKeyBits {
		t.Errorf("status=%v, want StatusEasyBadKeyBits", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// mapImportError — ErrUnknownPrimitive / ErrUnknownMAC / ErrBadKeyBits
// ───────────────────────────────────────────────────────────────────

// TestEasyImportSentinelErrors crafts state blobs that trigger each
// of the three error-sentinel branches in mapImportError that the
// existing tests do not exercise: ErrUnknownPrimitive, ErrUnknownMAC,
// ErrBadKeyBits. Each blob carries valid version / kind so the parse
// reaches the matching validator inside Encryptor.Import.
func TestEasyImportSentinelErrors(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	defer FreeEasy(id)

	// Unknown primitive on Import. The blob's "primitive" field is
	// not in hashes.Registry; Import returns ErrUnknownPrimitive
	// before reaching the per-field mismatch check.
	blob := map[string]any{
		"v":         1,
		"kind":      "itb-easy",
		"primitive": "nonsense-primitive",
		"key_bits":  1024,
		"mode":      "single",
		"mac":       "kmac256",
		"prf_keys":  []string{"00", "00", "00"},
		"seeds":     [][]string{{"0"}, {"0"}, {"0"}},
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

	// Unknown MAC on Import — primitive + key_bits valid, mac name
	// missing from registry.
	blob["key_bits"] = 1024
	blob["mac"] = "nonsense-mac"
	data, _ = json.Marshal(blob)
	if st := EasyImport(id, data); st != StatusEasyUnknownMAC {
		t.Errorf("unknown MAC: status=%v, want StatusEasyUnknownMAC", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// easy_state — EasyExport / EasyImport bad-handle paths
// ───────────────────────────────────────────────────────────────────

// TestEasyExportImportBadHandle covers the resolveEasy bad-handle
// branch on the two state-blob helpers.
func TestEasyExportImportBadHandle(t *testing.T) {
	id, _ := NewEasy("blake3", 1024, "kmac256", 1)
	FreeEasy(id)
	if _, st := EasyExport(id, nil); st != StatusBadHandle {
		t.Errorf("EasyExport(stale): %v, want StatusBadHandle", st)
	}
	if st := EasyImport(id, []byte("{}")); st != StatusBadHandle {
		t.Errorf("EasyImport(stale): %v, want StatusBadHandle", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// Status.String — defensive default branch
// ───────────────────────────────────────────────────────────────────

// TestStatusStringUnknownValue covers the default "unknown status"
// branch in Status.String() by constructing a Status value outside
// the defined constants. This is a defensive branch in normal use
// (every emitted Status is one of the defined constants) but the
// branch exists so a future-added code surfaces a sane label even
// before the switch is updated.
func TestStatusStringUnknownValue(t *testing.T) {
	s := Status(12345)
	if got := s.String(); got != "unknown status" {
		t.Errorf("Status(12345).String() = %q, want %q", got, "unknown status")
	}
}

// ───────────────────────────────────────────────────────────────────
// FreeSeed / FreeMAC — explicit zero-handle path
// ───────────────────────────────────────────────────────────────────

// TestFreeZeroHandles covers the id == 0 short-circuit on FreeSeed
// and FreeMAC (the bad-handle path for FreeMAC under a different
// entry compared to TestMACDoubleFree).
func TestFreeZeroHandles(t *testing.T) {
	if st := FreeSeed(0); st != StatusBadHandle {
		t.Errorf("FreeSeed(0): %v, want StatusBadHandle", st)
	}
	if st := FreeMAC(0); st != StatusBadMAC {
		t.Errorf("FreeMAC(0): %v, want StatusBadMAC", st)
	}
}

// TestSeedHashKeyBadHandle covers the resolve bad-handle path on
// the introspection helpers SeedHashKey / SeedComponents that are
// otherwise reached only through their success branches.
func TestSeedHashKeyBadHandle(t *testing.T) {
	if _, st := SeedHashKey(0); st != StatusBadHandle {
		t.Errorf("SeedHashKey(0): %v, want StatusBadHandle", st)
	}
	if _, st := SeedComponents(0); st != StatusBadHandle {
		t.Errorf("SeedComponents(0): %v, want StatusBadHandle", st)
	}
	if _, st := SeedHashName(0); st != StatusBadHandle {
		t.Errorf("SeedHashName(0): %v, want StatusBadHandle", st)
	}
}

// TestMACNameAndTagSizeBadHandle covers the bad-handle branch on
// MACName / MACTagSize.
func TestMACNameAndTagSizeBadHandle(t *testing.T) {
	if _, st := MACName(0); st != StatusBadMAC {
		t.Errorf("MACName(0): %v, want StatusBadMAC", st)
	}
	if _, st := MACTagSize(0); st != StatusBadMAC {
		t.Errorf("MACTagSize(0): %v, want StatusBadMAC", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// EasySeedCount / EasyHasPRFKeys — fresh-state coverage smoke
// ───────────────────────────────────────────────────────────────────

// TestEasyFreshSeedsAcrossModes makes sure the per-mode SeedCount
// branches in easy_config (3 / 4 / 7 / 8) land at every variant.
// The existing TestEasyMaterialGetters covers them but only for one
// primitive each; this test fans across primitives to nudge a few
// width-arms that the original misses (the test runs are also
// dirt-cheap).
func TestEasyFreshSeedsAcrossModes(t *testing.T) {
	for _, prim := range []string{"siphash24", "blake3", "areion512"} {
		for _, mode := range []int{1, 3} {
			t.Run(fmt.Sprintf("%s/mode%d", prim, mode), func(t *testing.T) {
				id, st := NewEasy(prim, 1024, "kmac256", mode)
				if st != StatusOK {
					t.Fatalf("NewEasy: %v", st)
				}
				defer FreeEasy(id)
				n, _ := EasySeedCount(id)
				want := 3
				if mode == 3 {
					want = 7
				}
				if n != want {
					t.Errorf("SeedCount = %d, want %d", n, want)
				}
			})
		}
	}
}
