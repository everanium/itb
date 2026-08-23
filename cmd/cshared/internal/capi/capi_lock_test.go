package capi

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Scope: width-arm branches not exercised by the existing test files
// (the Blob128 / Blob256 MAC and slot variants), MAC-registry
// out-of-range probes for KeySize / TagSize, the low-level
// DecryptAuth3 buffer-too-small probe path, the WrapStreamUpdate
// empty-src early return, and defensive-status-branch coverage.

// ───────────────────────────────────────────────────────────────────
// Blob128 / Blob256 — MAC key + name width-arm coverage
// ───────────────────────────────────────────────────────────────────

// TestBlobMACKeyAndNameAllWidths exercises BlobSetMACKey /
// BlobGetMACKey / BlobSetMACName / BlobGetMACName on every width.
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
// W256 widths. The Triple round-trip tests exercise this surface
// only on the 512-bit width; the smaller widths' slot branches are
// otherwise unreached.
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
// through BlobSetComponents + BlobGetComponents on W128 / W256.
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
// out-of-range branches that return 0.
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
// Low-level DecryptAuth3 — buffer-too-small probe path
// ───────────────────────────────────────────────────────────────────

// TestDecryptAuth3BufferTooSmallVariant covers a second
// StatusBufferTooSmall path on DecryptAuth3, encrypting a fresh
// message, then attempting to decrypt into a buffer too small for
// the recovered plaintext, then retrying with the correct size.
func TestDecryptAuth3BufferTooSmallVariant(t *testing.T) {
	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)
	macKey := bytes.Repeat([]byte{0x42}, 32)
	mh, st := NewMAC("kmac256", macKey)
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(mh)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		mh, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("EncryptAuth3: %v", st)
	}

	tiny := make([]byte, 4)
	required, st := DecryptAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		mh, ctBuf[:ctLen], tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("DecryptAuth3 probe: status=%v, want StatusBufferTooSmall", st)
	}
	if required != len(plaintext) {
		t.Errorf("DecryptAuth3 required=%d, want %d", required, len(plaintext))
	}

	full := make([]byte, required)
	got, st := DecryptAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		mh, ctBuf[:ctLen], full)
	if st != StatusOK {
		t.Fatalf("DecryptAuth3 sized: %v", st)
	}
	if !bytes.Equal(full[:got], plaintext) {
		t.Errorf("DecryptAuth3 plaintext mismatch")
	}
}

// TestDecryptAuth3BadMACHandle covers the bad-MAC-handle path on
// DecryptAuth3 (the symmetric branch of EncryptAuth3 is covered
// separately).
func TestDecryptAuth3BadMACHandle(t *testing.T) {
	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)
	mh, _ := NewMAC("kmac256", bytes.Repeat([]byte{0x33}, 32))
	FreeMAC(mh) // stale

	out := make([]byte, 1<<16)
	if _, st := DecryptAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		mh, []byte("ignored"), out); st != StatusBadMAC {
		t.Errorf("DecryptAuth3(stale mac): status=%v, want StatusBadMAC", st)
	}
}

// TestEncryptStreamAuth3BadMACHandle covers the bad-MAC-handle path
// on EncryptStreamAuth3 / DecryptStreamAuth3.
func TestEncryptStreamAuth3BadMACHandle(t *testing.T) {
	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)
	mh, _ := NewMAC("kmac256", bytes.Repeat([]byte{0x55}, 32))
	FreeMAC(mh) // stale

	var sid [32]byte
	out := make([]byte, 1<<16)
	if _, st := EncryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		mh, []byte("x"), out, sid, 0, true); st != StatusBadMAC {
		t.Errorf("EncryptStreamAuth3(stale mac): status=%v, want StatusBadMAC", st)
	}
	if _, _, st := DecryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
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
// of the right size for the named outer cipher.
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
// Status.String — defensive default branch
// ───────────────────────────────────────────────────────────────────

// TestStatusStringUnknownValue covers the default "unknown status"
// branch in Status.String() by constructing a Status value outside
// the defined constants.
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
// and FreeMAC.
func TestFreeZeroHandles(t *testing.T) {
	if st := FreeSeed(0); st != StatusBadHandle {
		t.Errorf("FreeSeed(0): %v, want StatusBadHandle", st)
	}
	if st := FreeMAC(0); st != StatusBadMAC {
		t.Errorf("FreeMAC(0): %v, want StatusBadMAC", st)
	}
}

// TestSeedHashKeyBadHandle covers the resolve bad-handle path on
// the introspection helpers SeedHashKey / SeedComponents /
// SeedHashName.
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

