package capi

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// withCapiBlobGlobals brackets a capi-blob test region with explicit
// non-default globals (NonceBits=512, BarrierFill=4) and restores
// the prior state via t.Cleanup. The BitSoup / LockSoup / LockBatch
// globals removed by the Interlocked Barrier merge are no longer
// captured or restored.
func withCapiBlobGlobals(t *testing.T) {
	t.Helper()
	prevN := itb.GetNonceBits()
	prevB := itb.GetBarrierFill()
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	t.Cleanup(func() {
		itb.SetNonceBits(prevN)
		itb.SetBarrierFill(prevB)
	})
}

// resetCapiBlobGlobals forces both globals to defaults so an
// Import-applied snapshot can be detected via post-Import reads.
// Pairs with an outer t.Cleanup that restores the original state.
func resetCapiBlobGlobals() {
	itb.SetNonceBits(128)
	itb.SetBarrierFill(1)
}

// assertCapiGlobalsRestored verifies that BlobImport / BlobImport3
// applied the captured globals via SetNonceBits / SetBarrierFill.
func assertCapiGlobalsRestored(t *testing.T, nonce, barrier int) {
	t.Helper()
	if g := itb.GetNonceBits(); g != nonce {
		t.Errorf("after Import: NonceBits = %d, want %d", g, nonce)
	}
	if g := itb.GetBarrierFill(); g != barrier {
		t.Errorf("after Import: BarrierFill = %d, want %d", g, barrier)
	}
}

// blobMatrixCapiName mirrors blob_test.go's blobMatrixName so test
// subtests use the same naming convention across the two packages.
// LockSeed is now mandatory in the Triple pipeline, so the "with"
// axis only varies MAC presence — every Triple encrypt call takes
// eight seeds via the mandatory lockSeed slot.
func blobMatrixCapiName(withMAC bool) string {
	if withMAC {
		return "mac"
	}
	return "nomac"
}

// probeBlobBuf runs the standard caller-allocated-buffer probe
// (zero-cap call to discover required size, then sized call), used
// by every BlobExport / BlobExport3 wrapper test.
func probeBlobBuf(t *testing.T, fn func(out []byte) (int, Status)) []byte {
	t.Helper()
	var probe [0]byte
	need, st := fn(probe[:])
	if st != StatusBufferTooSmall {
		t.Fatalf("probe expected StatusBufferTooSmall, got %v (last=%q)", st, LastError())
	}
	out := make([]byte, need)
	n, st := fn(out)
	if st != StatusOK {
		t.Fatalf("Export: status=%v, last=%q", st, LastError())
	}
	return out[:n]
}

// ───────────────────────────────────────────────────────────────────
// Blob512 — Areion-SoEM-512 Triple round-trip via capi handle
// ───────────────────────────────────────────────────────────────────

// TestCapiBlob512TripleRoundtrip drives the seven-seed Triple
// Export3 / Import3 path plus the optional MAC axis. LockSeed always
// travels as the 8th seed passed to Encrypt3x512 (mandatory), and it
// is populated via Blob512Opts.LS when a dedicated lockSeed is used
// alongside a distinct primitive; here every seed is Areion-SoEM-512
// under distinct random components so a single-primitive test suffices.
func TestCapiBlob512TripleRoundtripFullMatrix(t *testing.T) {
	withCapiBlobGlobals(t)

	plaintext := []byte("capi blob512 triple round-trip payload")

	for _, withMAC := range []bool{false, true} {
		t.Run(blobMatrixCapiName(withMAC), func(t *testing.T) {
			// Build 8 seeds directly. LockSeed rides in slot 1
			// (immediately after noiseSeed) per the v0.3.0 8-seed
			// API. The blob layer here serialises the 7 primary
			// slots (N + D1..D3 + S1..S3) via Export3 and the
			// dedicated lockSeed via Blob512Opts.LS.
			fnN, batchN, keyN := itb.MakeAreionSoEM512Hash()
			fnL, batchL, keyL := itb.MakeAreionSoEM512Hash()
			fnD1, batchD1, keyD1 := itb.MakeAreionSoEM512Hash()
			fnD2, batchD2, keyD2 := itb.MakeAreionSoEM512Hash()
			fnD3, batchD3, keyD3 := itb.MakeAreionSoEM512Hash()
			fnS1, batchS1, keyS1 := itb.MakeAreionSoEM512Hash()
			fnS2, batchS2, keyS2 := itb.MakeAreionSoEM512Hash()
			fnS3, batchS3, keyS3 := itb.MakeAreionSoEM512Hash()

			ns, _ := itb.NewSeed512(2048, fnN)
			ls, _ := itb.NewSeed512(2048, fnL)
			ds1, _ := itb.NewSeed512(2048, fnD1)
			ds2, _ := itb.NewSeed512(2048, fnD2)
			ds3, _ := itb.NewSeed512(2048, fnD3)
			ss1, _ := itb.NewSeed512(2048, fnS1)
			ss2, _ := itb.NewSeed512(2048, fnS2)
			ss3, _ := itb.NewSeed512(2048, fnS3)
			ns.BatchHash = batchN
			ls.BatchHash = batchL
			ds1.BatchHash = batchD1
			ds2.BatchHash = batchD2
			ds3.BatchHash = batchD3
			ss1.BatchHash = batchS1
			ss2.BatchHash = batchS2
			ss3.BatchHash = batchS3

			var macKey [32]byte
			var mac itb.MACFunc
			if withMAC {
				rand.Read(macKey[:])
				mac, _ = macs.KMAC256(macKey[:])
			}

			var ct []byte
			if withMAC {
				ct, _ = itb.EncryptAuthenticated3x512(
					ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, mac)
			} else {
				ct, _ = itb.Encrypt3x512(
					ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
			}

			idSrc, st := NewBlob512()
			if st != StatusOK {
				t.Fatalf("NewBlob512: status=%v", st)
			}
			defer FreeBlob(idSrc)

			// Populate the primary Triple slots via Set*.
			slotKeys := []struct {
				slot int
				key  [64]byte
			}{
				{BlobSlotN, keyN},
				{BlobSlotD1, keyD1},
				{BlobSlotD2, keyD2},
				{BlobSlotD3, keyD3},
				{BlobSlotS1, keyS1},
				{BlobSlotS2, keyS2},
				{BlobSlotS3, keyS3},
			}
			for _, sk := range slotKeys {
				if st := BlobSetKey(idSrc, sk.slot, sk.key[:]); st != StatusOK {
					t.Fatalf("SetKey slot=%d: status=%v", sk.slot, st)
				}
			}
			slotComps := []struct {
				slot  int
				seed  *itb.Seed512
				label string
			}{
				{BlobSlotN, ns, "N"},
				{BlobSlotD1, ds1, "D1"},
				{BlobSlotD2, ds2, "D2"},
				{BlobSlotD3, ds3, "D3"},
				{BlobSlotS1, ss1, "S1"},
				{BlobSlotS2, ss2, "S2"},
				{BlobSlotS3, ss3, "S3"},
			}
			for _, sc := range slotComps {
				if st := BlobSetComponents(idSrc, sc.slot, sc.seed.Components); st != StatusOK {
					t.Fatalf("SetComponents slot=%s: status=%v", sc.label, st)
				}
			}

			// Populate the dedicated lockSeed slot too (always
			// present in the 8-seed API).
			optsBitmask := BlobOptLockSeed
			if st := BlobSetKey(idSrc, BlobSlotL, keyL[:]); st != StatusOK {
				t.Fatalf("SetKey L: status=%v", st)
			}
			if st := BlobSetComponents(idSrc, BlobSlotL, ls.Components); st != StatusOK {
				t.Fatalf("SetComponents L: status=%v", st)
			}
			if withMAC {
				optsBitmask |= BlobOptMAC
				if st := BlobSetMACKey(idSrc, macKey[:]); st != StatusOK {
					t.Fatalf("SetMACKey: status=%v", st)
				}
				if st := BlobSetMACName(idSrc, "kmac256"); st != StatusOK {
					t.Fatalf("SetMACName: status=%v", st)
				}
			}

			blob := probeBlobBuf(t, func(out []byte) (int, Status) {
				return BlobExport3(idSrc, optsBitmask, out)
			})

			resetCapiBlobGlobals()

			idDst, st := NewBlob512()
			if st != StatusOK {
				t.Fatalf("NewBlob512 dst: status=%v", st)
			}
			defer FreeBlob(idDst)

			if st := BlobImport3(idDst, blob); st != StatusOK {
				t.Fatalf("BlobImport3: status=%v, last=%q", st, LastError())
			}
			assertCapiGlobalsRestored(t, 512, 4)
			if mode, _ := BlobMode(idDst); mode != 3 {
				t.Fatalf("Mode after Import3 = %d, want 3", mode)
			}

			dstNS := readSeed512(t, idDst, BlobSlotN, readKey64(t, idDst, BlobSlotN))
			dstDS1 := readSeed512(t, idDst, BlobSlotD1, readKey64(t, idDst, BlobSlotD1))
			dstDS2 := readSeed512(t, idDst, BlobSlotD2, readKey64(t, idDst, BlobSlotD2))
			dstDS3 := readSeed512(t, idDst, BlobSlotD3, readKey64(t, idDst, BlobSlotD3))
			dstSS1 := readSeed512(t, idDst, BlobSlotS1, readKey64(t, idDst, BlobSlotS1))
			dstSS2 := readSeed512(t, idDst, BlobSlotS2, readKey64(t, idDst, BlobSlotS2))
			dstSS3 := readSeed512(t, idDst, BlobSlotS3, readKey64(t, idDst, BlobSlotS3))
			dstLS := readSeed512(t, idDst, BlobSlotL, readKey64(t, idDst, BlobSlotL))

			var mac2 itb.MACFunc
			if withMAC {
				mac2, _ = macs.Make(readMACName(t, idDst), readMACKey(t, idDst))
			}

			var pt []byte
			var err error
			if withMAC {
				pt, err = itb.DecryptAuthenticated3x512(
					dstNS, dstLS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct, mac2)
			} else {
				pt, err = itb.Decrypt3x512(
					dstNS, dstLS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct)
			}
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("plaintext mismatch")
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob256 — BLAKE3 Triple round-trip via capi handle
// ───────────────────────────────────────────────────────────────────

func TestCapiBlob256TripleRoundtrip(t *testing.T) {
	withCapiBlobGlobals(t)
	plaintext := []byte("capi blob256 triple round-trip")

	mkSeed := func() (*itb.Seed256, [32]byte) {
		fn, batch, key := hashes.BLAKE3256Pair()
		s, _ := itb.NewSeed256(1024, fn)
		s.BatchHash = batch
		return s, key
	}
	ns, keyN := mkSeed()
	ls, keyL := mkSeed()
	ds1, keyD1 := mkSeed()
	ds2, keyD2 := mkSeed()
	ds3, keyD3 := mkSeed()
	ss1, keyS1 := mkSeed()
	ss2, keyS2 := mkSeed()
	ss3, keyS3 := mkSeed()

	ct, err := itb.Encrypt3x256(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256: %v", err)
	}

	idSrc, st := NewBlob256()
	if st != StatusOK {
		t.Fatalf("NewBlob256: %v", st)
	}
	defer FreeBlob(idSrc)
	BlobSetKey(idSrc, BlobSlotN, keyN[:])
	BlobSetKey(idSrc, BlobSlotL, keyL[:])
	BlobSetKey(idSrc, BlobSlotD1, keyD1[:])
	BlobSetKey(idSrc, BlobSlotD2, keyD2[:])
	BlobSetKey(idSrc, BlobSlotD3, keyD3[:])
	BlobSetKey(idSrc, BlobSlotS1, keyS1[:])
	BlobSetKey(idSrc, BlobSlotS2, keyS2[:])
	BlobSetKey(idSrc, BlobSlotS3, keyS3[:])
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotL, ls.Components)
	BlobSetComponents(idSrc, BlobSlotD1, ds1.Components)
	BlobSetComponents(idSrc, BlobSlotD2, ds2.Components)
	BlobSetComponents(idSrc, BlobSlotD3, ds3.Components)
	BlobSetComponents(idSrc, BlobSlotS1, ss1.Components)
	BlobSetComponents(idSrc, BlobSlotS2, ss2.Components)
	BlobSetComponents(idSrc, BlobSlotS3, ss3.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport3(idSrc, BlobOptLockSeed, out)
	})

	resetCapiBlobGlobals()

	idDst, st := NewBlob256()
	if st != StatusOK {
		t.Fatalf("NewBlob256 dst: %v", st)
	}
	defer FreeBlob(idDst)
	if st := BlobImport3(idDst, blob); st != StatusOK {
		t.Fatalf("BlobImport3: %v", st)
	}

	dstNS := readSeed256(t, idDst, BlobSlotN, readKey32(t, idDst, BlobSlotN))
	dstLS := readSeed256(t, idDst, BlobSlotL, readKey32(t, idDst, BlobSlotL))
	dstDS1 := readSeed256(t, idDst, BlobSlotD1, readKey32(t, idDst, BlobSlotD1))
	dstDS2 := readSeed256(t, idDst, BlobSlotD2, readKey32(t, idDst, BlobSlotD2))
	dstDS3 := readSeed256(t, idDst, BlobSlotD3, readKey32(t, idDst, BlobSlotD3))
	dstSS1 := readSeed256(t, idDst, BlobSlotS1, readKey32(t, idDst, BlobSlotS1))
	dstSS2 := readSeed256(t, idDst, BlobSlotS2, readKey32(t, idDst, BlobSlotS2))
	dstSS3 := readSeed256(t, idDst, BlobSlotS3, readKey32(t, idDst, BlobSlotS3))

	pt, err := itb.Decrypt3x256(dstNS, dstLS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob128 — SipHash-2-4 (no fixed key) and AES-CMAC (16-byte key)
// ───────────────────────────────────────────────────────────────────

func TestCapiBlob128TripleRoundtripSipHash(t *testing.T) {
	withCapiBlobGlobals(t)
	plaintext := []byte("capi blob128 siphash triple round-trip")

	mkSeed := func() *itb.Seed128 {
		fn, batch := hashes.SipHash24Pair()
		s, _ := itb.NewSeed128(512, fn)
		s.BatchHash = batch
		return s
	}
	ns := mkSeed()
	ls := mkSeed()
	ds1 := mkSeed()
	ds2 := mkSeed()
	ds3 := mkSeed()
	ss1 := mkSeed()
	ss2 := mkSeed()
	ss3 := mkSeed()

	ct, err := itb.Encrypt3x128(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x128: %v", err)
	}

	idSrc, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128: %v", st)
	}
	defer FreeBlob(idSrc)
	for _, slot := range []int{BlobSlotN, BlobSlotL, BlobSlotD1, BlobSlotD2, BlobSlotD3, BlobSlotS1, BlobSlotS2, BlobSlotS3} {
		BlobSetKey(idSrc, slot, nil)
	}
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotL, ls.Components)
	BlobSetComponents(idSrc, BlobSlotD1, ds1.Components)
	BlobSetComponents(idSrc, BlobSlotD2, ds2.Components)
	BlobSetComponents(idSrc, BlobSlotD3, ds3.Components)
	BlobSetComponents(idSrc, BlobSlotS1, ss1.Components)
	BlobSetComponents(idSrc, BlobSlotS2, ss2.Components)
	BlobSetComponents(idSrc, BlobSlotS3, ss3.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport3(idSrc, BlobOptLockSeed, out)
	})

	resetCapiBlobGlobals()

	idDst, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128 dst: %v", st)
	}
	defer FreeBlob(idDst)
	if st := BlobImport3(idDst, blob); st != StatusOK {
		t.Fatalf("BlobImport3: %v", st)
	}

	dstNS := readSeed128SipHash(t, idDst, BlobSlotN)
	dstLS := readSeed128SipHash(t, idDst, BlobSlotL)
	dstDS1 := readSeed128SipHash(t, idDst, BlobSlotD1)
	dstDS2 := readSeed128SipHash(t, idDst, BlobSlotD2)
	dstDS3 := readSeed128SipHash(t, idDst, BlobSlotD3)
	dstSS1 := readSeed128SipHash(t, idDst, BlobSlotS1)
	dstSS2 := readSeed128SipHash(t, idDst, BlobSlotS2)
	dstSS3 := readSeed128SipHash(t, idDst, BlobSlotS3)

	pt, err := itb.Decrypt3x128(dstNS, dstLS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestCapiBlob128TripleRoundtripAESCMAC(t *testing.T) {
	withCapiBlobGlobals(t)
	plaintext := []byte("capi blob128 aescmac triple round-trip")

	mkSeed := func() (*itb.Seed128, [16]byte) {
		fn, batch, key := hashes.AESCMACPair()
		s, _ := itb.NewSeed128(512, fn)
		s.BatchHash = batch
		return s, key
	}
	ns, keyN := mkSeed()
	ls, keyL := mkSeed()
	ds1, keyD1 := mkSeed()
	ds2, keyD2 := mkSeed()
	ds3, keyD3 := mkSeed()
	ss1, keyS1 := mkSeed()
	ss2, keyS2 := mkSeed()
	ss3, keyS3 := mkSeed()

	ct, err := itb.Encrypt3x128(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x128: %v", err)
	}

	idSrc, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128: %v", st)
	}
	defer FreeBlob(idSrc)
	BlobSetKey(idSrc, BlobSlotN, keyN[:])
	BlobSetKey(idSrc, BlobSlotL, keyL[:])
	BlobSetKey(idSrc, BlobSlotD1, keyD1[:])
	BlobSetKey(idSrc, BlobSlotD2, keyD2[:])
	BlobSetKey(idSrc, BlobSlotD3, keyD3[:])
	BlobSetKey(idSrc, BlobSlotS1, keyS1[:])
	BlobSetKey(idSrc, BlobSlotS2, keyS2[:])
	BlobSetKey(idSrc, BlobSlotS3, keyS3[:])
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotL, ls.Components)
	BlobSetComponents(idSrc, BlobSlotD1, ds1.Components)
	BlobSetComponents(idSrc, BlobSlotD2, ds2.Components)
	BlobSetComponents(idSrc, BlobSlotD3, ds3.Components)
	BlobSetComponents(idSrc, BlobSlotS1, ss1.Components)
	BlobSetComponents(idSrc, BlobSlotS2, ss2.Components)
	BlobSetComponents(idSrc, BlobSlotS3, ss3.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport3(idSrc, BlobOptLockSeed, out)
	})

	resetCapiBlobGlobals()

	idDst, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128 dst: %v", st)
	}
	defer FreeBlob(idDst)
	if st := BlobImport3(idDst, blob); st != StatusOK {
		t.Fatalf("BlobImport3: %v", st)
	}

	dstNS := readSeed128AESCMAC(t, idDst, BlobSlotN)
	dstLS := readSeed128AESCMAC(t, idDst, BlobSlotL)
	dstDS1 := readSeed128AESCMAC(t, idDst, BlobSlotD1)
	dstDS2 := readSeed128AESCMAC(t, idDst, BlobSlotD2)
	dstDS3 := readSeed128AESCMAC(t, idDst, BlobSlotD3)
	dstSS1 := readSeed128AESCMAC(t, idDst, BlobSlotS1)
	dstSS2 := readSeed128AESCMAC(t, idDst, BlobSlotS2)
	dstSS3 := readSeed128AESCMAC(t, idDst, BlobSlotS3)

	pt, err := itb.Decrypt3x128(dstNS, dstLS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Error paths — malformed JSON, version too new, bad handle
// ───────────────────────────────────────────────────────────────────

func TestCapiBlobMalformed(t *testing.T) {
	id, _ := NewBlob512()
	defer FreeBlob(id)
	if st := BlobImport(id, []byte("{not json")); st != StatusBlobMalformed {
		t.Fatalf("Import on garbage: status=%v, want StatusBlobMalformed", st)
	}
}

func TestCapiBlobVersionTooNew(t *testing.T) {
	// Construct a blob with version > current. The blob layer still
	// supports Mode == 1 in the JSON schema (Blob512.Import consumes
	// Single-mode blobs), so this fixture uses Mode == 1 fields but
	// with a too-new version stamp — the version check fires first.
	doc := map[string]any{
		"v":        99,
		"mode":     1,
		"key_bits": 512,
		"key_n":    bytesToHex(make([]byte, 64)),
		"key_d":    bytesToHex(make([]byte, 64)),
		"key_s":    bytesToHex(make([]byte, 64)),
		"ns":       []string{"0", "0", "0", "0", "0", "0", "0", "0"},
		"ds":       []string{"0", "0", "0", "0", "0", "0", "0", "0"},
		"ss":       []string{"0", "0", "0", "0", "0", "0", "0", "0"},
		"globals": map[string]any{
			"nonce_bits":   128,
			"barrier_fill": 1,
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewBlob512()
	defer FreeBlob(id)
	if st := BlobImport(id, data); st != StatusBlobVersionTooNew {
		t.Fatalf("Import on v=99: status=%v, want StatusBlobVersionTooNew", st)
	}
}

func TestCapiBlobBadHandle(t *testing.T) {
	if st := FreeBlob(0); st != StatusBadHandle {
		t.Fatalf("FreeBlob(0): status=%v, want StatusBadHandle", st)
	}
	if _, st := BlobMode(0); st != StatusBadHandle {
		t.Fatalf("BlobMode(0): status=%v, want StatusBadHandle", st)
	}
	if st := BlobSetKey(0, BlobSlotN, []byte{1, 2, 3}); st != StatusBadHandle {
		t.Fatalf("BlobSetKey(0): status=%v, want StatusBadHandle", st)
	}
}

// ───────────────────────────────────────────────────────────────────
// helpers
// ───────────────────────────────────────────────────────────────────

func readKey64(t *testing.T, id BlobHandleID, slot int) [64]byte {
	t.Helper()
	var arr [64]byte
	n, st := BlobGetKey(id, slot, arr[:])
	if st != StatusOK || n != 64 {
		t.Fatalf("BlobGetKey slot=%d: n=%d status=%v", slot, n, st)
	}
	return arr
}

func readKey32(t *testing.T, id BlobHandleID, slot int) [32]byte {
	t.Helper()
	var arr [32]byte
	n, st := BlobGetKey(id, slot, arr[:])
	if st != StatusOK || n != 32 {
		t.Fatalf("BlobGetKey slot=%d: n=%d status=%v", slot, n, st)
	}
	return arr
}

func readSeed512(t *testing.T, id BlobHandleID, slot int, key [64]byte) *itb.Seed512 {
	t.Helper()
	probeN, st := BlobGetComponents(id, slot, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("BlobGetComponents probe slot=%d: status=%v", slot, st)
	}
	comps := make([]uint64, probeN)
	n, st := BlobGetComponents(id, slot, comps)
	if st != StatusOK {
		t.Fatalf("BlobGetComponents slot=%d: n=%d status=%v", slot, n, st)
	}
	fn, batch := itb.MakeAreionSoEM512HashWithKey(key)
	s, err := itb.SeedFromComponents512(fn, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents512 slot=%d: %v", slot, err)
	}
	s.BatchHash = batch
	return s
}

func readSeed256(t *testing.T, id BlobHandleID, slot int, key [32]byte) *itb.Seed256 {
	t.Helper()
	probeN, st := BlobGetComponents(id, slot, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("BlobGetComponents probe slot=%d: status=%v", slot, st)
	}
	comps := make([]uint64, probeN)
	n, st := BlobGetComponents(id, slot, comps)
	if st != StatusOK {
		t.Fatalf("BlobGetComponents slot=%d: n=%d status=%v", slot, n, st)
	}
	fn, batch := hashes.BLAKE3256PairWithKey(key)
	s, err := itb.SeedFromComponents256(fn, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents256: %v", err)
	}
	s.BatchHash = batch
	return s
}

func readSeed128SipHash(t *testing.T, id BlobHandleID, slot int) *itb.Seed128 {
	t.Helper()
	probeN, st := BlobGetComponents(id, slot, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("BlobGetComponents probe slot=%d: status=%v", slot, st)
	}
	comps := make([]uint64, probeN)
	BlobGetComponents(id, slot, comps)
	fn, batch := hashes.SipHash24Pair()
	s, err := itb.SeedFromComponents128(fn, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents128: %v", err)
	}
	s.BatchHash = batch
	return s
}

func readSeed128AESCMAC(t *testing.T, id BlobHandleID, slot int) *itb.Seed128 {
	t.Helper()
	probeN, st := BlobGetComponents(id, slot, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("BlobGetComponents probe slot=%d: status=%v", slot, st)
	}
	comps := make([]uint64, probeN)
	BlobGetComponents(id, slot, comps)
	probeK, st := BlobGetKey(id, slot, nil)
	if st != StatusBufferTooSmall {
		t.Fatalf("BlobGetKey probe slot=%d: status=%v", slot, st)
	}
	key := make([]byte, probeK)
	BlobGetKey(id, slot, key)
	if len(key) != 16 {
		t.Fatalf("AES-CMAC key length = %d, want 16", len(key))
	}
	var keyArr [16]byte
	copy(keyArr[:], key)
	fn, batch := hashes.AESCMACPairWithKey(keyArr)
	s, err := itb.SeedFromComponents128(fn, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents128: %v", err)
	}
	s.BatchHash = batch
	return s
}

func readMACKey(t *testing.T, id BlobHandleID) []byte {
	t.Helper()
	probe, st := BlobGetMACKey(id, nil)
	if st != StatusOK && st != StatusBufferTooSmall {
		t.Fatalf("BlobGetMACKey probe: %v", st)
	}
	if probe == 0 {
		return nil
	}
	out := make([]byte, probe)
	n, st := BlobGetMACKey(id, out)
	if st != StatusOK {
		t.Fatalf("BlobGetMACKey: %v", st)
	}
	return out[:n]
}

func readMACName(t *testing.T, id BlobHandleID) string {
	t.Helper()
	name, st := BlobGetMACName(id)
	if st != StatusOK {
		t.Fatalf("BlobGetMACName: %v", st)
	}
	return name
}

func bytesToHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

// TestBlobWidthReturnsConstructedWidth covers BlobWidth across the
// three native hash widths.
func TestBlobWidthReturnsConstructedWidth(t *testing.T) {
	cases := []struct {
		name string
		ctor func() (BlobHandleID, Status)
		want int
	}{
		{"W128", NewBlob128, 128},
		{"W256", NewBlob256, 256},
		{"W512", NewBlob512, 512},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, st := c.ctor()
			if st != StatusOK {
				t.Fatalf("ctor: status=%v", st)
			}
			defer FreeBlob(id)
			w, st := BlobWidth(id)
			if st != StatusOK {
				t.Errorf("BlobWidth: status=%v", st)
			}
			if int(w) != c.want {
				t.Errorf("BlobWidth = %d, want %d", w, c.want)
			}
		})
	}

	// Bad handle path — zero id is rejected with StatusBadHandle.
	if _, st := BlobWidth(0); st != StatusBadHandle {
		t.Errorf("BlobWidth(0): status=%v, want StatusBadHandle", st)
	}
}

// TestBlobSetKeyBadLen exercises the wrong-key-length branches on
// the 256 and 512 widths (the 128 width accepts variable-length
// keys and is excluded).
func TestBlobSetKeyBadLen(t *testing.T) {
	id256, _ := NewBlob256()
	defer FreeBlob(id256)
	for _, sz := range []int{0, 1, 7, 31, 33, 64, 100} {
		if st := BlobSetKey(id256, BlobSlotN, make([]byte, sz)); st != StatusBadInput {
			t.Errorf("Blob256 SetKey(len=%d): status=%v, want StatusBadInput", sz, st)
		}
	}

	id512, _ := NewBlob512()
	defer FreeBlob(id512)
	for _, sz := range []int{0, 1, 7, 32, 63, 65, 128} {
		if st := BlobSetKey(id512, BlobSlotN, make([]byte, sz)); st != StatusBadInput {
			t.Errorf("Blob512 SetKey(len=%d): status=%v, want StatusBadInput", sz, st)
		}
	}
}

// TestBlobSetKeyBadSlot exercises the unknown-slot branch across all
// three widths.
func TestBlobSetKeyBadSlot(t *testing.T) {
	for _, c := range []struct {
		name string
		ctor func() (BlobHandleID, Status)
		key  []byte
	}{
		{"W128", NewBlob128, make([]byte, 16)},
		{"W256", NewBlob256, make([]byte, 32)},
		{"W512", NewBlob512, make([]byte, 64)},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, _ := c.ctor()
			defer FreeBlob(id)
			if st := BlobSetKey(id, 9999, c.key); st != StatusBadInput {
				t.Errorf("SetKey(bad slot): status=%v, want StatusBadInput", st)
			}
		})
	}
}

// TestBlobSetComponentsBadSlot exercises the unknown-slot branch on
// BlobSetComponents across all three widths.
func TestBlobSetComponentsBadSlot(t *testing.T) {
	for _, c := range []struct {
		name string
		ctor func() (BlobHandleID, Status)
	}{
		{"W128", NewBlob128},
		{"W256", NewBlob256},
		{"W512", NewBlob512},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, _ := c.ctor()
			defer FreeBlob(id)
			comps := make([]uint64, 8)
			if st := BlobSetComponents(id, 9999, comps); st != StatusBadInput {
				t.Errorf("SetComponents(bad slot): status=%v, want StatusBadInput", st)
			}
		})
	}
}

// TestBlobSetMACKeyBadHandle covers the stale-handle branch on
// BlobSetMACKey.
func TestBlobSetMACKeyBadHandle(t *testing.T) {
	id, _ := NewBlob512()
	FreeBlob(id) // stale
	if st := BlobSetMACKey(id, make([]byte, 32)); st != StatusBadHandle {
		t.Errorf("BlobSetMACKey(stale): status=%v, want StatusBadHandle", st)
	}
}

// TestBlobSetMACNameBadHandle is the BlobSetMACName counterpart of
// TestBlobSetMACKeyBadHandle.
func TestBlobSetMACNameBadHandle(t *testing.T) {
	id, _ := NewBlob512()
	FreeBlob(id)
	if st := BlobSetMACName(id, "kmac256"); st != StatusBadHandle {
		t.Errorf("BlobSetMACName(stale): status=%v, want StatusBadHandle", st)
	}
}

// TestBlobExportRejectsUnknownOptsBits verifies that bits in
// optsBitmask outside BlobOptLockSeed / BlobOptMAC surface as
// StatusBadInput — future-incompatibility guard against bindings
// setting an unknown bit expecting an option that doesn't exist.
func TestBlobExportRejectsUnknownOptsBits(t *testing.T) {
	id, _ := NewBlob512()
	defer FreeBlob(id)
	probe := make([]byte, 0)
	// Unknown bit 0x4 → BadInput.
	if _, st := BlobExport3(id, 0x4, probe); st != StatusBadInput {
		t.Errorf("BlobExport3 with unknown bit 0x4: %v, want StatusBadInput", st)
	}
	// Combined known + unknown — still rejected because of unknown.
	if _, st := BlobExport3(id, BlobOptLockSeed|0x10, probe); st != StatusBadInput {
		t.Errorf("BlobExport3 with mixed known+unknown bits: %v, want StatusBadInput", st)
	}
}

// TestLastErrorBadHandlePath confirms LastError reports a non-empty
// diagnostic after a stale-handle resolution failure.
func TestLastErrorBadHandlePath(t *testing.T) {
	if _, st := BlobWidth(0); st != StatusBadHandle {
		t.Fatalf("BlobWidth(0): status=%v, want StatusBadHandle", st)
	}
	if msg := LastError(); msg == "" {
		t.Errorf("LastError empty after stale-handle call; want non-empty")
	}
}

// TestBlobImportBadHandle covers the stale-handle branch on
// BlobImport / BlobImport3.
func TestBlobImportBadHandle(t *testing.T) {
	id, _ := NewBlob512()
	FreeBlob(id)
	if st := BlobImport(id, []byte("{}")); st != StatusBadHandle {
		t.Errorf("BlobImport(stale): status=%v, want StatusBadHandle", st)
	}
	if st := BlobImport3(id, []byte("{}")); st != StatusBadHandle {
		t.Errorf("BlobImport3(stale): status=%v, want StatusBadHandle", st)
	}
}

// TestBlobExportBadHandle covers the stale-handle branch on
// BlobExport / BlobExport3.
func TestBlobExportBadHandle(t *testing.T) {
	id, _ := NewBlob512()
	FreeBlob(id)
	probe := make([]byte, 0)
	if _, st := BlobExport(id, 0, probe); st != StatusBadHandle {
		t.Errorf("BlobExport(stale): status=%v, want StatusBadHandle", st)
	}
	if _, st := BlobExport3(id, 0, probe); st != StatusBadHandle {
		t.Errorf("BlobExport3(stale): status=%v, want StatusBadHandle", st)
	}
}

// TestBlobGetMACOnEmpty covers the empty-state branch on
// BlobGetMACKey / BlobGetMACName.
func TestBlobGetMACOnEmpty(t *testing.T) {
	id, _ := NewBlob512()
	defer FreeBlob(id)
	if n, st := BlobGetMACKey(id, nil); st != StatusOK || n != 0 {
		t.Errorf("BlobGetMACKey empty: n=%d status=%v, want 0/OK", n, st)
	}
	if name, st := BlobGetMACName(id); st != StatusOK || name != "" {
		t.Errorf("BlobGetMACName empty: name=%q status=%v, want empty/OK", name, st)
	}
}

// TestBlobGetKVBadSlot exercises the unknown-slot branch on
// BlobGetKey / BlobGetComponents across the three widths.
func TestBlobGetKVBadSlot(t *testing.T) {
	for _, c := range []struct {
		name string
		ctor func() (BlobHandleID, Status)
	}{
		{"W128", NewBlob128},
		{"W256", NewBlob256},
		{"W512", NewBlob512},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, _ := c.ctor()
			defer FreeBlob(id)
			buf := make([]byte, 64)
			if _, st := BlobGetKey(id, 9999, buf); st != StatusBadInput {
				t.Errorf("BlobGetKey(bad slot): status=%v, want StatusBadInput", st)
			}
			cbuf := make([]uint64, 8)
			if _, st := BlobGetComponents(id, 9999, cbuf); st != StatusBadInput {
				t.Errorf("BlobGetComponents(bad slot): status=%v, want StatusBadInput", st)
			}
		})
	}
}

// TestBlobGetKVStaleHandle covers the stale-handle resolve branch
// on the read-side helpers.
func TestBlobGetKVStaleHandle(t *testing.T) {
	id, _ := NewBlob512()
	FreeBlob(id)
	buf := make([]byte, 64)
	if _, st := BlobGetKey(id, BlobSlotN, buf); st != StatusBadHandle {
		t.Errorf("BlobGetKey(stale): status=%v, want StatusBadHandle", st)
	}
	cbuf := make([]uint64, 8)
	if _, st := BlobGetComponents(id, BlobSlotN, cbuf); st != StatusBadHandle {
		t.Errorf("BlobGetComponents(stale): status=%v, want StatusBadHandle", st)
	}
	if _, st := BlobGetMACKey(id, buf); st != StatusBadHandle {
		t.Errorf("BlobGetMACKey(stale): status=%v, want StatusBadHandle", st)
	}
	if _, st := BlobGetMACName(id); st != StatusBadHandle {
		t.Errorf("BlobGetMACName(stale): status=%v, want StatusBadHandle", st)
	}
}
