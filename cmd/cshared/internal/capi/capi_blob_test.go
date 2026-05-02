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
// non-default globals (NonceBits=512, BarrierFill=4, BitSoup=1,
// LockSoup=1) and restores the prior state via t.Cleanup. Mirrors
// the withGlobals helper in blob_test.go (external package); the
// capi package needs its own copy to avoid an import cycle.
func withCapiBlobGlobals(t *testing.T) {
	t.Helper()
	prevN := itb.GetNonceBits()
	prevB := itb.GetBarrierFill()
	prevBS := itb.GetBitSoup()
	prevLS := itb.GetLockSoup()
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	itb.SetBitSoup(1)
	itb.SetLockSoup(1)
	t.Cleanup(func() {
		itb.SetNonceBits(prevN)
		itb.SetBarrierFill(prevB)
		itb.SetBitSoup(prevBS)
		itb.SetLockSoup(prevLS)
	})
}

// resetCapiBlobGlobals forces all four globals to their defaults so
// an Import-applied snapshot can be detected via post-Import reads.
// Pairs with an outer t.Cleanup that restores the original state.
func resetCapiBlobGlobals() {
	itb.SetNonceBits(128)
	itb.SetBarrierFill(1)
	itb.SetBitSoup(0)
	itb.SetLockSoup(0)
}

// assertCapiGlobalsRestored verifies that BlobImport / BlobImport3
// applied the captured globals via SetNonceBits / SetBarrierFill /
// SetBitSoup / SetLockSoup.
func assertCapiGlobalsRestored(t *testing.T, nonce, barrier int, bitSoup, lockSoup int32) {
	t.Helper()
	if g := itb.GetNonceBits(); g != nonce {
		t.Errorf("after Import: NonceBits = %d, want %d", g, nonce)
	}
	if g := itb.GetBarrierFill(); g != barrier {
		t.Errorf("after Import: BarrierFill = %d, want %d", g, barrier)
	}
	if g := itb.GetBitSoup(); g != bitSoup {
		t.Errorf("after Import: BitSoup = %d, want %d", g, bitSoup)
	}
	if g := itb.GetLockSoup(); g != lockSoup {
		t.Errorf("after Import: LockSoup = %d, want %d", g, lockSoup)
	}
}

// blobMatrixCapiName mirrors blob_test.go's blobMatrixName so test
// subtests use the same naming convention across the two packages.
func blobMatrixCapiName(withLS, withMAC bool) string {
	switch {
	case withLS && withMAC:
		return "lockseed_mac"
	case withLS:
		return "lockseed_nomac"
	case withMAC:
		return "nolockseed_mac"
	default:
		return "nolockseed_nomac"
	}
}

// probeBlobBuf runs the standard caller-allocated-buffer probe
// (zero-cap call to discover required size, then sized call), used
// by every BlobExport / BlobExport3 wrapper test. Returns the blob
// bytes written, or fails the test on any non-OK status.
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
// Blob512 — Areion-SoEM-512 round-trip via capi handle
// ───────────────────────────────────────────────────────────────────

func TestCapiBlob512SingleRoundtripFullMatrix(t *testing.T) {
	withCapiBlobGlobals(t)

	plaintext := []byte("capi blob512 single round-trip payload")

	for _, withLS := range []bool{false, true} {
		for _, withMAC := range []bool{false, true} {
			t.Run(blobMatrixCapiName(withLS, withMAC), func(t *testing.T) {
				fnN, batchN, keyN := itb.MakeAreionSoEM512Hash()
				fnD, batchD, keyD := itb.MakeAreionSoEM512Hash()
				fnS, batchS, keyS := itb.MakeAreionSoEM512Hash()
				ns, _ := itb.NewSeed512(2048, fnN)
				ds, _ := itb.NewSeed512(2048, fnD)
				ss, _ := itb.NewSeed512(2048, fnS)
				ns.BatchHash = batchN
				ds.BatchHash = batchD
				ss.BatchHash = batchS

				var ls *itb.Seed512
				var keyL [64]byte
				if withLS {
					var fnL itb.HashFunc512
					var batchL itb.BatchHashFunc512
					fnL, batchL, keyL = itb.MakeAreionSoEM512Hash()
					ls, _ = itb.NewSeed512(2048, fnL)
					ls.BatchHash = batchL
					ns.AttachLockSeed(ls)
				}

				var macKey [32]byte
				var mac itb.MACFunc
				if withMAC {
					rand.Read(macKey[:])
					mac, _ = macs.KMAC256(macKey[:])
				}

				var ct []byte
				if withMAC {
					ct, _ = itb.EncryptAuthenticated512(ns, ds, ss, plaintext, mac)
				} else {
					ct, _ = itb.Encrypt512(ns, ds, ss, plaintext)
				}

				// Build the source handle, populate slots via Set*.
				idSrc, st := NewBlob512()
				if st != StatusOK {
					t.Fatalf("NewBlob512: status=%v", st)
				}
				defer FreeBlob(idSrc)

				if st := BlobSetKey(idSrc, BlobSlotN, keyN[:]); st != StatusOK {
					t.Fatalf("SetKey N: status=%v", st)
				}
				if st := BlobSetKey(idSrc, BlobSlotD, keyD[:]); st != StatusOK {
					t.Fatalf("SetKey D: status=%v", st)
				}
				if st := BlobSetKey(idSrc, BlobSlotS, keyS[:]); st != StatusOK {
					t.Fatalf("SetKey S: status=%v", st)
				}
				if st := BlobSetComponents(idSrc, BlobSlotN, ns.Components); st != StatusOK {
					t.Fatalf("SetComponents N: status=%v", st)
				}
				if st := BlobSetComponents(idSrc, BlobSlotD, ds.Components); st != StatusOK {
					t.Fatalf("SetComponents D: status=%v", st)
				}
				if st := BlobSetComponents(idSrc, BlobSlotS, ss.Components); st != StatusOK {
					t.Fatalf("SetComponents S: status=%v", st)
				}

				optsBitmask := 0
				if withLS {
					optsBitmask |= BlobOptLockSeed
					if st := BlobSetKey(idSrc, BlobSlotL, keyL[:]); st != StatusOK {
						t.Fatalf("SetKey L: status=%v", st)
					}
					if st := BlobSetComponents(idSrc, BlobSlotL, ls.Components); st != StatusOK {
						t.Fatalf("SetComponents L: status=%v", st)
					}
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
					return BlobExport(idSrc, optsBitmask, out)
				})

				resetCapiBlobGlobals()

				// Build the destination handle, Import.
				idDst, st := NewBlob512()
				if st != StatusOK {
					t.Fatalf("NewBlob512 dst: status=%v", st)
				}
				defer FreeBlob(idDst)

				if st := BlobImport(idDst, blob); st != StatusOK {
					t.Fatalf("BlobImport: status=%v, last=%q", st, LastError())
				}

				assertCapiGlobalsRestored(t, 512, 4, 1, 1)
				if mode, _ := BlobMode(idDst); mode != 1 {
					t.Fatalf("Mode after Import = %d, want 1", mode)
				}

				// Read slots back, wire factories, decrypt.
				dstKeyN := readKey64(t, idDst, BlobSlotN)
				dstKeyD := readKey64(t, idDst, BlobSlotD)
				dstKeyS := readKey64(t, idDst, BlobSlotS)
				dstNS := readSeed512(t, idDst, BlobSlotN, dstKeyN)
				dstDS := readSeed512(t, idDst, BlobSlotD, dstKeyD)
				dstSS := readSeed512(t, idDst, BlobSlotS, dstKeyS)

				if withLS {
					dstKeyL := readKey64(t, idDst, BlobSlotL)
					dstLS := readSeed512(t, idDst, BlobSlotL, dstKeyL)
					dstNS.AttachLockSeed(dstLS)
				}

				var mac2 itb.MACFunc
				if withMAC {
					macKey2 := readMACKey(t, idDst)
					macName2 := readMACName(t, idDst)
					if macName2 != "kmac256" || !bytes.Equal(macKey2, macKey[:]) {
						t.Fatalf("MAC material mismatch after Import")
					}
					mac2, _ = macs.Make(macName2, macKey2)
				}

				var pt []byte
				var err error
				if withMAC {
					pt, err = itb.DecryptAuthenticated512(dstNS, dstDS, dstSS, ct, mac2)
				} else {
					pt, err = itb.Decrypt512(dstNS, dstDS, dstSS, ct)
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
}

func TestCapiBlob512TripleRoundtripFullMatrix(t *testing.T) {
	withCapiBlobGlobals(t)

	plaintext := []byte("capi blob512 triple round-trip payload")

	for _, withLS := range []bool{false, true} {
		for _, withMAC := range []bool{false, true} {
			t.Run(blobMatrixCapiName(withLS, withMAC), func(t *testing.T) {
				ks := makeCapi512Keys(t, 7)
				ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeCapiSeed512Triple(t, ks)

				var ls *itb.Seed512
				var keyL [64]byte
				if withLS {
					fnL, batchL, k := itb.MakeAreionSoEM512Hash()
					keyL = k
					ls, _ = itb.NewSeed512(2048, fnL)
					ls.BatchHash = batchL
					ns.AttachLockSeed(ls)
				}

				var macKey [32]byte
				var mac itb.MACFunc
				if withMAC {
					rand.Read(macKey[:])
					mac, _ = macs.KMAC256(macKey[:])
				}

				var ct []byte
				if withMAC {
					ct, _ = itb.EncryptAuthenticated3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, mac)
				} else {
					ct, _ = itb.Encrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
				}

				idSrc, st := NewBlob512()
				if st != StatusOK {
					t.Fatalf("NewBlob512: status=%v", st)
				}
				defer FreeBlob(idSrc)

				slotKeys := []struct {
					slot int
					key  [64]byte
				}{
					{BlobSlotN, ks[0]},
					{BlobSlotD1, ks[1]},
					{BlobSlotD2, ks[2]},
					{BlobSlotD3, ks[3]},
					{BlobSlotS1, ks[4]},
					{BlobSlotS2, ks[5]},
					{BlobSlotS3, ks[6]},
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

				optsBitmask := 0
				if withLS {
					optsBitmask |= BlobOptLockSeed
					if st := BlobSetKey(idSrc, BlobSlotL, keyL[:]); st != StatusOK {
						t.Fatalf("SetKey L: status=%v", st)
					}
					if st := BlobSetComponents(idSrc, BlobSlotL, ls.Components); st != StatusOK {
						t.Fatalf("SetComponents L: status=%v", st)
					}
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
				assertCapiGlobalsRestored(t, 512, 4, 1, 1)
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

				if withLS {
					dstLS := readSeed512(t, idDst, BlobSlotL, readKey64(t, idDst, BlobSlotL))
					dstNS.AttachLockSeed(dstLS)
				}

				var mac2 itb.MACFunc
				if withMAC {
					mac2, _ = macs.Make(readMACName(t, idDst), readMACKey(t, idDst))
				}

				var pt []byte
				var err error
				if withMAC {
					pt, err = itb.DecryptAuthenticated3x512(dstNS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct, mac2)
				} else {
					pt, err = itb.Decrypt3x512(dstNS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct)
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
}

// ───────────────────────────────────────────────────────────────────
// Blob256 — BLAKE3 round-trip via capi handle
// ───────────────────────────────────────────────────────────────────

func TestCapiBlob256SingleRoundtrip(t *testing.T) {
	withCapiBlobGlobals(t)
	plaintext := []byte("capi blob256 single round-trip")

	fnN, batchN, keyN := hashes.BLAKE3256Pair()
	fnD, batchD, keyD := hashes.BLAKE3256Pair()
	fnS, batchS, keyS := hashes.BLAKE3256Pair()
	ns, _ := itb.NewSeed256(1024, fnN)
	ds, _ := itb.NewSeed256(1024, fnD)
	ss, _ := itb.NewSeed256(1024, fnS)
	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	ct, _ := itb.Encrypt256(ns, ds, ss, plaintext)

	idSrc, st := NewBlob256()
	if st != StatusOK {
		t.Fatalf("NewBlob256: status=%v", st)
	}
	defer FreeBlob(idSrc)

	if st := BlobSetKey(idSrc, BlobSlotN, keyN[:]); st != StatusOK {
		t.Fatalf("SetKey N: %v", st)
	}
	if st := BlobSetKey(idSrc, BlobSlotD, keyD[:]); st != StatusOK {
		t.Fatalf("SetKey D: %v", st)
	}
	if st := BlobSetKey(idSrc, BlobSlotS, keyS[:]); st != StatusOK {
		t.Fatalf("SetKey S: %v", st)
	}
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotD, ds.Components)
	BlobSetComponents(idSrc, BlobSlotS, ss.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport(idSrc, 0, out)
	})

	resetCapiBlobGlobals()

	idDst, st := NewBlob256()
	if st != StatusOK {
		t.Fatalf("NewBlob256 dst: %v", st)
	}
	defer FreeBlob(idDst)
	if st := BlobImport(idDst, blob); st != StatusOK {
		t.Fatalf("BlobImport: %v", st)
	}
	assertCapiGlobalsRestored(t, 512, 4, 1, 1)

	dstNS := readSeed256(t, idDst, BlobSlotN, readKey32(t, idDst, BlobSlotN))
	dstDS := readSeed256(t, idDst, BlobSlotD, readKey32(t, idDst, BlobSlotD))
	dstSS := readSeed256(t, idDst, BlobSlotS, readKey32(t, idDst, BlobSlotS))

	pt, err := itb.Decrypt256(dstNS, dstDS, dstSS, ct)
	if err != nil {
		t.Fatalf("Decrypt256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

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
	ds1, keyD1 := mkSeed()
	ds2, keyD2 := mkSeed()
	ds3, keyD3 := mkSeed()
	ss1, keyS1 := mkSeed()
	ss2, keyS2 := mkSeed()
	ss3, keyS3 := mkSeed()

	ct, _ := itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)

	idSrc, st := NewBlob256()
	if st != StatusOK {
		t.Fatalf("NewBlob256: %v", st)
	}
	defer FreeBlob(idSrc)
	BlobSetKey(idSrc, BlobSlotN, keyN[:])
	BlobSetKey(idSrc, BlobSlotD1, keyD1[:])
	BlobSetKey(idSrc, BlobSlotD2, keyD2[:])
	BlobSetKey(idSrc, BlobSlotD3, keyD3[:])
	BlobSetKey(idSrc, BlobSlotS1, keyS1[:])
	BlobSetKey(idSrc, BlobSlotS2, keyS2[:])
	BlobSetKey(idSrc, BlobSlotS3, keyS3[:])
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotD1, ds1.Components)
	BlobSetComponents(idSrc, BlobSlotD2, ds2.Components)
	BlobSetComponents(idSrc, BlobSlotD3, ds3.Components)
	BlobSetComponents(idSrc, BlobSlotS1, ss1.Components)
	BlobSetComponents(idSrc, BlobSlotS2, ss2.Components)
	BlobSetComponents(idSrc, BlobSlotS3, ss3.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport3(idSrc, 0, out)
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
	dstDS1 := readSeed256(t, idDst, BlobSlotD1, readKey32(t, idDst, BlobSlotD1))
	dstDS2 := readSeed256(t, idDst, BlobSlotD2, readKey32(t, idDst, BlobSlotD2))
	dstDS3 := readSeed256(t, idDst, BlobSlotD3, readKey32(t, idDst, BlobSlotD3))
	dstSS1 := readSeed256(t, idDst, BlobSlotS1, readKey32(t, idDst, BlobSlotS1))
	dstSS2 := readSeed256(t, idDst, BlobSlotS2, readKey32(t, idDst, BlobSlotS2))
	dstSS3 := readSeed256(t, idDst, BlobSlotS3, readKey32(t, idDst, BlobSlotS3))

	pt, err := itb.Decrypt3x256(dstNS, dstDS1, dstDS2, dstDS3, dstSS1, dstSS2, dstSS3, ct)
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

func TestCapiBlob128SingleRoundtripSipHash(t *testing.T) {
	withCapiBlobGlobals(t)
	plaintext := []byte("capi blob128 siphash round-trip")

	fnN, batchN := hashes.SipHash24Pair()
	fnD, batchD := hashes.SipHash24Pair()
	fnS, batchS := hashes.SipHash24Pair()
	ns, _ := itb.NewSeed128(512, fnN)
	ds, _ := itb.NewSeed128(512, fnD)
	ss, _ := itb.NewSeed128(512, fnS)
	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	ct, _ := itb.Encrypt128(ns, ds, ss, plaintext)

	idSrc, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128: %v", st)
	}
	defer FreeBlob(idSrc)
	BlobSetKey(idSrc, BlobSlotN, nil)
	BlobSetKey(idSrc, BlobSlotD, nil)
	BlobSetKey(idSrc, BlobSlotS, nil)
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotD, ds.Components)
	BlobSetComponents(idSrc, BlobSlotS, ss.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport(idSrc, 0, out)
	})

	resetCapiBlobGlobals()

	idDst, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128 dst: %v", st)
	}
	defer FreeBlob(idDst)
	if st := BlobImport(idDst, blob); st != StatusOK {
		t.Fatalf("BlobImport: %v", st)
	}

	dstNS := readSeed128SipHash(t, idDst, BlobSlotN)
	dstDS := readSeed128SipHash(t, idDst, BlobSlotD)
	dstSS := readSeed128SipHash(t, idDst, BlobSlotS)

	pt, err := itb.Decrypt128(dstNS, dstDS, dstSS, ct)
	if err != nil {
		t.Fatalf("Decrypt128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestCapiBlob128SingleRoundtripAESCMAC(t *testing.T) {
	withCapiBlobGlobals(t)
	plaintext := []byte("capi blob128 aescmac round-trip")

	fnN, batchN, keyN := hashes.AESCMACPair()
	fnD, batchD, keyD := hashes.AESCMACPair()
	fnS, batchS, keyS := hashes.AESCMACPair()
	ns, _ := itb.NewSeed128(512, fnN)
	ds, _ := itb.NewSeed128(512, fnD)
	ss, _ := itb.NewSeed128(512, fnS)
	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	ct, _ := itb.Encrypt128(ns, ds, ss, plaintext)

	idSrc, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128: %v", st)
	}
	defer FreeBlob(idSrc)
	BlobSetKey(idSrc, BlobSlotN, keyN[:])
	BlobSetKey(idSrc, BlobSlotD, keyD[:])
	BlobSetKey(idSrc, BlobSlotS, keyS[:])
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotD, ds.Components)
	BlobSetComponents(idSrc, BlobSlotS, ss.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport(idSrc, 0, out)
	})

	resetCapiBlobGlobals()

	idDst, st := NewBlob128()
	if st != StatusOK {
		t.Fatalf("NewBlob128 dst: %v", st)
	}
	defer FreeBlob(idDst)
	if st := BlobImport(idDst, blob); st != StatusOK {
		t.Fatalf("BlobImport: %v", st)
	}

	dstNS := readSeed128AESCMAC(t, idDst, BlobSlotN)
	dstDS := readSeed128AESCMAC(t, idDst, BlobSlotD)
	dstSS := readSeed128AESCMAC(t, idDst, BlobSlotS)

	pt, err := itb.Decrypt128(dstNS, dstDS, dstSS, ct)
	if err != nil {
		t.Fatalf("Decrypt128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Error paths — mode mismatch, malformed JSON, version too new
// ───────────────────────────────────────────────────────────────────

func TestCapiBlobModeMismatch(t *testing.T) {
	withCapiBlobGlobals(t)

	fnN, _, keyN := itb.MakeAreionSoEM512Hash()
	fnD, _, keyD := itb.MakeAreionSoEM512Hash()
	fnS, _, keyS := itb.MakeAreionSoEM512Hash()
	ns, _ := itb.NewSeed512(1024, fnN)
	ds, _ := itb.NewSeed512(1024, fnD)
	ss, _ := itb.NewSeed512(1024, fnS)

	idSrc, _ := NewBlob512()
	defer FreeBlob(idSrc)
	BlobSetKey(idSrc, BlobSlotN, keyN[:])
	BlobSetKey(idSrc, BlobSlotD, keyD[:])
	BlobSetKey(idSrc, BlobSlotS, keyS[:])
	BlobSetComponents(idSrc, BlobSlotN, ns.Components)
	BlobSetComponents(idSrc, BlobSlotD, ds.Components)
	BlobSetComponents(idSrc, BlobSlotS, ss.Components)

	blob := probeBlobBuf(t, func(out []byte) (int, Status) {
		return BlobExport(idSrc, 0, out) // mode=1
	})

	idDst, _ := NewBlob512()
	defer FreeBlob(idDst)
	if st := BlobImport3(idDst, blob); st != StatusBlobModeMismatch {
		t.Fatalf("Import3 on Single blob: status=%v, want StatusBlobModeMismatch", st)
	}
}

func TestCapiBlobMalformed(t *testing.T) {
	id, _ := NewBlob512()
	defer FreeBlob(id)
	if st := BlobImport(id, []byte("{not json")); st != StatusBlobMalformed {
		t.Fatalf("Import on garbage: status=%v, want StatusBlobMalformed", st)
	}
}

func TestCapiBlobVersionTooNew(t *testing.T) {
	// Construct a blob with version > current.
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
			"bit_soup":     0,
			"lock_soup":    0,
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

func makeCapi512Keys(t *testing.T, n int) [][64]byte {
	t.Helper()
	out := make([][64]byte, n)
	for i := 0; i < n; i++ {
		_, _, k := itb.MakeAreionSoEM512Hash()
		out[i] = k
	}
	return out
}

func makeCapiSeed512Triple(t *testing.T, keys [][64]byte) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed512) {
	t.Helper()
	mk := func(key [64]byte) *itb.Seed512 {
		fn, batch := itb.MakeAreionSoEM512HashWithKey(key)
		s, err := itb.NewSeed512(2048, fn)
		if err != nil {
			t.Fatalf("NewSeed512: %v", err)
		}
		s.BatchHash = batch
		return s
	}
	ns = mk(keys[0])
	ds1 = mk(keys[1])
	ds2 = mk(keys[2])
	ds3 = mk(keys[3])
	ss1 = mk(keys[4])
	ss2 = mk(keys[5])
	ss3 = mk(keys[6])
	return
}

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
	// Probe length first.
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
