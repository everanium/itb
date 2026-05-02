package itb_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// withGlobals brackets a test region with explicit non-default
// globals (NonceBits=512, BarrierFill=4, BitSoup=1, LockSoup=1)
// and restores the prior state via t.Cleanup. Used by every
// blob round-trip test that exercises the Globals capture +
// apply path.
func withGlobals(t *testing.T) {
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

// resetGlobals forces all four globals to their defaults so an
// Import-applied snapshot can be detected via post-Import reads.
// Pairs with an outer t.Cleanup that restores the original state.
func resetGlobals() {
	itb.SetNonceBits(128)
	itb.SetBarrierFill(1)
	itb.SetBitSoup(0)
	itb.SetLockSoup(0)
}

// ───────────────────────────────────────────────────────────────────
// Blob512 — Areion-SoEM-512 round-trip
// ───────────────────────────────────────────────────────────────────

func TestBlob512SingleRoundtripFullMatrix(t *testing.T) {
	withGlobals(t)

	plaintext := []byte("blob512 single round-trip payload")

	for _, withLS := range []bool{false, true} {
		for _, withMAC := range []bool{false, true} {
			t.Run(blobMatrixName(withLS, withMAC), func(t *testing.T) {
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

				bSrc := &itb.Blob512{}
				opts := itb.Blob512Opts{}
				if withLS {
					opts.KeyL = keyL
					opts.LS = ls
				}
				if withMAC {
					opts.MACKey = macKey[:]
					opts.MACName = "kmac256"
				}
				data, err := bSrc.Export(keyN, keyD, keyS, ns, ds, ss, opts)
				if err != nil {
					t.Fatalf("Export: %v", err)
				}

				resetGlobals()
				bDst := &itb.Blob512{}
				if err := bDst.Import(data); err != nil {
					t.Fatalf("Import: %v", err)
				}

				assertGlobalsRestored(t, 512, 4, 1, 1)
				assertMode(t, bDst.Mode, 1)

				fnN2, batchN2 := itb.MakeAreionSoEM512HashWithKey(bDst.KeyN)
				fnD2, batchD2 := itb.MakeAreionSoEM512HashWithKey(bDst.KeyD)
				fnS2, batchS2 := itb.MakeAreionSoEM512HashWithKey(bDst.KeyS)
				bDst.NS.Hash, bDst.NS.BatchHash = fnN2, batchN2
				bDst.DS.Hash, bDst.DS.BatchHash = fnD2, batchD2
				bDst.SS.Hash, bDst.SS.BatchHash = fnS2, batchS2

				if withLS {
					if bDst.LS == nil {
						t.Fatalf("Import dropped lockSeed")
					}
					fnL2, batchL2 := itb.MakeAreionSoEM512HashWithKey(bDst.KeyL)
					bDst.LS.Hash, bDst.LS.BatchHash = fnL2, batchL2
					bDst.NS.AttachLockSeed(bDst.LS)
				}
				var mac2 itb.MACFunc
				if withMAC {
					if bDst.MACName != "kmac256" || !bytes.Equal(bDst.MACKey, macKey[:]) {
						t.Fatalf("MAC material mismatch after Import")
					}
					mac2, _ = macs.Make(bDst.MACName, bDst.MACKey)
				}

				var pt []byte
				if withMAC {
					pt, err = itb.DecryptAuthenticated512(bDst.NS, bDst.DS, bDst.SS, ct, mac2)
				} else {
					pt, err = itb.Decrypt512(bDst.NS, bDst.DS, bDst.SS, ct)
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

func TestBlob512TripleRoundtripFullMatrix(t *testing.T) {
	withGlobals(t)

	plaintext := []byte("blob512 triple round-trip payload")

	for _, withLS := range []bool{false, true} {
		for _, withMAC := range []bool{false, true} {
			t.Run(blobMatrixName(withLS, withMAC), func(t *testing.T) {
				ks := makeAreion512Keys(t, 7)
				ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSeed512Triple(t, ks)

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

				bSrc := &itb.Blob512{}
				opts := itb.Blob512Opts{}
				if withLS {
					opts.KeyL = keyL
					opts.LS = ls
				}
				if withMAC {
					opts.MACKey = macKey[:]
					opts.MACName = "kmac256"
				}
				data, err := bSrc.Export3(
					ks[0], ks[1], ks[2], ks[3], ks[4], ks[5], ks[6],
					ns, ds1, ds2, ds3, ss1, ss2, ss3, opts,
				)
				if err != nil {
					t.Fatalf("Export3: %v", err)
				}

				resetGlobals()
				bDst := &itb.Blob512{}
				if err := bDst.Import3(data); err != nil {
					t.Fatalf("Import3: %v", err)
				}
				assertGlobalsRestored(t, 512, 4, 1, 1)
				assertMode(t, bDst.Mode, 3)

				wireSeed512(bDst.NS, bDst.KeyN)
				wireSeed512(bDst.DS1, bDst.KeyD1)
				wireSeed512(bDst.DS2, bDst.KeyD2)
				wireSeed512(bDst.DS3, bDst.KeyD3)
				wireSeed512(bDst.SS1, bDst.KeyS1)
				wireSeed512(bDst.SS2, bDst.KeyS2)
				wireSeed512(bDst.SS3, bDst.KeyS3)

				if withLS {
					wireSeed512(bDst.LS, bDst.KeyL)
					bDst.NS.AttachLockSeed(bDst.LS)
				}
				var mac2 itb.MACFunc
				if withMAC {
					mac2, _ = macs.Make(bDst.MACName, bDst.MACKey)
				}

				var pt []byte
				if withMAC {
					pt, err = itb.DecryptAuthenticated3x512(
						bDst.NS, bDst.DS1, bDst.DS2, bDst.DS3, bDst.SS1, bDst.SS2, bDst.SS3, ct, mac2,
					)
				} else {
					pt, err = itb.Decrypt3x512(
						bDst.NS, bDst.DS1, bDst.DS2, bDst.DS3, bDst.SS1, bDst.SS2, bDst.SS3, ct,
					)
				}
				if err != nil {
					t.Fatalf("itb.Decrypt3x512: %v", err)
				}
				if !bytes.Equal(pt, plaintext) {
					t.Fatalf("plaintext mismatch")
				}
			})
		}
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob256 — BLAKE3 round-trip (covers 256-bit width branch)
// ───────────────────────────────────────────────────────────────────

func TestBlob256SingleRoundtrip(t *testing.T) {
	withGlobals(t)
	plaintext := []byte("blob256 single round-trip")

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

	bSrc := &itb.Blob256{}
	data, err := bSrc.Export(keyN, keyD, keyS, ns, ds, ss)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	resetGlobals()
	bDst := &itb.Blob256{}
	if err := bDst.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}
	assertGlobalsRestored(t, 512, 4, 1, 1)
	assertMode(t, bDst.Mode, 1)

	fnN2, batchN2 := hashes.BLAKE3256PairWithKey(bDst.KeyN)
	fnD2, batchD2 := hashes.BLAKE3256PairWithKey(bDst.KeyD)
	fnS2, batchS2 := hashes.BLAKE3256PairWithKey(bDst.KeyS)
	bDst.NS.Hash, bDst.NS.BatchHash = fnN2, batchN2
	bDst.DS.Hash, bDst.DS.BatchHash = fnD2, batchD2
	bDst.SS.Hash, bDst.SS.BatchHash = fnS2, batchS2

	pt, err := itb.Decrypt256(bDst.NS, bDst.DS, bDst.SS, ct)
	if err != nil {
		t.Fatalf("Decrypt256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestBlob256TripleRoundtrip(t *testing.T) {
	withGlobals(t)
	plaintext := []byte("blob256 triple round-trip")

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

	bSrc := &itb.Blob256{}
	data, err := bSrc.Export3(keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
		ns, ds1, ds2, ds3, ss1, ss2, ss3)
	if err != nil {
		t.Fatalf("Export3: %v", err)
	}

	resetGlobals()
	bDst := &itb.Blob256{}
	if err := bDst.Import3(data); err != nil {
		t.Fatalf("Import3: %v", err)
	}
	assertMode(t, bDst.Mode, 3)

	wireSeed256(bDst.NS, bDst.KeyN)
	wireSeed256(bDst.DS1, bDst.KeyD1)
	wireSeed256(bDst.DS2, bDst.KeyD2)
	wireSeed256(bDst.DS3, bDst.KeyD3)
	wireSeed256(bDst.SS1, bDst.KeyS1)
	wireSeed256(bDst.SS2, bDst.KeyS2)
	wireSeed256(bDst.SS3, bDst.KeyS3)

	pt, err := itb.Decrypt3x256(bDst.NS, bDst.DS1, bDst.DS2, bDst.DS3, bDst.SS1, bDst.SS2, bDst.SS3, ct)
	if err != nil {
		t.Fatalf("itb.Decrypt3x256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob128 — SipHash-2-4 (no fixed key) + AES-CMAC (16-byte key)
// ───────────────────────────────────────────────────────────────────

func TestBlob128SingleRoundtripSipHash(t *testing.T) {
	withGlobals(t)
	plaintext := []byte("blob128 siphash round-trip")

	mkSeed := func() *itb.Seed128 {
		fn := hashes.SipHash24()
		s, _ := itb.NewSeed128(1024, fn)
		return s
	}
	ns := mkSeed()
	ds := mkSeed()
	ss := mkSeed()

	ct, _ := itb.Encrypt128(ns, ds, ss, plaintext)

	bSrc := &itb.Blob128{}
	// SipHash has no fixed hash key — pass nil for keyN / keyD / keyS.
	data, err := bSrc.Export(nil, nil, nil, ns, ds, ss)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	resetGlobals()
	bDst := &itb.Blob128{}
	if err := bDst.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}
	assertMode(t, bDst.Mode, 1)
	if len(bDst.KeyN) != 0 || len(bDst.KeyD) != 0 || len(bDst.KeyS) != 0 {
		t.Fatalf("siphash blob carried non-empty hash keys: KeyN=%d KeyD=%d KeyS=%d",
			len(bDst.KeyN), len(bDst.KeyD), len(bDst.KeyS))
	}

	bDst.NS.Hash = hashes.SipHash24()
	bDst.DS.Hash = hashes.SipHash24()
	bDst.SS.Hash = hashes.SipHash24()

	pt, err := itb.Decrypt128(bDst.NS, bDst.DS, bDst.SS, ct)
	if err != nil {
		t.Fatalf("itb.Decrypt128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestBlob128SingleRoundtripAESCMAC(t *testing.T) {
	withGlobals(t)
	plaintext := []byte("blob128 aescmac round-trip")

	mkSeed := func() (*itb.Seed128, []byte) {
		fn, key := hashes.AESCMAC()
		s, _ := itb.NewSeed128(1024, fn)
		return s, key[:]
	}
	ns, keyN := mkSeed()
	ds, keyD := mkSeed()
	ss, keyS := mkSeed()

	ct, _ := itb.Encrypt128(ns, ds, ss, plaintext)

	bSrc := &itb.Blob128{}
	data, err := bSrc.Export(keyN, keyD, keyS, ns, ds, ss)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	resetGlobals()
	bDst := &itb.Blob128{}
	if err := bDst.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}
	assertMode(t, bDst.Mode, 1)
	if !bytes.Equal(bDst.KeyN, keyN) {
		t.Fatalf("KeyN mismatch")
	}

	var keyArr [16]byte
	copy(keyArr[:], bDst.KeyN)
	bDst.NS.Hash = hashes.AESCMACWithKey(keyArr)
	copy(keyArr[:], bDst.KeyD)
	bDst.DS.Hash = hashes.AESCMACWithKey(keyArr)
	copy(keyArr[:], bDst.KeyS)
	bDst.SS.Hash = hashes.AESCMACWithKey(keyArr)

	pt, err := itb.Decrypt128(bDst.NS, bDst.DS, bDst.SS, ct)
	if err != nil {
		t.Fatalf("itb.Decrypt128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Error paths
// ───────────────────────────────────────────────────────────────────

func TestBlobModeMismatch(t *testing.T) {
	withGlobals(t)
	fnN, batchN, keyN := itb.MakeAreionSoEM512Hash()
	fnD, batchD, keyD := itb.MakeAreionSoEM512Hash()
	fnS, batchS, keyS := itb.MakeAreionSoEM512Hash()
	ns, _ := itb.NewSeed512(2048, fnN)
	ds, _ := itb.NewSeed512(2048, fnD)
	ss, _ := itb.NewSeed512(2048, fnS)
	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	bSrc := &itb.Blob512{}
	singleData, _ := bSrc.Export(keyN, keyD, keyS, ns, ds, ss)

	bDst := &itb.Blob512{}
	if err := bDst.Import3(singleData); !errors.Is(err, itb.ErrBlobModeMismatch) {
		t.Errorf("Import3 on Single blob: got %v, want itb.ErrBlobModeMismatch", err)
	}

	// Triple → Import (Single)
	ks := makeAreion512Keys(t, 7)
	ns2, ds1, ds2, ds3, ss1, ss2, ss3 := makeSeed512Triple(t, ks)
	tripleData, _ := bSrc.Export3(
		ks[0], ks[1], ks[2], ks[3], ks[4], ks[5], ks[6],
		ns2, ds1, ds2, ds3, ss1, ss2, ss3,
	)
	if err := bDst.Import(tripleData); !errors.Is(err, itb.ErrBlobModeMismatch) {
		t.Errorf("Import on Triple blob: got %v, want itb.ErrBlobModeMismatch", err)
	}
}

func TestBlobMalformed(t *testing.T) {
	bDst := &itb.Blob512{}
	for _, raw := range [][]byte{
		nil,
		[]byte("not json"),
		[]byte("{}"),
		[]byte(`{"v":1,"mode":1,"key_bits":1024,"key_n":"zzzz"}`),
	} {
		if err := bDst.Import(raw); err == nil {
			t.Errorf("Import malformed input %q: expected error", raw)
		}
	}
}

func TestBlobVersionTooNew(t *testing.T) {
	bDst := &itb.Blob512{}
	tooNew := []byte(`{"v":99,"mode":1,"key_bits":1024,"globals":{"nonce_bits":128,"barrier_fill":1,"bit_soup":0,"lock_soup":0}}`)
	if err := bDst.Import(tooNew); !errors.Is(err, itb.ErrBlobVersionTooNew) {
		t.Errorf("Import too-new blob: got %v, want itb.ErrBlobVersionTooNew", err)
	}
}

func TestBlobTooManyOpts(t *testing.T) {
	withGlobals(t)
	fnN, batchN, keyN := itb.MakeAreionSoEM512Hash()
	fnD, batchD, keyD := itb.MakeAreionSoEM512Hash()
	fnS, batchS, keyS := itb.MakeAreionSoEM512Hash()
	ns, _ := itb.NewSeed512(2048, fnN)
	ds, _ := itb.NewSeed512(2048, fnD)
	ss, _ := itb.NewSeed512(2048, fnS)
	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	b := &itb.Blob512{}
	if _, err := b.Export(keyN, keyD, keyS, ns, ds, ss, itb.Blob512Opts{}, itb.Blob512Opts{}); !errors.Is(err, itb.ErrBlobTooManyOpts) {
		t.Errorf("Export with two opts: got %v, want itb.ErrBlobTooManyOpts", err)
	}
}

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

func blobMatrixName(withLS, withMAC bool) string {
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

func assertMode(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("Mode = %d, want %d", got, want)
	}
}

func assertGlobalsRestored(t *testing.T, nonce, barrier int, bitSoup, lockSoup int32) {
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

func makeAreion512Keys(t *testing.T, n int) [][64]byte {
	t.Helper()
	out := make([][64]byte, n)
	for i := 0; i < n; i++ {
		_, _, k := itb.MakeAreionSoEM512Hash()
		out[i] = k
	}
	return out
}

func makeSeed512Triple(t *testing.T, keys [][64]byte) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed512) {
	t.Helper()
	mk := func(key [64]byte) *itb.Seed512 {
		fn, batch := itb.MakeAreionSoEM512HashWithKey(key)
		s, err := itb.NewSeed512(2048, fn)
		if err != nil {
			t.Fatalf("itb.NewSeed512: %v", err)
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

func wireSeed512(s *itb.Seed512, key [64]byte) {
	fn, batch := itb.MakeAreionSoEM512HashWithKey(key)
	s.Hash = fn
	s.BatchHash = batch
}

func wireSeed256(s *itb.Seed256, key [32]byte) {
	fn, batch := hashes.BLAKE3256PairWithKey(key)
	s.Hash = fn
	s.BatchHash = batch
}
