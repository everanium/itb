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
// globals (NonceBits=512, BarrierFill=4) and restores the prior state
// via t.Cleanup. Used by every blob round-trip test that exercises the
// Globals capture + apply path.
func withGlobals(t *testing.T) {
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

// resetGlobals forces both globals to their defaults so an
// Import-applied snapshot can be detected via post-Import reads.
// Pairs with an outer t.Cleanup that restores the original state.
func resetGlobals() {
	itb.SetNonceBits(128)
	itb.SetBarrierFill(1)
}

// ───────────────────────────────────────────────────────────────────
// Blob512 — Areion-SoEM-512 Triple round-trip
// ───────────────────────────────────────────────────────────────────

func TestBlob512TripleRoundtripFullMatrix(t *testing.T) {
	withGlobals(t)

	plaintext := []byte("blob512 triple round-trip payload")

	for _, withMAC := range []bool{false, true} {
		t.Run(blobMatrixName(withMAC), func(t *testing.T) {
			ks := makeAreion512Keys(t, 8)
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeed512Triple(t, ks)

			var macKey [32]byte
			var mac itb.MACFunc
			if withMAC {
				_, _ = rand.Read(macKey[:])
				mac, _ = macs.KMAC256(macKey[:])
			}

			var ct []byte
			var err error
			if withMAC {
				ct, err = itb.EncryptAuthenticated3x512(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, mac)
			} else {
				ct, err = itb.Encrypt3x512(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
			}
			if err != nil {
				t.Fatalf("Encrypt3x512: %v", err)
			}

			bSrc := &itb.Blob512{}
			opts := itb.Blob512Opts{
				KeyL: ks[1],
				LS:   ls,
			}
			if withMAC {
				opts.MACKey = macKey[:]
				opts.MACName = "kmac256"
			}
			data, err := bSrc.Export3(
				ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
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
			assertGlobalsRestored(t, 512, 4)
			assertMode(t, bDst.Mode, 3)

			wireSeed512(bDst.NS, bDst.KeyN)
			wireSeed512(bDst.DS1, bDst.KeyD1)
			wireSeed512(bDst.DS2, bDst.KeyD2)
			wireSeed512(bDst.DS3, bDst.KeyD3)
			wireSeed512(bDst.SS1, bDst.KeyS1)
			wireSeed512(bDst.SS2, bDst.KeyS2)
			wireSeed512(bDst.SS3, bDst.KeyS3)

			if bDst.LS == nil {
				t.Fatalf("Import3 dropped lockSeed")
			}
			wireSeed512(bDst.LS, bDst.KeyL)

			var mac2 itb.MACFunc
			if withMAC {
				if bDst.MACName != "kmac256" || !bytes.Equal(bDst.MACKey, macKey[:]) {
					t.Fatalf("MAC material mismatch after Import3")
				}
				mac2, _ = macs.Make(bDst.MACName, bDst.MACKey)
			}

			var pt []byte
			if withMAC {
				pt, err = itb.DecryptAuthenticated3x512(
					bDst.NS, bDst.LS, bDst.DS1, bDst.DS2, bDst.DS3, bDst.SS1, bDst.SS2, bDst.SS3, ct, mac2,
				)
			} else {
				pt, err = itb.Decrypt3x512(
					bDst.NS, bDst.LS, bDst.DS1, bDst.DS2, bDst.DS3, bDst.SS1, bDst.SS2, bDst.SS3, ct,
				)
			}
			if err != nil {
				t.Fatalf("Decrypt3x512: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("plaintext mismatch")
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob256 — BLAKE3 Triple round-trip (covers 256-bit width branch)
// ───────────────────────────────────────────────────────────────────

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

	bSrc := &itb.Blob256{}
	opts := itb.Blob256Opts{KeyL: keyL, LS: ls}
	data, err := bSrc.Export3(keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
		ns, ds1, ds2, ds3, ss1, ss2, ss3, opts)
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
	if bDst.LS == nil {
		t.Fatalf("Import3 dropped lockSeed")
	}
	wireSeed256(bDst.LS, bDst.KeyL)

	pt, err := itb.Decrypt3x256(bDst.NS, bDst.LS, bDst.DS1, bDst.DS2, bDst.DS3, bDst.SS1, bDst.SS2, bDst.SS3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Blob128 — SipHash-2-4 (no fixed key) + AES-CMAC (16-byte key)
// Triple round-trip. Exercises both branches on the 128-bit width.
// ───────────────────────────────────────────────────────────────────

// TestBlob128TripleRoundtripSipHash exercises the 128-bit Triple
// Ouroboros Export3 / Import3 path under SipHash-2-4 — the primitive
// carries no fixed key so the eight hash-key arguments are nil.
func TestBlob128TripleRoundtripSipHash(t *testing.T) {
	withGlobals(t)
	plaintext := []byte("blob128 triple siphash round-trip")

	mkSeed := func() *itb.Seed128 {
		fn := hashes.SipHash24()
		s, _ := itb.NewSeed128(1024, fn)
		return s
	}
	ns := mkSeed()
	ls := mkSeed()
	ds1, ds2, ds3 := mkSeed(), mkSeed(), mkSeed()
	ss1, ss2, ss3 := mkSeed(), mkSeed(), mkSeed()

	ct, err := itb.Encrypt3x128(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x128: %v", err)
	}

	bSrc := &itb.Blob128{}
	opts := itb.Blob128Opts{KeyL: nil, LS: ls}
	data, err := bSrc.Export3(nil, nil, nil, nil, nil, nil, nil,
		ns, ds1, ds2, ds3, ss1, ss2, ss3, opts)
	if err != nil {
		t.Fatalf("Export3: %v", err)
	}

	resetGlobals()
	bDst := &itb.Blob128{}
	if err := bDst.Import3(data); err != nil {
		t.Fatalf("Import3: %v", err)
	}
	assertGlobalsRestored(t, 512, 4)
	assertMode(t, bDst.Mode, 3)

	bDst.NS.Hash = hashes.SipHash24()
	bDst.DS1.Hash = hashes.SipHash24()
	bDst.DS2.Hash = hashes.SipHash24()
	bDst.DS3.Hash = hashes.SipHash24()
	bDst.SS1.Hash = hashes.SipHash24()
	bDst.SS2.Hash = hashes.SipHash24()
	bDst.SS3.Hash = hashes.SipHash24()
	if bDst.LS == nil {
		t.Fatalf("Import3 dropped lockSeed")
	}
	bDst.LS.Hash = hashes.SipHash24()

	pt, err := itb.Decrypt3x128(bDst.NS, bDst.LS, bDst.DS1, bDst.DS2, bDst.DS3,
		bDst.SS1, bDst.SS2, bDst.SS3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestBlob128TripleRoundtripAESCMAC exercises the 128-bit Triple
// Ouroboros Export3 / Import3 path under AES-CMAC — each seed carries
// a distinct 16-byte fixed key that must round-trip via the blob's
// KeyN / KeyD1..3 / KeyS1..3 / KeyL fields.
func TestBlob128TripleRoundtripAESCMAC(t *testing.T) {
	withGlobals(t)
	plaintext := []byte("blob128 triple aescmac round-trip")

	mkSeed := func() (*itb.Seed128, []byte) {
		fn, key := hashes.AESCMAC()
		s, _ := itb.NewSeed128(1024, fn)
		return s, key[:]
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

	bSrc := &itb.Blob128{}
	opts := itb.Blob128Opts{KeyL: keyL, LS: ls}
	data, err := bSrc.Export3(keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
		ns, ds1, ds2, ds3, ss1, ss2, ss3, opts)
	if err != nil {
		t.Fatalf("Export3: %v", err)
	}

	resetGlobals()
	bDst := &itb.Blob128{}
	if err := bDst.Import3(data); err != nil {
		t.Fatalf("Import3: %v", err)
	}
	assertMode(t, bDst.Mode, 3)
	if !bytes.Equal(bDst.KeyN, keyN) {
		t.Fatalf("KeyN mismatch after Import3")
	}
	if bDst.LS == nil {
		t.Fatalf("Import3 dropped lockSeed")
	}

	wire := func(s *itb.Seed128, key []byte) {
		var arr [16]byte
		copy(arr[:], key)
		s.Hash = hashes.AESCMACWithKey(arr)
	}
	wire(bDst.NS, bDst.KeyN)
	wire(bDst.DS1, bDst.KeyD1)
	wire(bDst.DS2, bDst.KeyD2)
	wire(bDst.DS3, bDst.KeyD3)
	wire(bDst.SS1, bDst.KeyS1)
	wire(bDst.SS2, bDst.KeyS2)
	wire(bDst.SS3, bDst.KeyS3)
	wire(bDst.LS, bDst.KeyL)

	pt, err := itb.Decrypt3x128(bDst.NS, bDst.LS, bDst.DS1, bDst.DS2, bDst.DS3,
		bDst.SS1, bDst.SS2, bDst.SS3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────
// Error paths
// ───────────────────────────────────────────────────────────────────

// TestBlobMalformed exercises the Import parser's rejection of
// obviously invalid JSON payloads: empty input, non-JSON bytes, an
// empty object missing required fields, and a JSON body with a
// non-hex Key* field.
func TestBlobMalformed(t *testing.T) {
	bDst := &itb.Blob512{}
	for _, raw := range [][]byte{
		nil,
		[]byte("not json"),
		[]byte("{}"),
		[]byte(`{"v":1,"mode":3,"key_bits":1024,"key_n":"zzzz"}`),
	} {
		if err := bDst.Import3(raw); err == nil {
			t.Errorf("Import3 malformed input %q: expected error", raw)
		}
	}
}

// TestBlobVersionTooNew exercises the version guard — a blob whose
// "v" field exceeds the highest version this build understands is
// rejected with ErrBlobVersionTooNew.
func TestBlobVersionTooNew(t *testing.T) {
	bDst := &itb.Blob512{}
	tooNew := []byte(`{"v":99,"mode":3,"key_bits":1024,"globals":{"nonce_bits":128,"barrier_fill":1}}`)
	if err := bDst.Import3(tooNew); !errors.Is(err, itb.ErrBlobVersionTooNew) {
		t.Errorf("Import3 too-new blob: got %v, want ErrBlobVersionTooNew", err)
	}
}

// TestBlobImportRejectsUnknownFields verifies that a blob carrying
// extra (unknown) JSON fields is rejected as malformed rather than
// silently accepted. The decoder enables DisallowUnknownFields to
// harden the wire-format validation.
func TestBlobImportRejectsUnknownFields(t *testing.T) {
	bDst := &itb.Blob512{}
	// Otherwise-valid Triple blob shape with one extra unknown field
	// "extra_attacker_field" injected at the top level.
	withUnknown := []byte(`{"v":1,"mode":3,"key_bits":512,` +
		`"key_n":"00","ns":["0"],"ds1":["0"],"ds2":["0"],"ds3":["0"],` +
		`"ss1":["0"],"ss2":["0"],"ss3":["0"],` +
		`"globals":{"nonce_bits":128,"barrier_fill":1},` +
		`"extra_attacker_field":"oops"}`)
	if err := bDst.Import3(withUnknown); !errors.Is(err, itb.ErrBlobMalformed) {
		t.Errorf("Import3 blob with unknown field: got %v, want ErrBlobMalformed", err)
	}
}

// TestBlobTooManyOpts confirms Export3 rejects more than one options
// struct in the variadic trailing position.
func TestBlobTooManyOpts(t *testing.T) {
	withGlobals(t)
	ks := makeAreion512Keys(t, 8)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeed512Triple(t, ks)

	b := &itb.Blob512{}
	if _, err := b.Export3(ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
		ns, ds1, ds2, ds3, ss1, ss2, ss3,
		itb.Blob512Opts{LS: ls}, itb.Blob512Opts{},
	); !errors.Is(err, itb.ErrBlobTooManyOpts) {
		t.Errorf("Export3 with two opts: got %v, want ErrBlobTooManyOpts", err)
	}
}

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

func blobMatrixName(withMAC bool) string {
	if withMAC {
		return "lockseed_mac"
	}
	return "lockseed_nomac"
}

func assertMode(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("Mode = %d, want %d", got, want)
	}
}

func assertGlobalsRestored(t *testing.T, nonce, barrier int) {
	t.Helper()
	if g := itb.GetNonceBits(); g != nonce {
		t.Errorf("after Import: NonceBits = %d, want %d", g, nonce)
	}
	if g := itb.GetBarrierFill(); g != barrier {
		t.Errorf("after Import: BarrierFill = %d, want %d", g, barrier)
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

// makeEightSeed512Triple constructs the eight Triple-mode seeds from a
// pre-generated set of Areion-SoEM-512 fixed keys. Keys[0] wires the
// noiseSeed, keys[1] wires the dedicated lockSeed, and keys[2..7]
// wire the three data + three start seeds in canonical order.
func makeEightSeed512Triple(t *testing.T, keys [][64]byte) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed512) {
	t.Helper()
	if len(keys) < 8 {
		t.Fatalf("makeEightSeed512Triple: need 8 keys, got %d", len(keys))
	}
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
	ls = mk(keys[1])
	ds1 = mk(keys[2])
	ds2 = mk(keys[3])
	ds3 = mk(keys[4])
	ss1 = mk(keys[5])
	ss2 = mk(keys[6])
	ss3 = mk(keys[7])
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
