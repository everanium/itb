package itb_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

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

// ───────────────────────────────────────────────────────────────────
// Cfg-aware Blob Export3Cfg / Import3Cfg error paths
// ───────────────────────────────────────────────────────────────────

// TestBlobMalformed exercises the Import3Cfg parser's rejection of
// obviously invalid JSON payloads: empty input, non-JSON bytes, an
// empty object missing required fields, and a JSON body with a
// non-hex Key* field.
func TestBlobMalformed(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		[]byte("not json"),
		[]byte("{}"),
		[]byte(`{"v":1,"mode":3,"key_bits":1024,"key_n":"zzzz"}`),
	} {
		bDst := &itb.Blob512{}
		if err := bDst.Import3Cfg(raw, &itb.Config{}); err == nil {
			t.Errorf("Import3Cfg malformed input %q: expected error", raw)
		}
	}
}

// TestBlobVersionTooNew exercises the version guard — a blob whose
// "v" field exceeds the highest version this build understands is
// rejected with ErrBlobVersionTooNew.
func TestBlobVersionTooNew(t *testing.T) {
	bDst := &itb.Blob512{}
	tooNew := []byte(`{"v":99,"mode":3,"key_bits":1024,"globals":{"nonce_bits":128,"barrier_fill":1}}`)
	if err := bDst.Import3Cfg(tooNew, &itb.Config{}); !errors.Is(err, itb.ErrBlobVersionTooNew) {
		t.Errorf("Import3Cfg too-new blob: got %v, want ErrBlobVersionTooNew", err)
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
	if err := bDst.Import3Cfg(withUnknown, &itb.Config{}); !errors.Is(err, itb.ErrBlobMalformed) {
		t.Errorf("Import3Cfg blob with unknown field: got %v, want ErrBlobMalformed", err)
	}
}

// TestBlobTooManyOpts confirms Export3Cfg rejects more than one
// options struct in the variadic trailing position.
func TestBlobTooManyOpts(t *testing.T) {
	ks := makeAreion512Keys(t, 8)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeed512Triple(t, ks)

	cfg := &itb.Config{NonceBits: 512, BarrierFill: 4}
	b := &itb.Blob512{}
	if _, err := b.Export3Cfg(cfg,
		ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
		ns, ds1, ds2, ds3, ss1, ss2, ss3,
		itb.Blob512Opts{LS: ls}, itb.Blob512Opts{},
	); !errors.Is(err, itb.ErrBlobTooManyOpts) {
		t.Errorf("Export3Cfg with two opts: got %v, want ErrBlobTooManyOpts", err)
	}
}

// ───────────────────────────────────────────────────────────────────
// Cfg-aware Blob Export3Cfg / Import3Cfg round-trips
// ───────────────────────────────────────────────────────────────────

// TestBlob512ExportImport3CfgRoundTrip exercises the Cfg-aware
// Export3Cfg / Import3Cfg surface at the 512-bit width. Round-tripped
// Cfg carries the ORIGINAL cfg values; a nil cfg supplied to
// Export3Cfg / Import3Cfg yields ErrBlobNilCfg.
func TestBlob512ExportImport3CfgRoundTrip(t *testing.T) {
	ks := makeAreion512Keys(t, 8)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeed512Triple(t, ks)

	t.Run("cfg_carries_maxworkers", func(t *testing.T) {
		cfg := &itb.Config{NonceBits: 256, BarrierFill: 8, MaxWorkers: 4}

		bSrc := &itb.Blob512{}
		opts := itb.Blob512Opts{KeyL: ks[1], LS: ls}
		data, err := bSrc.Export3Cfg(cfg,
			ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
			ns, ds1, ds2, ds3, ss1, ss2, ss3, opts,
		)
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}

		fresh := &itb.Config{}
		bDst := &itb.Blob512{}
		if err := bDst.Import3Cfg(data, fresh); err != nil {
			t.Fatalf("Import3Cfg: %v", err)
		}

		if fresh.NonceBits != 256 || fresh.BarrierFill != 8 || fresh.MaxWorkers != 4 {
			t.Fatalf("fresh Cfg = %+v, want {NonceBits:256 BarrierFill:8 MaxWorkers:4}", fresh)
		}
	})

	t.Run("nil_cfg_rejected", func(t *testing.T) {
		bSrc := &itb.Blob512{}
		if _, err := bSrc.Export3Cfg(nil,
			ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
		); !errors.Is(err, itb.ErrBlobNilCfg) {
			t.Errorf("Export3Cfg(nil): got %v, want ErrBlobNilCfg", err)
		}

		cfg := &itb.Config{NonceBits: 256, BarrierFill: 8}
		data, err := bSrc.Export3Cfg(cfg,
			ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
		)
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}
		bDst := &itb.Blob512{}
		if err := bDst.Import3Cfg(data, nil); !errors.Is(err, itb.ErrBlobNilCfg) {
			t.Errorf("Import3Cfg(nil): got %v, want ErrBlobNilCfg", err)
		}
	})
}

// TestBlob256ExportImport3CfgRoundTrip mirrors the 512-bit round-trip
// at the 256-bit width using BLAKE3.
func TestBlob256ExportImport3CfgRoundTrip(t *testing.T) {
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

	t.Run("cfg_carries_maxworkers", func(t *testing.T) {
		cfg := &itb.Config{NonceBits: 256, BarrierFill: 8, MaxWorkers: 4}

		bSrc := &itb.Blob256{}
		opts := itb.Blob256Opts{KeyL: keyL, LS: ls}
		data, err := bSrc.Export3Cfg(cfg, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3, opts)
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}

		fresh := &itb.Config{}
		bDst := &itb.Blob256{}
		if err := bDst.Import3Cfg(data, fresh); err != nil {
			t.Fatalf("Import3Cfg: %v", err)
		}

		if fresh.NonceBits != 256 || fresh.BarrierFill != 8 || fresh.MaxWorkers != 4 {
			t.Fatalf("fresh Cfg = %+v, want {NonceBits:256 BarrierFill:8 MaxWorkers:4}", fresh)
		}
	})

	t.Run("nil_cfg_rejected", func(t *testing.T) {
		bSrc := &itb.Blob256{}
		if _, err := bSrc.Export3Cfg(nil, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
		); !errors.Is(err, itb.ErrBlobNilCfg) {
			t.Errorf("Export3Cfg(nil): got %v, want ErrBlobNilCfg", err)
		}

		cfg := &itb.Config{NonceBits: 256, BarrierFill: 8}
		data, err := bSrc.Export3Cfg(cfg, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
		)
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}
		bDst := &itb.Blob256{}
		if err := bDst.Import3Cfg(data, nil); !errors.Is(err, itb.ErrBlobNilCfg) {
			t.Errorf("Import3Cfg(nil): got %v, want ErrBlobNilCfg", err)
		}
	})
}

// TestBlob128ExportImport3CfgRoundTrip mirrors the 512-bit round-trip
// at the 128-bit width using AES-CMAC (a 16-byte fixed-key primitive
// on this width — exercises the []byte key path).
func TestBlob128ExportImport3CfgRoundTrip(t *testing.T) {
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

	t.Run("cfg_carries_maxworkers", func(t *testing.T) {
		cfg := &itb.Config{NonceBits: 256, BarrierFill: 8, MaxWorkers: 4}

		bSrc := &itb.Blob128{}
		opts := itb.Blob128Opts{KeyL: keyL, LS: ls}
		data, err := bSrc.Export3Cfg(cfg, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3, opts)
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}

		fresh := &itb.Config{}
		bDst := &itb.Blob128{}
		if err := bDst.Import3Cfg(data, fresh); err != nil {
			t.Fatalf("Import3Cfg: %v", err)
		}

		if fresh.NonceBits != 256 || fresh.BarrierFill != 8 || fresh.MaxWorkers != 4 {
			t.Fatalf("fresh Cfg = %+v, want {NonceBits:256 BarrierFill:8 MaxWorkers:4}", fresh)
		}
	})

	t.Run("nil_cfg_rejected", func(t *testing.T) {
		bSrc := &itb.Blob128{}
		if _, err := bSrc.Export3Cfg(nil, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
		); !errors.Is(err, itb.ErrBlobNilCfg) {
			t.Errorf("Export3Cfg(nil): got %v, want ErrBlobNilCfg", err)
		}

		cfg := &itb.Config{NonceBits: 256, BarrierFill: 8}
		data, err := bSrc.Export3Cfg(cfg, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
		)
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}
		bDst := &itb.Blob128{}
		if err := bDst.Import3Cfg(data, nil); !errors.Is(err, itb.ErrBlobNilCfg) {
			t.Errorf("Import3Cfg(nil): got %v, want ErrBlobNilCfg", err)
		}
	})
}

// TestBlobV1MaxWorkersFieldBackCompat exercises the wire back-compat
// contract: a JSON blob that omits the "max_workers" key entirely
// is accepted by Import3Cfg and lands as cfg.MaxWorkers == 0.
func TestBlobV1MaxWorkersFieldBackCompat(t *testing.T) {
	// Build a legit 512-width Triple blob via Export3Cfg, then verify
	// the raw JSON has no "max_workers" key (Cfg carries MaxWorkers=0
	// so omitempty drops the field).
	ks := makeAreion512Keys(t, 8)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeed512Triple(t, ks)
	cfg := &itb.Config{NonceBits: 256, BarrierFill: 8}
	bSrc := &itb.Blob512{}
	data, err := bSrc.Export3Cfg(cfg,
		ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
		ns, ds1, ds2, ds3, ss1, ss2, ss3,
		itb.Blob512Opts{KeyL: ks[1], LS: ls},
	)
	if err != nil {
		t.Fatalf("Export3Cfg: %v", err)
	}
	if bytes.Contains(data, []byte("max_workers")) {
		t.Fatalf("wire unexpectedly carries max_workers key: %s", data)
	}

	// Round-trip the field-missing blob through Import3Cfg.
	fresh := &itb.Config{}
	bDst := &itb.Blob512{}
	if err := bDst.Import3Cfg(data, fresh); err != nil {
		t.Fatalf("Import3Cfg: %v", err)
	}
	if fresh.MaxWorkers != 0 {
		t.Errorf("field-missing blob decoded MaxWorkers = %d, want 0", fresh.MaxWorkers)
	}
	if fresh.NonceBits != 256 || fresh.BarrierFill != 8 {
		t.Errorf("field-missing blob decoded NonceBits/BarrierFill = %d/%d, want 256/8",
			fresh.NonceBits, fresh.BarrierFill)
	}
}

// TestBlobExportRejectsInvalidCfg pins the [Blob512.Export3Cfg]
// front-door validation for out-of-enum [itb.Config] values: a
// [Config.NonceBits] outside the shipped enum, an off-schedule
// [Config.BarrierFill], and a negative [Config.MaxWorkers] each
// prevent a poisoned blob from landing on the wire. The receiver's
// [Blob512.Import3Cfg] would refuse the resulting JSON downstream —
// the export-side reject moves the failure to the boundary where the
// misconfiguration originated.
func TestBlobExportRejectsInvalidCfg(t *testing.T) {
	ks := makeAreion512Keys(t, 8)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeed512Triple(t, ks)

	cases := []struct {
		label string
		cfg   *itb.Config
	}{
		{"bad_nonce_bits", &itb.Config{NonceBits: 999, BarrierFill: 1}},
		{"neg_nonce_bits", &itb.Config{NonceBits: -1, BarrierFill: 1}},
		{"bad_barrier_fill", &itb.Config{NonceBits: 256, BarrierFill: 5}},
		{"neg_barrier_fill", &itb.Config{NonceBits: 256, BarrierFill: -1}},
		{"huge_barrier_fill", &itb.Config{NonceBits: 256, BarrierFill: 1 << 30}},
		{"neg_max_workers", &itb.Config{NonceBits: 256, BarrierFill: 1, MaxWorkers: -1}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			b := &itb.Blob512{}
			out, err := b.Export3Cfg(c.cfg,
				ks[0], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7],
				ns, ds1, ds2, ds3, ss1, ss2, ss3,
				itb.Blob512Opts{KeyL: ks[1], LS: ls},
			)
			if err == nil {
				t.Fatalf("Export3Cfg accepted invalid cfg: %s (produced %d bytes)", c.label, len(out))
			}
		})
	}
}
