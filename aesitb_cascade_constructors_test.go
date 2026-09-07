package itb_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// aesitb_cascade_constructors_test.go — cross-constructor agreement of
// aesitb128 seeds on the Low-Level surface. The batch-16 hook of an
// aesitb128 lockSeed selects the Interlocked Barrier cascade fill, so
// every constructor that yields a usable seed must attach it: a seed
// built by hashes.NewSeed128x16, the same seed exported through
// Blob128.Export3Cfg and rebuilt after Import3Cfg through
// hashes.SeedFromComponents128x16, and the same import wired by hand
// (Make128Pair arms + AttachFused128 + AttachInterlockBatch16) must
// decrypt each other's wire. The import wired with the arms only — the
// documented Low-Level hazard — is pinned as the negative: no error
// oracle, plaintext mismatch.

type aesitbConstellation struct {
	seeds [8]*itb.Seed128
	keys  [8][]byte
}

func newAESITBConstellation(t *testing.T, bits int) aesitbConstellation {
	t.Helper()
	var c aesitbConstellation
	for i := range c.seeds {
		s, key, err := hashes.NewSeed128x16(bits, hashes.CipherAESITB128)
		if err != nil {
			t.Fatal(err)
		}
		c.seeds[i], c.keys[i] = s, key
	}
	return c
}

func (c aesitbConstellation) encrypt(cfg *itb.Config, plain []byte) ([]byte, error) {
	s := c.seeds
	return itb.Encrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
}

func (c aesitbConstellation) decrypt(cfg *itb.Config, wire []byte) ([]byte, error) {
	s := c.seeds
	return itb.Decrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], wire)
}

// export round-trips the constellation through Blob128 and returns the
// imported blob; the imported seeds carry Components only.
func (c aesitbConstellation) export(t *testing.T, cfg *itb.Config) itb.Blob128 {
	t.Helper()
	var b itb.Blob128
	s, k := c.seeds, c.keys
	data, err := b.Export3Cfg(cfg, k[0], k[2], k[3], k[4], k[5], k[6], k[7],
		s[0], s[2], s[3], s[4], s[5], s[6], s[7], itb.Blob128Opts{KeyL: k[1], LS: s[1]})
	if err != nil {
		t.Fatalf("Export3Cfg: %v", err)
	}
	var in itb.Blob128
	if err := in.Import3Cfg(data, cfg); err != nil {
		t.Fatalf("Import3Cfg: %v", err)
	}
	return in
}

func blobSlots(b *itb.Blob128) ([8]*itb.Seed128, [8][]byte) {
	return [8]*itb.Seed128{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3},
		[8][]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
}

// rebuildHelper rebuilds every slot through hashes.SeedFromComponents128x16.
func rebuildHelper(t *testing.T, b *itb.Blob128) aesitbConstellation {
	t.Helper()
	raw, keys := blobSlots(b)
	var c aesitbConstellation
	for i := range raw {
		s, err := hashes.SeedFromComponents128x16(hashes.CipherAESITB128, keys[i], raw[i].Components...)
		if err != nil {
			t.Fatalf("SeedFromComponents128x16 slot %d: %v", i, err)
		}
		c.seeds[i], c.keys[i] = s, keys[i]
	}
	return c
}

// rebuildManual wires the imported seeds in place with the Hash /
// BatchHash arms and, when attach is set, the fused and batch-16 hooks.
func rebuildManual(t *testing.T, b *itb.Blob128, attach bool) aesitbConstellation {
	t.Helper()
	raw, keys := blobSlots(b)
	var c aesitbConstellation
	for i := range raw {
		single, batched, _, err := hashes.Make128Pair(hashes.CipherAESITB128, keys[i])
		if err != nil {
			t.Fatalf("Make128Pair slot %d: %v", i, err)
		}
		raw[i].Hash, raw[i].BatchHash = single, batched
		if attach {
			if err := hashes.AttachFused128(raw[i], hashes.CipherAESITB128, keys[i]); err != nil {
				t.Fatal(err)
			}
			if err := hashes.AttachInterlockBatch16(raw[i], hashes.CipherAESITB128, keys[i]); err != nil {
				t.Fatal(err)
			}
		}
		c.seeds[i], c.keys[i] = raw[i], keys[i]
	}
	return c
}

// TestAESITBCascadeCrossConstructorRoundTrip encrypts under the
// NewSeed128x16-built constellation and decrypts under each rebuilt
// variant, and back, at every key size; the arms-only import is the
// documented negative.
func TestAESITBCascadeCrossConstructorRoundTrip(t *testing.T) {
	cfg := &itb.Config{NonceBits: itb.DefaultNonceBits, BarrierFill: itb.DefaultBarrierFill}
	plain := make([]byte, 20_000)
	rand.Read(plain)
	for _, bits := range []int{512, 1024, 2048} {
		orig := newAESITBConstellation(t, bits)
		wire, err := orig.encrypt(cfg, plain)
		if err != nil {
			t.Fatalf("%d-bit encrypt: %v", bits, err)
		}
		blobHelper, blobManual, blobArms := orig.export(t, cfg), orig.export(t, cfg), orig.export(t, cfg)
		for _, v := range []struct {
			name string
			c    aesitbConstellation
			ok   bool
		}{
			{"helper", rebuildHelper(t, &blobHelper), true},
			{"manual-attach", rebuildManual(t, &blobManual, true), true},
			{"arms-only", rebuildManual(t, &blobArms, false), false},
		} {
			for i := range v.c.seeds {
				if (v.c.seeds[i].InterlockFillX16() != nil) != v.ok {
					t.Fatalf("%d-bit %s slot %d: batch-16 hook presence %v, want %v", bits, v.name, i, !v.ok, v.ok)
				}
			}
			got, err := v.c.decrypt(cfg, wire)
			match := err == nil && bytes.Equal(got, plain)
			if match != v.ok {
				t.Fatalf("%d-bit %s: decrypt of the original wire: err=%v match=%v, want match=%v", bits, v.name, err, match, v.ok)
			}
			if !v.ok {
				continue
			}
			back, err := v.c.encrypt(cfg, plain)
			if err != nil {
				t.Fatalf("%d-bit %s encrypt: %v", bits, v.name, err)
			}
			got, err = orig.decrypt(cfg, back)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("%d-bit %s: original constructor cannot decrypt the rebuilt constellation's wire: err=%v", bits, v.name, err)
			}
		}
	}
}
