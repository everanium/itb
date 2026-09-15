package itb_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// cascade_constructors_test.go — cross-constructor agreement of
// Low-Level seeds at every width and for every shipped primitive. The
// Interlocked Barrier cascade fill is the wire for every lockSeed, and
// the optional fast-path hooks (fused cascade, batch-16 fill) never
// change it, so every constructor that yields a usable seed must
// decrypt every other constructor's wire: a seed built by hand from the
// registry arms with the hooks attached, the same seed exported through
// Blob{128,256,512}.Export3Cfg and rebuilt after Import3Cfg with the
// arms plus the attach helpers, and the same import wired with the arms
// only — no hook at all — must all decrypt each other's wire at every
// shipped key size.

// lowLevelConstellation is one eight-seed constellation with the
// per-slot primitive keys, typed by width through the any slots.
type lowLevelConstellation struct {
	name  string
	width hashes.Width
	seeds [8]any
	keys  [8][]byte
}

// newLowLevelConstellation builds the eight seeds through the
// name-keyed constructors — the path the triple package runs for every
// slot.
func newLowLevelConstellation(t *testing.T, name string, bits int) lowLevelConstellation {
	t.Helper()
	spec, ok := hashes.Find(name)
	if !ok {
		t.Fatalf("hashes.Find(%q)", name)
	}
	c := lowLevelConstellation{name: name, width: spec.Width}
	for i := range c.seeds {
		switch spec.Width {
		case hashes.W128:
			s, key, err := hashes.NewSeed128(name, bits)
			if err != nil {
				t.Fatal(err)
			}
			c.seeds[i], c.keys[i] = s, key
		case hashes.W256:
			s, key, err := hashes.NewSeed256(name, bits)
			if err != nil {
				t.Fatal(err)
			}
			c.seeds[i], c.keys[i] = s, key
		case hashes.W512:
			s, key, err := hashes.NewSeed512(name, bits)
			if err != nil {
				t.Fatal(err)
			}
			c.seeds[i], c.keys[i] = s, key
		}
	}
	return c
}

func (c lowLevelConstellation) encrypt(cfg *itb.Config, plain []byte) ([]byte, error) {
	s := c.seeds
	switch c.width {
	case hashes.W128:
		return itb.Encrypt3x128Cfg(cfg, s[0].(*itb.Seed128), s[1].(*itb.Seed128), s[2].(*itb.Seed128), s[3].(*itb.Seed128), s[4].(*itb.Seed128), s[5].(*itb.Seed128), s[6].(*itb.Seed128), s[7].(*itb.Seed128), plain)
	case hashes.W256:
		return itb.Encrypt3x256Cfg(cfg, s[0].(*itb.Seed256), s[1].(*itb.Seed256), s[2].(*itb.Seed256), s[3].(*itb.Seed256), s[4].(*itb.Seed256), s[5].(*itb.Seed256), s[6].(*itb.Seed256), s[7].(*itb.Seed256), plain)
	default:
		return itb.Encrypt3x512Cfg(cfg, s[0].(*itb.Seed512), s[1].(*itb.Seed512), s[2].(*itb.Seed512), s[3].(*itb.Seed512), s[4].(*itb.Seed512), s[5].(*itb.Seed512), s[6].(*itb.Seed512), s[7].(*itb.Seed512), plain)
	}
}

func (c lowLevelConstellation) decrypt(cfg *itb.Config, wire []byte) ([]byte, error) {
	s := c.seeds
	switch c.width {
	case hashes.W128:
		return itb.Decrypt3x128Cfg(cfg, s[0].(*itb.Seed128), s[1].(*itb.Seed128), s[2].(*itb.Seed128), s[3].(*itb.Seed128), s[4].(*itb.Seed128), s[5].(*itb.Seed128), s[6].(*itb.Seed128), s[7].(*itb.Seed128), wire)
	case hashes.W256:
		return itb.Decrypt3x256Cfg(cfg, s[0].(*itb.Seed256), s[1].(*itb.Seed256), s[2].(*itb.Seed256), s[3].(*itb.Seed256), s[4].(*itb.Seed256), s[5].(*itb.Seed256), s[6].(*itb.Seed256), s[7].(*itb.Seed256), wire)
	default:
		return itb.Decrypt3x512Cfg(cfg, s[0].(*itb.Seed512), s[1].(*itb.Seed512), s[2].(*itb.Seed512), s[3].(*itb.Seed512), s[4].(*itb.Seed512), s[5].(*itb.Seed512), s[6].(*itb.Seed512), s[7].(*itb.Seed512), wire)
	}
}

// hooked reports whether slot i carries every hook the width offers.
func (c lowLevelConstellation) hooked(i int) bool {
	switch s := c.seeds[i].(type) {
	case *itb.Seed128:
		return s.FusedChain != nil || s.BatchFusedChain != nil || s.InterlockFillX16() != nil
	case *itb.Seed256:
		return s.FusedChain != nil || s.BatchFusedChain != nil || s.BatchFusedChain8() != nil || s.InterlockFillX16() != nil || s.InterlockFillX32() != nil
	case *itb.Seed512:
		return s.FusedChain != nil || s.BatchFusedChain != nil || s.BatchFusedChain8() != nil || s.InterlockFillX16() != nil || s.InterlockFillX32() != nil
	}
	return false
}

// exportImport round-trips the constellation through the width's Blob
// and returns the imported slots (Components only) with their keys.
func (c lowLevelConstellation) exportImport(t *testing.T, cfg *itb.Config) ([8]any, [8][]byte) {
	t.Helper()
	s, k := c.seeds, c.keys
	var out [8]any
	var keys [8][]byte
	switch c.width {
	case hashes.W128:
		var b itb.Blob128
		data, err := b.Export3Cfg(cfg, k[0], k[2], k[3], k[4], k[5], k[6], k[7],
			s[0].(*itb.Seed128), s[2].(*itb.Seed128), s[3].(*itb.Seed128), s[4].(*itb.Seed128), s[5].(*itb.Seed128), s[6].(*itb.Seed128), s[7].(*itb.Seed128),
			itb.Blob128Opts{KeyL: k[1], LS: s[1].(*itb.Seed128)})
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}
		var in itb.Blob128
		if err := in.Import3Cfg(data, cfg); err != nil {
			t.Fatalf("Import3Cfg: %v", err)
		}
		out = [8]any{in.NS, in.LS, in.DS1, in.DS2, in.DS3, in.SS1, in.SS2, in.SS3}
		keys = [8][]byte{in.KeyN, in.KeyL, in.KeyD1, in.KeyD2, in.KeyD3, in.KeyS1, in.KeyS2, in.KeyS3}
	case hashes.W256:
		var k32 [8][32]byte
		for i := range k32 {
			copy(k32[i][:], k[i])
		}
		var b itb.Blob256
		data, err := b.Export3Cfg(cfg, k32[0], k32[2], k32[3], k32[4], k32[5], k32[6], k32[7],
			s[0].(*itb.Seed256), s[2].(*itb.Seed256), s[3].(*itb.Seed256), s[4].(*itb.Seed256), s[5].(*itb.Seed256), s[6].(*itb.Seed256), s[7].(*itb.Seed256),
			itb.Blob256Opts{KeyL: k32[1], LS: s[1].(*itb.Seed256)})
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}
		var in itb.Blob256
		if err := in.Import3Cfg(data, cfg); err != nil {
			t.Fatalf("Import3Cfg: %v", err)
		}
		out = [8]any{in.NS, in.LS, in.DS1, in.DS2, in.DS3, in.SS1, in.SS2, in.SS3}
		for i, kk := range [8][32]byte{in.KeyN, in.KeyL, in.KeyD1, in.KeyD2, in.KeyD3, in.KeyS1, in.KeyS2, in.KeyS3} {
			keys[i] = append([]byte(nil), kk[:]...)
		}
	default:
		var k64 [8][64]byte
		for i := range k64 {
			copy(k64[i][:], k[i])
		}
		var b itb.Blob512
		data, err := b.Export3Cfg(cfg, k64[0], k64[2], k64[3], k64[4], k64[5], k64[6], k64[7],
			s[0].(*itb.Seed512), s[2].(*itb.Seed512), s[3].(*itb.Seed512), s[4].(*itb.Seed512), s[5].(*itb.Seed512), s[6].(*itb.Seed512), s[7].(*itb.Seed512),
			itb.Blob512Opts{KeyL: k64[1], LS: s[1].(*itb.Seed512)})
		if err != nil {
			t.Fatalf("Export3Cfg: %v", err)
		}
		var in itb.Blob512
		if err := in.Import3Cfg(data, cfg); err != nil {
			t.Fatalf("Import3Cfg: %v", err)
		}
		out = [8]any{in.NS, in.LS, in.DS1, in.DS2, in.DS3, in.SS1, in.SS2, in.SS3}
		for i, kk := range [8][64]byte{in.KeyN, in.KeyL, in.KeyD1, in.KeyD2, in.KeyD3, in.KeyS1, in.KeyS2, in.KeyS3} {
			keys[i] = append([]byte(nil), kk[:]...)
		}
	}
	return out, keys
}

// rebuild wires the imported slots: hooked rebuilds every slot through
// the name-keyed restore constructor, which attaches every hook the
// width offers; arms-only wires the Hash / BatchHash arms alone onto the
// imported components.
func (c lowLevelConstellation) rebuild(t *testing.T, cfg *itb.Config, mode string) lowLevelConstellation {
	t.Helper()
	raw, keys := c.exportImport(t, cfg)
	out := lowLevelConstellation{name: c.name, width: c.width, keys: keys}
	for i := range raw {
		var keyArg [][]byte
		if len(keys[i]) > 0 {
			keyArg = [][]byte{keys[i]}
		}
		switch s := raw[i].(type) {
		case *itb.Seed128:
			if mode == "hooked" {
				h, err := hashes.SeedFromComponents128(c.name, keys[i], s.Components...)
				if err != nil {
					t.Fatalf("SeedFromComponents128 slot %d: %v", i, err)
				}
				out.seeds[i] = h
				continue
			}
			single, batched, _, err := hashes.Make128Pair(c.name, keyArg...)
			if err != nil {
				t.Fatalf("Make128Pair slot %d: %v", i, err)
			}
			s.Hash, s.BatchHash = single, batched
			out.seeds[i] = s
		case *itb.Seed256:
			if mode == "hooked" {
				h, err := hashes.SeedFromComponents256(c.name, keys[i], s.Components...)
				if err != nil {
					t.Fatalf("SeedFromComponents256 slot %d: %v", i, err)
				}
				out.seeds[i] = h
				continue
			}
			single, batched, _, err := hashes.Make256Pair(c.name, keyArg...)
			if err != nil {
				t.Fatalf("Make256Pair slot %d: %v", i, err)
			}
			s.Hash, s.BatchHash = single, batched
			out.seeds[i] = s
		case *itb.Seed512:
			if mode == "hooked" {
				h, err := hashes.SeedFromComponents512(c.name, keys[i], s.Components...)
				if err != nil {
					t.Fatalf("SeedFromComponents512 slot %d: %v", i, err)
				}
				out.seeds[i] = h
				continue
			}
			single, batched, _, err := hashes.Make512Pair(c.name, keyArg...)
			if err != nil {
				t.Fatalf("Make512Pair slot %d: %v", i, err)
			}
			s.Hash, s.BatchHash = single, batched
			out.seeds[i] = s
		}
	}
	return out
}

// TestCascadeCrossConstructorRoundTrip encrypts under the hand-built
// constellation and decrypts under each rebuilt variant, and back, for
// every shipped primitive at every key size. The arms-only rebuild —
// no hook on any slot — must decrypt the hooked constellation's wire:
// the hooks are performance paths and the cascade fill is the wire for
// every lockSeed.
func TestCascadeCrossConstructorRoundTrip(t *testing.T) {
	cfg := &itb.Config{NonceBits: itb.DefaultNonceBits, BarrierFill: itb.DefaultBarrierFill}
	plain := make([]byte, 6_000)
	rand.Read(plain)
	for _, spec := range hashes.Registry {
		for _, bits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%d", spec.Name, bits), func(t *testing.T) {
				orig := newLowLevelConstellation(t, spec.Name, bits)
				wire, err := orig.encrypt(cfg, plain)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				for _, mode := range []string{"hooked", "arms-only"} {
					v := orig.rebuild(t, cfg, mode)
					for i := range v.seeds {
						if mode == "arms-only" && v.hooked(i) {
							t.Fatalf("%s slot %d: arms-only rebuild carries a hook", mode, i)
						}
					}
					got, err := v.decrypt(cfg, wire)
					if err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("%s: decrypt of the original wire: err=%v match=%v", mode, err, bytes.Equal(got, plain))
					}
					back, err := v.encrypt(cfg, plain)
					if err != nil {
						t.Fatalf("%s encrypt: %v", mode, err)
					}
					got, err = orig.decrypt(cfg, back)
					if err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("%s: original constructor cannot decrypt the rebuilt constellation's wire: err=%v", mode, err)
					}
				}
			})
		}
	}
}
