package hashes

import (
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"

	"github.com/everanium/itb"
)

// seed_attach_wide_test.go — the width-256 / width-512 attach surface:
// AttachFused256 / AttachInterlockBatch16x256 and their 512 twins. Every
// shipped entry leaves the wide factory fields nil, so the helpers are
// pinned as no-ops on the registry and exercised through custom
// primitives registered with pure-Go whole-cascade factories.

// wideAttachCase is one width's attach surface, expressed through the
// registry-agnostic operations the tests below need.
type wideAttachCase struct {
	width Width
	// registryNoOp attaches both helpers to a fresh seed of the named
	// shipped primitive and reports whether any hook was populated.
	registryNoOp func(t *testing.T, name string) bool
}

var wideAttachCases = []wideAttachCase{
	{W256, func(t *testing.T, name string) bool {
		s, err := newSeed256(name, 512)
		if err != nil {
			t.Fatal(err)
		}
		_, _, key, err := Make256Pair(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := AttachFused256(s, name, key); err != nil {
			t.Fatalf("AttachFused256: %v", err)
		}
		if err := AttachInterlockBatch16x256(s, name, key); err != nil {
			t.Fatalf("AttachInterlockBatch16x256: %v", err)
		}
		return s.FusedChain != nil || s.BatchFusedChain != nil || s.InterlockFillX16() != nil
	}},
	{W512, func(t *testing.T, name string) bool {
		s, err := newSeed512(name, 512)
		if err != nil {
			t.Fatal(err)
		}
		_, _, key, err := Make512Pair(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := AttachFused512(s, name, key); err != nil {
			t.Fatalf("AttachFused512: %v", err)
		}
		if err := AttachInterlockBatch16x512(s, name, key); err != nil {
			t.Fatalf("AttachInterlockBatch16x512: %v", err)
		}
		return s.FusedChain != nil || s.BatchFusedChain != nil || s.InterlockFillX16() != nil
	}},
}

// TestWideAttachHelpersRegistry pins, for every shipped width-256 /
// width-512 entry, that the attach helpers populate the hooks exactly
// when the entry carries a wide factory field and return without error
// and without touching the seed otherwise.
func TestWideAttachHelpersRegistry(t *testing.T) {
	for _, spec := range Registry {
		for _, c := range wideAttachCases {
			if spec.Width != c.width {
				continue
			}
			t.Run(spec.Name, func(t *testing.T) {
				var has bool
				switch c.width {
				case W256:
					has = spec.FusedChainHash256 != nil || spec.InterlockFillBatch16x256 != nil
				case W512:
					has = spec.FusedChainHash512 != nil || spec.InterlockFillBatch16x512 != nil
				}
				if got := c.registryNoOp(t, spec.Name); got != has {
					t.Fatalf("attach helpers populated a hook: %v, wide factory fields present: %v", got, has)
				}
			})
		}
	}
	for _, name := range []string{"no_such_primitive_256", "no_such_primitive_512"} {
		s256, err := newSeed256(CipherAreion256, 512)
		if err != nil {
			t.Fatal(err)
		}
		if err := AttachFused256(s256, name, nil); err != nil || s256.FusedChain != nil {
			t.Fatalf("AttachFused256(%q): err=%v hook=%v", name, err, s256.FusedChain != nil)
		}
		if err := AttachInterlockBatch16x256(s256, name, nil); err != nil || s256.InterlockFillX16() != nil {
			t.Fatalf("AttachInterlockBatch16x256(%q): err=%v", name, err)
		}
		s512, err := newSeed512(CipherAreion512, 512)
		if err != nil {
			t.Fatal(err)
		}
		if err := AttachFused512(s512, name, nil); err != nil || s512.FusedChain != nil {
			t.Fatalf("AttachFused512(%q): err=%v hook=%v", name, err, s512.FusedChain != nil)
		}
		if err := AttachInterlockBatch16x512(s512, name, nil); err != nil || s512.InterlockFillX16() != nil {
			t.Fatalf("AttachInterlockBatch16x512(%q): err=%v", name, err)
		}
	}
}

// goFused256Factory returns a FusedChainHash256 factory evaluating the
// cascade in Go over the supplied single arm — the shape a custom
// primitive supplies when its own kernel covers the cascade. corrupt
// flips one output word so the Register smoke rejects the factory.
func goFused256Factory(mk func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error), corrupt bool) func(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) {
	return func(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, nil, err
		}
		cascade := func(components []uint64, data []byte) [4]uint64 {
			var seed [4]uint64
			copy(seed[:], components[0:4])
			h := single(data, seed)
			for i := 4; i < len(components); i += 4 {
				for j := 0; j < 4; j++ {
					seed[j] = components[i+j] ^ h[j]
				}
				h = single(data, seed)
			}
			if corrupt {
				h[0] ^= 1
			}
			return h
		}
		fs := func(components []uint64, data []byte) ([4]uint64, bool) {
			if len(data) != 13 && len(data) != 20 && len(data) != 36 && len(data) != 68 {
				return [4]uint64{}, false
			}
			return cascade(components, data), true
		}
		fb := func(components []uint64, data *[4][]byte) ([4][4]uint64, bool) {
			var out [4][4]uint64
			for l := range data {
				var ok bool
				if out[l], ok = fs(components, data[l]); !ok {
					return out, false
				}
			}
			return out, true
		}
		return fs, fb, nil
	}
}

// goFused512Factory is the width-512 twin of goFused256Factory.
func goFused512Factory(mk func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error), corrupt bool) func(key []byte) (itb.FusedChainHashFunc512, itb.BatchFusedChainHashFunc512, error) {
	return func(key []byte) (itb.FusedChainHashFunc512, itb.BatchFusedChainHashFunc512, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, nil, err
		}
		cascade := func(components []uint64, data []byte) [8]uint64 {
			var seed [8]uint64
			copy(seed[:], components[0:8])
			h := single(data, seed)
			for i := 8; i < len(components); i += 8 {
				for j := 0; j < 8; j++ {
					seed[j] = components[i+j] ^ h[j]
				}
				h = single(data, seed)
			}
			if corrupt {
				h[0] ^= 1
			}
			return h
		}
		fs := func(components []uint64, data []byte) ([8]uint64, bool) {
			if len(data) != 13 && len(data) != 20 && len(data) != 36 && len(data) != 68 {
				return [8]uint64{}, false
			}
			return cascade(components, data), true
		}
		fb := func(components []uint64, data *[4][]byte) ([4][8]uint64, bool) {
			var out [4][8]uint64
			for l := range data {
				var ok bool
				if out[l], ok = fs(components, data[l]); !ok {
					return out, false
				}
			}
			return out, true
		}
		return fs, fb, nil
	}
}

// makeCustom512PairFactory mirrors makeCustom256PairFactory over a
// SHA-512 one-shot.
func makeCustom512PairFactory() func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error) {
	return func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error) {
		fixedKey := make([]byte, 64)
		if len(key) > 0 {
			if len(key[0]) != 64 {
				return nil, nil, nil, fmt.Errorf("custom test factory: key must be 64 bytes, got %d", len(key[0]))
			}
			copy(fixedKey, key[0])
		} else {
			for i := range fixedKey {
				fixedKey[i] = byte(i*13 + 5)
			}
		}
		return BuildARXChainAbsorb512(sha512.Sum512, fixedKey), nil, fixedKey, nil
	}
}

// TestWideAttachCustomFusedFactory registers a custom W256 and a custom
// W512 primitive carrying pure-Go whole-cascade factories and pins that
// the attach helpers populate the hooks, that a hooked seed agrees with
// the same seed on the arms alone on every pixel shape, and that a
// divergent factory is rejected at Register time.
func TestWideAttachCustomFusedFactory(t *testing.T) {
	mk256 := makeCustom256PairFactory()
	mk512 := makeCustom512PairFactory()
	t.Run("256", func(t *testing.T) {
		name := customFactoryName + "fused256"
		if err := Register(Spec{Name: name, Width: W256, Make256Pair: mk256, FusedChainHash256: goFused256Factory(mk256, false)}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		single, _, key, err := Make256Pair(name)
		if err != nil {
			t.Fatal(err)
		}
		comps := make([]uint64, 16)
		for i := range comps {
			comps[i] = uint64(i+1) * 0x9E3779B97F4A7C15
		}
		plain, err := itb.SeedFromComponents256(single, comps...)
		if err != nil {
			t.Fatal(err)
		}
		hooked, err := itb.SeedFromComponents256(single, comps...)
		if err != nil {
			t.Fatal(err)
		}
		if err := AttachFused256(hooked, name, key); err != nil {
			t.Fatalf("AttachFused256: %v", err)
		}
		if hooked.FusedChain == nil || hooked.BatchFusedChain == nil {
			t.Fatal("AttachFused256 left the hooks nil")
		}
		for _, n := range pixelShapes {
			buf := make([]byte, n)
			for i := range buf {
				buf[i] = byte(i*7 + n)
			}
			if hooked.ChainHash256(buf) != plain.ChainHash256(buf) {
				t.Fatalf("ChainHash256 differs at len %d", n)
			}
		}
		bad := customFactoryName + "f256bad"
		err = Register(Spec{Name: bad, Width: W256, Make256Pair: mk256, FusedChainHash256: goFused256Factory(mk256, true)})
		if err == nil || !strings.Contains(err.Error(), "diverges") {
			t.Fatalf("Register of a divergent FusedChainHash256 factory: err=%v", err)
		}
	})
	t.Run("512", func(t *testing.T) {
		name := customFactoryName + "fused512"
		if err := Register(Spec{Name: name, Width: W512, Make512Pair: mk512, FusedChainHash512: goFused512Factory(mk512, false)}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		single, _, key, err := Make512Pair(name)
		if err != nil {
			t.Fatal(err)
		}
		comps := make([]uint64, 16)
		for i := range comps {
			comps[i] = uint64(i+1) * 0x9E3779B97F4A7C15
		}
		plain, err := itb.SeedFromComponents512(single, comps...)
		if err != nil {
			t.Fatal(err)
		}
		hooked, err := itb.SeedFromComponents512(single, comps...)
		if err != nil {
			t.Fatal(err)
		}
		if err := AttachFused512(hooked, name, key); err != nil {
			t.Fatalf("AttachFused512: %v", err)
		}
		if hooked.FusedChain == nil || hooked.BatchFusedChain == nil {
			t.Fatal("AttachFused512 left the hooks nil")
		}
		for _, n := range pixelShapes {
			buf := make([]byte, n)
			for i := range buf {
				buf[i] = byte(i*7 + n)
			}
			if hooked.ChainHash512(buf) != plain.ChainHash512(buf) {
				t.Fatalf("ChainHash512 differs at len %d", n)
			}
		}
		bad := customFactoryName + "f512bad"
		err = Register(Spec{Name: bad, Width: W512, Make512Pair: mk512, FusedChainHash512: goFused512Factory(mk512, true)})
		if err == nil || !strings.Contains(err.Error(), "diverges") {
			t.Fatalf("Register of a divergent FusedChainHash512 factory: err=%v", err)
		}
	})
}
