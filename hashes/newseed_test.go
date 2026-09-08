package hashes

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb"
)

// newseed_test.go — the name-keyed seed constructors NewSeed128 /
// NewSeed256 / NewSeed512. For every shipped primitive at every key
// size the constructed seed carries exactly the hooks the manual attach
// sequence installs, the returned key rebuilds identical arms, and the
// wire round-trips both ways against an arms-only twin built through
// the itb constructor on the same components — the cascade fill is the
// wire, the hooks only evaluate it. A custom registered primitive goes
// through the same constructor; bad names, widths, keys and key sizes
// are rejected.

// armsSeed256 / armsSeed512 build a seed from components through the
// arms alone (the width-128 form is manualSeed128 in seed_attach_test.go).
func armsSeed256(t *testing.T, name string, key []byte, comps []uint64) *itb.Seed256 {
	t.Helper()
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, _, err := Make256Pair(name, keyArg...)
	if err != nil {
		t.Fatalf("Make256Pair(%q): %v", name, err)
	}
	s, err := itb.SeedFromComponents256(single, comps...)
	if err != nil {
		t.Fatal(err)
	}
	s.BatchHash = batched
	return s
}

func armsSeed512(t *testing.T, name string, key []byte, comps []uint64) *itb.Seed512 {
	t.Helper()
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, _, err := Make512Pair(name, keyArg...)
	if err != nil {
		t.Fatalf("Make512Pair(%q): %v", name, err)
	}
	s, err := itb.SeedFromComponents512(single, comps...)
	if err != nil {
		t.Fatal(err)
	}
	s.BatchHash = batched
	return s
}

func newSeedTestBuf(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i*7 + n)
	}
	return buf
}

// TestNewSeedShippedPrimitives runs every shipped primitive at its
// width through the constructor at 512 / 1024 / 2048 bits.
func TestNewSeedShippedPrimitives(t *testing.T) {
	cfg := &itb.Config{NonceBits: itb.DefaultNonceBits, BarrierFill: itb.DefaultBarrierFill}
	plain := make([]byte, 3_000)
	rand.Read(plain)
	for _, spec := range Registry {
		for _, bits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%d", spec.Name, bits), func(t *testing.T) {
				switch spec.Width {
				case W128:
					checkNewSeed128(t, cfg, spec.Name, bits, plain)
				case W256:
					checkNewSeed256(t, cfg, spec.Name, bits, plain)
				case W512:
					checkNewSeed512(t, cfg, spec.Name, bits, plain)
				}
			})
		}
	}
}

func checkNewSeed128(t *testing.T, cfg *itb.Config, name string, bits int, plain []byte) {
	t.Helper()
	var hooked, arms [8]*itb.Seed128
	for i := range hooked {
		s, key, err := NewSeed128(name, bits)
		if err != nil {
			t.Fatalf("NewSeed128(%q, %d): %v", name, bits, err)
		}
		if len(s.Components)*64 != bits {
			t.Fatalf("key bits = %d, want %d", len(s.Components)*64, bits)
		}
		if (key == nil) != (name == CipherSipHash24) {
			t.Fatalf("returned key %x: keyless expected only for %q", key, CipherSipHash24)
		}
		twin := manualSeed128(t, name, key, s.Components)
		if (twin.BatchHash == nil) != (s.BatchHash == nil) {
			t.Fatal("batched arm presence differs from the manual build")
		}
		for _, n := range pixelShapes {
			buf := newSeedTestBuf(n)
			lo, hi := s.ChainHash128(buf)
			tlo, thi := twin.ChainHash128(buf)
			if lo != tlo || hi != thi {
				t.Fatalf("len %d: the returned key does not rebuild the arms", n)
			}
		}
		ref := manualSeed128(t, name, key, s.Components)
		if err := AttachFused128(ref, name, key); err != nil {
			t.Fatal(err)
		}
		if err := AttachInterlockBatch16(ref, name, key); err != nil {
			t.Fatal(err)
		}
		if (s.FusedChain == nil) != (ref.FusedChain == nil) || (s.BatchFusedChain == nil) != (ref.BatchFusedChain == nil) ||
			(s.BatchFusedChain8() == nil) != (ref.BatchFusedChain8() == nil) || (s.InterlockFillX16() == nil) != (ref.InterlockFillX16() == nil) {
			t.Fatal("hook set differs from AttachFused128 + AttachInterlockBatch16 on the same seed")
		}
		hooked[i], arms[i] = s, twin
	}
	enc := func(s [8]*itb.Seed128) []byte {
		w, err := itb.Encrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	dec := func(s [8]*itb.Seed128, w []byte) []byte {
		got, err := itb.Decrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], w)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if !bytes.Equal(dec(arms, enc(hooked)), plain) {
		t.Fatal("arms-only twins do not decrypt the constructor seeds' wire")
	}
	if !bytes.Equal(dec(hooked, enc(arms)), plain) {
		t.Fatal("constructor seeds do not decrypt the arms-only twins' wire")
	}
}

func checkNewSeed256(t *testing.T, cfg *itb.Config, name string, bits int, plain []byte) {
	t.Helper()
	var hooked, arms [8]*itb.Seed256
	for i := range hooked {
		s, key, err := NewSeed256(name, bits)
		if err != nil {
			t.Fatalf("NewSeed256(%q, %d): %v", name, bits, err)
		}
		if len(s.Components)*64 != bits {
			t.Fatalf("key bits = %d, want %d", len(s.Components)*64, bits)
		}
		twin := armsSeed256(t, name, key, s.Components)
		if (twin.BatchHash == nil) != (s.BatchHash == nil) {
			t.Fatal("batched arm presence differs from the manual build")
		}
		for _, n := range pixelShapes {
			buf := newSeedTestBuf(n)
			if s.ChainHash256(buf) != twin.ChainHash256(buf) {
				t.Fatalf("len %d: the returned key does not rebuild the arms", n)
			}
		}
		ref := armsSeed256(t, name, key, s.Components)
		if err := AttachFused256(ref, name, key); err != nil {
			t.Fatal(err)
		}
		if err := AttachInterlockBatch16x256(ref, name, key); err != nil {
			t.Fatal(err)
		}
		if (s.FusedChain == nil) != (ref.FusedChain == nil) || (s.BatchFusedChain == nil) != (ref.BatchFusedChain == nil) ||
			(s.InterlockFillX16() == nil) != (ref.InterlockFillX16() == nil) {
			t.Fatal("hook set differs from AttachFused256 + AttachInterlockBatch16x256 on the same seed")
		}
		hooked[i], arms[i] = s, twin
	}
	enc := func(s [8]*itb.Seed256) []byte {
		w, err := itb.Encrypt3x256Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	dec := func(s [8]*itb.Seed256, w []byte) []byte {
		got, err := itb.Decrypt3x256Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], w)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if !bytes.Equal(dec(arms, enc(hooked)), plain) {
		t.Fatal("arms-only twins do not decrypt the constructor seeds' wire")
	}
	if !bytes.Equal(dec(hooked, enc(arms)), plain) {
		t.Fatal("constructor seeds do not decrypt the arms-only twins' wire")
	}
}

func checkNewSeed512(t *testing.T, cfg *itb.Config, name string, bits int, plain []byte) {
	t.Helper()
	var hooked, arms [8]*itb.Seed512
	for i := range hooked {
		s, key, err := NewSeed512(name, bits)
		if err != nil {
			t.Fatalf("NewSeed512(%q, %d): %v", name, bits, err)
		}
		if len(s.Components)*64 != bits {
			t.Fatalf("key bits = %d, want %d", len(s.Components)*64, bits)
		}
		twin := armsSeed512(t, name, key, s.Components)
		if (twin.BatchHash == nil) != (s.BatchHash == nil) {
			t.Fatal("batched arm presence differs from the manual build")
		}
		for _, n := range pixelShapes {
			buf := newSeedTestBuf(n)
			if s.ChainHash512(buf) != twin.ChainHash512(buf) {
				t.Fatalf("len %d: the returned key does not rebuild the arms", n)
			}
		}
		ref := armsSeed512(t, name, key, s.Components)
		if err := AttachFused512(ref, name, key); err != nil {
			t.Fatal(err)
		}
		if err := AttachInterlockBatch16x512(ref, name, key); err != nil {
			t.Fatal(err)
		}
		if (s.FusedChain == nil) != (ref.FusedChain == nil) || (s.BatchFusedChain == nil) != (ref.BatchFusedChain == nil) ||
			(s.InterlockFillX16() == nil) != (ref.InterlockFillX16() == nil) {
			t.Fatal("hook set differs from AttachFused512 + AttachInterlockBatch16x512 on the same seed")
		}
		hooked[i], arms[i] = s, twin
	}
	enc := func(s [8]*itb.Seed512) []byte {
		w, err := itb.Encrypt3x512Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	dec := func(s [8]*itb.Seed512, w []byte) []byte {
		got, err := itb.Decrypt3x512Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], w)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if !bytes.Equal(dec(arms, enc(hooked)), plain) {
		t.Fatal("arms-only twins do not decrypt the constructor seeds' wire")
	}
	if !bytes.Equal(dec(hooked, enc(arms)), plain) {
		t.Fatal("constructor seeds do not decrypt the arms-only twins' wire")
	}
}

// TestNewSeedSuppliedKey pins that a caller-supplied key is the key the
// arms are built with and the key that is returned.
func TestNewSeedSuppliedKey(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	a, ka, err := NewSeed128(CipherAESITB128, 512, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, key) {
		t.Fatalf("returned key %x, want the supplied %x", ka, key)
	}
	b := manualSeed128(t, CipherAESITB128, key, a.Components)
	buf := newSeedTestBuf(20)
	alo, ahi := a.ChainHash128(buf)
	blo, bhi := b.ChainHash128(buf)
	if alo != blo || ahi != bhi {
		t.Fatal("the supplied key does not key the arms")
	}
}

// TestNewSeedRejects pins the error paths: unknown name, a name of
// another width, a key the primitive rejects, keyBits outside the
// width's range.
func TestNewSeedRejects(t *testing.T) {
	if _, _, err := NewSeed128("nosuch", 512); err == nil {
		t.Fatal("NewSeed128(unknown) accepted")
	}
	if _, _, err := NewSeed128(CipherBLAKE3, 512); err == nil {
		t.Fatal("NewSeed128 accepted a width-256 primitive")
	}
	if _, _, err := NewSeed256(CipherAESITB128, 512); err == nil {
		t.Fatal("NewSeed256 accepted a width-128 primitive")
	}
	if _, _, err := NewSeed512(CipherBLAKE3, 512); err == nil {
		t.Fatal("NewSeed512 accepted a width-256 primitive")
	}
	if _, _, err := NewSeed128(CipherSipHash24, 512, []byte{1}); err == nil {
		t.Fatal("NewSeed128(siphash24) accepted a key")
	}
	if _, _, err := NewSeed128(CipherAESITB128, 512, []byte{1, 2, 3}); err == nil {
		t.Fatal("NewSeed128(aesitb128) accepted a 3-byte key")
	}
	if _, _, err := NewSeed128(CipherAESITB128, 384); err == nil {
		t.Fatal("NewSeed128 accepted 384 bits")
	}
	if _, _, err := NewSeed256(CipherBLAKE3, 640); err == nil {
		t.Fatal("NewSeed256 accepted 640 bits (not a multiple of 256)")
	}
	if _, _, err := NewSeed512(CipherBLAKE2b512, 4096); err == nil {
		t.Fatal("NewSeed512 accepted 4096 bits")
	}
}

// TestNewSeedCustomPrimitive runs a user-registered width-128 primitive
// without hook factories through the constructor: the arms come from
// its factory, the key is the factory's, the hooks stay nil, and the
// wire round-trips against an arms-only twin.
func TestNewSeedCustomPrimitive(t *testing.T) {
	name := customFactoryName + "ns128"
	if err := Register(Spec{Name: name, Width: W128, Make128Pair: makeCustom128PairFactory()}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	cfg := &itb.Config{NonceBits: itb.DefaultNonceBits, BarrierFill: itb.DefaultBarrierFill}
	plain := make([]byte, 2_000)
	rand.Read(plain)
	var seeds, twins [8]*itb.Seed128
	for i := range seeds {
		s, key, err := NewSeed128(name, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != 32 {
			t.Fatalf("custom key length %d, want 32", len(key))
		}
		if s.FusedChain != nil || s.BatchFusedChain != nil || s.BatchFusedChain8() != nil || s.InterlockFillX16() != nil {
			t.Fatal("a custom primitive without factories received a hook")
		}
		seeds[i] = s
		twins[i] = manualSeed128(t, name, key, s.Components)
	}
	w, err := itb.Encrypt3x128Cfg(cfg, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := itb.Decrypt3x128Cfg(cfg, twins[0], twins[1], twins[2], twins[3], twins[4], twins[5], twins[6], twins[7], w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("arms-only twins do not decrypt the constructor seeds' wire")
	}
}
