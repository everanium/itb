package hashes

import (
	"testing"

	"github.com/everanium/itb"
)

// TestSeedFromComponents128x16AESITB checks the existing-components
// helper on aesitb128: the components are copied verbatim, every hook
// is attached, and the seed agrees with a NewSeed128x16-built seed on
// the same key and components for the per-pixel cascade.
func TestSeedFromComponents128x16AESITB(t *testing.T) {
	ref, key, err := NewSeed128x16(1024, CipherAESITB128)
	if err != nil {
		t.Fatalf("NewSeed128x16: %v", err)
	}
	s, err := SeedFromComponents128x16(CipherAESITB128, key, ref.Components...)
	if err != nil {
		t.Fatalf("SeedFromComponents128x16(aesitb128): %v", err)
	}
	if len(s.Components) != len(ref.Components) {
		t.Fatalf("components: got %d words, want %d", len(s.Components), len(ref.Components))
	}
	for i := range ref.Components {
		if s.Components[i] != ref.Components[i] {
			t.Fatalf("component %d differs", i)
		}
	}
	if s.Hash == nil || s.BatchHash == nil {
		t.Fatal("Hash / BatchHash not wired")
	}
	if s.FusedChain == nil || s.BatchFusedChain == nil {
		t.Fatal("fused hooks not attached")
	}
	if s.InterlockFillX16() == nil {
		t.Fatal("batch-16 hook not attached")
	}
	buf := []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13")
	aLo, aHi := ref.ChainHash128(buf)
	bLo, bHi := s.ChainHash128(buf)
	if aLo != bLo || aHi != bHi {
		t.Fatal("ChainHash128 differs between the two constructors on the same key and components")
	}
	var out [16][2]uint64
	s.InterlockFillX16()(s.Components, 0, &out)
}

// TestSeedFromComponents128x16Keyless checks the keyless primitive: an
// empty key is accepted (the blob key field of siphash24 is empty) and
// an explicit key is rejected.
func TestSeedFromComponents128x16Keyless(t *testing.T) {
	ref, _, err := NewSeed128x16(512, CipherSipHash24)
	if err != nil {
		t.Fatalf("NewSeed128x16(siphash24): %v", err)
	}
	s, err := SeedFromComponents128x16(CipherSipHash24, nil, ref.Components...)
	if err != nil {
		t.Fatalf("SeedFromComponents128x16(siphash24, nil): %v", err)
	}
	if s.InterlockFillX16() != nil || s.FusedChain != nil {
		t.Fatal("siphash24 received hooks it has no factories for")
	}
	buf := make([]byte, 20)
	aLo, aHi := ref.ChainHash128(buf)
	bLo, bHi := s.ChainHash128(buf)
	if aLo != bLo || aHi != bHi {
		t.Fatal("siphash24 ChainHash128 differs between the two constructors")
	}
	if _, err := SeedFromComponents128x16(CipherSipHash24, make([]byte, 16), ref.Components...); err == nil {
		t.Fatal("siphash24 accepted an explicit key")
	}
}

// TestSeedFromComponents128x16Errors checks error propagation: an
// empty key for a keyed primitive, a wrong key length, an unknown or
// non-128 primitive, and a bad component count.
func TestSeedFromComponents128x16Errors(t *testing.T) {
	comps := make([]uint64, 8)
	for i := range comps {
		comps[i] = uint64(i + 1)
	}
	if s, err := SeedFromComponents128x16(CipherAESITB128, nil, comps...); err == nil || s != nil {
		t.Fatal("aesitb128 with an empty key did not fail")
	}
	if s, err := SeedFromComponents128x16(CipherAES128CTR, nil, comps...); err == nil || s != nil {
		t.Fatal("aescmac with an empty key did not fail")
	}
	if s, err := SeedFromComponents128x16(CipherAESITB128, make([]byte, 15), comps...); err == nil || s != nil {
		t.Fatal("15-byte key did not fail")
	}
	if s, err := SeedFromComponents128x16("no_such_primitive", make([]byte, 16), comps...); err == nil || s != nil {
		t.Fatal("unknown primitive did not fail")
	}
	if s, err := SeedFromComponents128x16(CipherAreion512, make([]byte, 64), comps...); err == nil || s != nil {
		t.Fatal("width-512 primitive did not fail")
	}
	if s, err := SeedFromComponents128x16(CipherAESITB128, make([]byte, 16), comps[:6]...); err == nil || s != nil {
		t.Fatal("6-word component slice did not fail")
	}
	if s, err := SeedFromComponents128x16(CipherAESITB128, make([]byte, 16), comps[:7]...); err == nil || s != nil {
		t.Fatal("odd component count did not fail")
	}
	// The aescmac path with a proper key attaches nothing beyond the arms.
	s, err := SeedFromComponents128x16(CipherAES128CTR, make([]byte, 16), comps...)
	if err != nil {
		t.Fatalf("aescmac: %v", err)
	}
	if s.InterlockFillX16() != nil || s.FusedChain != nil {
		t.Fatal("aescmac received hooks it has no factories for")
	}
	_ = itb.MaxKeyBits
}
