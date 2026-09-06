package hashes

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// TestNewSeed128x16AESITB checks that the aesitb128 helper path attaches
// the fused ChainHash cascade and the batch-16 interlock fill hook, and
// returns the 16-byte fixed key the arms were built with.
func TestNewSeed128x16AESITB(t *testing.T) {
	s, key, err := NewSeed128x16(1024, CipherAESITB128)
	if err != nil {
		t.Fatalf("NewSeed128x16(aesitb128): %v", err)
	}
	if s == nil {
		t.Fatal("NewSeed128x16(aesitb128): nil seed")
	}
	if len(key) != 16 {
		t.Fatalf("returned key len = %d, want 16", len(key))
	}
	if s.Bits() != 1024 {
		t.Fatalf("seed bits = %d, want 1024", s.Bits())
	}
	if s.Hash == nil || s.BatchHash == nil {
		t.Fatal("base Hash / BatchHash arms not populated")
	}
	if s.InterlockFillX16() == nil {
		t.Fatal("InterlockFillX16 hook nil for aesitb128")
	}
	if forcetier.ChainHashSeq() {
		t.Log("ITB_FORCE_CHAINHASH_SEQ set: fused hooks intentionally nil, skipping fused assertions")
		return
	}
	if s.FusedChain == nil || s.BatchFusedChain == nil {
		t.Fatal("FusedChain / BatchFusedChain hooks nil for aesitb128")
	}
}

// TestNewSeed128x16ExplicitKey checks the persistence-restore path: a
// caller-supplied key is echoed back and the resulting seed's ChainHash128
// output (fused cascade when attached) is bit-exact with a hand-assembled
// seed carrying the same components and the same key on the sequential
// loop (no hooks attached).
func TestNewSeed128x16ExplicitKey(t *testing.T) {
	fixed := []byte("0123456789abcdef")
	s, key, err := NewSeed128x16(512, CipherAESITB128, fixed)
	if err != nil {
		t.Fatalf("NewSeed128x16(aesitb128, key): %v", err)
	}
	if !bytes.Equal(key, fixed) {
		t.Fatalf("returned key %x, want %x", key, fixed)
	}

	single, batched, _, err := Make128Pair(CipherAESITB128, fixed)
	if err != nil {
		t.Fatalf("Make128Pair: %v", err)
	}
	ref, err := itb.SeedFromComponents128(single, s.Components...)
	if err != nil {
		t.Fatalf("SeedFromComponents128: %v", err)
	}
	ref.BatchHash = batched
	if ref.FusedChain != nil || ref.InterlockFillX16() != nil {
		t.Fatal("reference seed unexpectedly carries fast-path hooks")
	}

	// 13-byte input is the per-pixel shape the fused kernel accepts; the
	// fused result must agree bit-exact with the sequential loop.
	in := []byte{0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	gotLo, gotHi := s.ChainHash128(in)
	wantLo, wantHi := ref.ChainHash128(in)
	if gotLo != wantLo || gotHi != wantHi {
		t.Fatalf("ChainHash128 mismatch: helper (%016x,%016x) vs manual (%016x,%016x)", gotLo, gotHi, wantLo, wantHi)
	}
}

// TestNewSeed128x16NoOpPrimitive checks that a primitive without fused /
// batch-16 factories still yields a usable seed with the optional hooks
// left nil (sequential fallback).
func TestNewSeed128x16NoOpPrimitive(t *testing.T) {
	s, key, err := NewSeed128x16(1024, CipherAES128CTR)
	if err != nil {
		t.Fatalf("NewSeed128x16(aescmac): %v", err)
	}
	if len(key) != 16 {
		t.Fatalf("returned key len = %d, want 16", len(key))
	}
	// BatchHash is deliberately not asserted: the aescmac batched arm is
	// nil on hosts without the ZMM kernel tier (the 4-single-call fallback).
	if s.Hash == nil {
		t.Fatal("base Hash arm not populated")
	}
	if s.FusedChain != nil || s.BatchFusedChain != nil {
		t.Fatal("fused hooks populated for aescmac (expected nil)")
	}
	if s.InterlockFillX16() != nil {
		t.Fatal("InterlockFillX16 populated for aescmac (expected nil)")
	}
	if lo, hi := s.ChainHash128([]byte{0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}); lo == 0 && hi == 0 {
		t.Fatal("ChainHash128 returned (0,0) on the sequential fallback")
	}
}

// TestNewSeed128x16Keyless checks the keyless primitive: no key is
// returned and an explicit key is rejected.
func TestNewSeed128x16Keyless(t *testing.T) {
	s, key, err := NewSeed128x16(512, CipherSipHash24)
	if err != nil {
		t.Fatalf("NewSeed128x16(siphash24): %v", err)
	}
	if s == nil || key != nil {
		t.Fatalf("siphash24: seed=%v key=%v, want non-nil seed and nil key", s != nil, key)
	}
	if _, _, err := NewSeed128x16(512, CipherSipHash24, make([]byte, 16)); err == nil {
		t.Fatal("siphash24 with explicit key: expected error, got nil")
	}
}

// TestNewSeed128x16Errors checks error propagation for unknown primitives,
// wrong-width primitives, and invalid bit counts.
func TestNewSeed128x16Errors(t *testing.T) {
	if s, key, err := NewSeed128x16(1024, "no_such_primitive"); err == nil || s != nil || key != nil {
		t.Fatalf("unknown primitive: seed=%v key=%v err=%v", s, key, err)
	}
	if s, _, err := NewSeed128x16(1024, CipherAreion512); err == nil || s != nil {
		t.Fatalf("512-bit primitive: seed=%v err=%v, want error", s, err)
	}
	for _, bits := range []int{0, 127, 384, 576, 2049, 4096} {
		if s, _, err := NewSeed128x16(bits, CipherAESITB128); err == nil || s != nil {
			t.Fatalf("bits=%d: seed=%v err=%v, want error", bits, s, err)
		}
	}
	if _, _, err := NewSeed128x16(1024, CipherAESITB128, make([]byte, 15)); err == nil {
		t.Fatal("aesitb128 with 15-byte key: expected error, got nil")
	}
}
