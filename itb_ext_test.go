// External-test-package helpers shared with itb3_ext_test.go. Both
// files live in `package itb_test` so cross-file symbol reuse is free;
// this file carries only the helper functions (seed builders, primitive
// Pair factories, lockSeed-slot fixtures), and the Triple Ouroboros
// benchmarks + integration tests live in itb3_ext_test.go.
package itb_test

import (
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// generateDataExt returns n bytes of cryptographically random data
// suitable for use as plaintext or fixture input.
func generateDataExt(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- Primitive Pair factories -----------------------------------------------
//
// Each returns the (single-call, batched) hash pair for the named
// primitive at the corresponding ITB seed width. Every fresh call to a
// Pair() constructor produces an independently-keyed hasher — callers
// building multiple seeds under one primitive should share the pair
// across those seeds if they want identical hash state, or call the
// factory once per seed for independent keys.

func makeBlake2bHash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.BLAKE2b256Pair()
	return h, b
}

func makeBlake2bHash512PairExt() (itb.HashFunc512, itb.BatchHashFunc512) {
	h, b, _ := hashes.BLAKE2b512Pair()
	return h, b
}

func makeBlake2sHash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.BLAKE2s256Pair()
	return h, b
}

func makeBlake3Hash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.BLAKE3256Pair()
	return h, b
}

func makeChaCha20Hash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.ChaCha20256Pair()
	return h, b
}

func makeAESCMACHash128PairExt() (itb.HashFunc128, itb.BatchHashFunc128) {
	h, b, _ := hashes.AESCMACPair()
	return h, b
}

func makeSipHash24Hash128PairExt() (itb.HashFunc128, itb.BatchHashFunc128) {
	h, b := hashes.SipHash24Pair()
	return h, b
}

func makeAreion256Hash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.Areion256Pair()
	return h, b
}

func makeAreion512Hash512PairExt() (itb.HashFunc512, itb.BatchHashFunc512) {
	h, b, _ := hashes.Areion512Pair()
	return h, b
}

// --- Seed builders for the lockSeed slot -----------------------------------
//
// The lockSeed slot supplies keying material for the 48-bit
// interlock overlay's bit-permutation derivation. These helpers
// build fresh Seed{128,256,512} instances suitable for use as any
// slot in the Triple 8-seed constellation; each call yields an
// independently-keyed hasher via the corresponding Pair factory.

func makeBlake3SeedAttachExt(t *testing.T, bits int) *itb.Seed256 {
	t.Helper()
	h, b, _ := hashes.BLAKE3256Pair()
	s, err := itb.NewSeed256(bits, h)
	if err != nil {
		t.Fatalf("NewSeed256(%d): %v", bits, err)
	}
	s.BatchHash = b
	return s
}
