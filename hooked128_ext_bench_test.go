package itb_test

import (
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// hooked128_ext_bench_test.go — width-128 Triple Ouroboros bench helpers
// that build the eight seeds the way every shipping constructor does
// (Make128Pair arms, itb.NewSeed128, BatchHash, then AttachFused128 and
// AttachInterlockBatch16), so a primitive whose assembly kernels are
// reached through the fused hooks is measured on its shipping path
// rather than on the arms alone.

// makeHookedSeed128Ext builds one seed of the named width-128 primitive
// with a fresh key through the explicit Low-Level sequence.
func makeHookedSeed128Ext(b *testing.B, name string, bits int) *itb.Seed128 {
	b.Helper()
	single, batched, key, err := hashes.Make128Pair(name)
	if err != nil {
		b.Fatalf("Make128Pair(%q): %v", name, err)
	}
	s, err := itb.NewSeed128(bits, single)
	if err != nil {
		b.Fatalf("NewSeed128: %v", err)
	}
	s.BatchHash = batched
	if err := hashes.AttachFused128(s, name, key); err != nil {
		b.Fatalf("AttachFused128(%q): %v", name, err)
	}
	if err := hashes.AttachInterlockBatch16(s, name, key); err != nil {
		b.Fatalf("AttachInterlockBatch16(%q): %v", name, err)
	}
	return s
}

func makeEightHookedSeeds128Ext(b *testing.B, name string, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed128) {
	mk := func() *itb.Seed128 { return makeHookedSeed128Ext(b, name, bits) }
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
}

// benchEncrypt3x128HookedExt is the hooked-seed counterpart of
// benchEncrypt3x128CachedBatchedExt.
func benchEncrypt3x128HookedExt(b *testing.B, name string, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightHookedSeeds128Ext(b, name, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

// benchDecrypt3x128HookedExt is the hooked-seed counterpart of
// benchDecrypt3x128CachedBatchedExt.
func benchDecrypt3x128HookedExt(b *testing.B, name string, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightHookedSeeds128Ext(b, name, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, _ := itb.Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}
