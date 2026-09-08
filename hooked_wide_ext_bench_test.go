package itb_test

import (
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// hooked_wide_ext_bench_test.go — width-256 / width-512 Triple Ouroboros
// bench helpers that build the eight seeds through hashes.NewSeed256 /
// NewSeed512, the way every shipping constructor does (arms, components
// and every fast-path hook the primitive offers), so a primitive whose
// assembly kernels are reached through the fused hooks is measured on
// its shipping path rather than on the arms alone.

func makeEightHookedSeeds256Ext(b *testing.B, name string, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed256) {
	b.Helper()
	mk := func() *itb.Seed256 {
		s, _, err := hashes.NewSeed256(name, bits)
		if err != nil {
			b.Fatalf("NewSeed256(%q): %v", name, err)
		}
		return s
	}
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
}

func makeEightHookedSeeds512Ext(b *testing.B, name string, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed512) {
	b.Helper()
	mk := func() *itb.Seed512 {
		s, _, err := hashes.NewSeed512(name, bits)
		if err != nil {
			b.Fatalf("NewSeed512(%q): %v", name, err)
		}
		return s
	}
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
}

// benchEncrypt3x256HookedExt / benchDecrypt3x256HookedExt are the
// hooked-seed counterparts of the width-256 CachedBatched helpers.
func benchEncrypt3x256HookedExt(b *testing.B, name string, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightHookedSeeds256Ext(b, name, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x256HookedExt(b *testing.B, name string, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightHookedSeeds256Ext(b, name, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, _ := itb.Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// benchEncrypt3x512HookedExt / benchDecrypt3x512HookedExt are the
// width-512 forms.
func benchEncrypt3x512HookedExt(b *testing.B, name string, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightHookedSeeds512Ext(b, name, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x512HookedExt(b *testing.B, name string, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightHookedSeeds512Ext(b, name, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, _ := itb.Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}
