// Triple Ouroboros (7-seed) integration benchmarks. Mirror of
// itb_ext_test.go but driving the Encrypt3x{128,256,512} /
// Decrypt3x{128,256,512} entry points instead of the Single
// Encrypt{128,256,512} pair, with seven-seed builders in place of
// the three-seed ones. Bench function names carry a "Triple"
// infix (BenchmarkExtTriple<Primitive>…) to keep the result
// cohort distinct from the BenchmarkExtSingle… cohort emitted by
// itb_ext_test.go.
//
// The hashes/Pair-factory makers (makeBlake2bHash256PairExt,
// makeAESCMACHash128PairExt, …) live in itb_ext_test.go and are
// reused verbatim here — package itb_test sees both files as the
// same compilation unit, so cross-file symbol reuse is free. Only
// helpers that are structurally Triple-specific (seven-seed
// constructors, the Encrypt3x / Decrypt3x bench drivers) and the
// benchmark functions themselves duplicate.
package itb_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/triple"
)

// extTripleBenchCfg returns the *itb.Config every ExtTriple bench
// driver threads through the Cfg-suffixed entry points. The ITB_NONCE_BITS
// environment variable selects the nonce width (128 / 256 / 512); when
// unset or invalid the config pins the compile-in [itb.DefaultNonceBits]
// explicitly. The external test package cannot reach the root package's
// testCfg helper, so the env var is read here directly — same contract,
// same accepted values.
func extTripleBenchCfg() *itb.Config {
	switch os.Getenv("ITB_NONCE_BITS") {
	case "128":
		return &itb.Config{NonceBits: 128}
	case "256":
		return &itb.Config{NonceBits: 256}
	case "512":
		return &itb.Config{NonceBits: 512}
	}
	return &itb.Config{NonceBits: itb.DefaultNonceBits}
}

// makeEightSeeds128Ext is the external-test counterpart of
// itb_test.go:makeEightSeeds128. Constructs the eight independent
// 128-bit ITB seeds the Triple Ouroboros API consumes (1 noise +
// 1 lockSeed + 3 data + 3 start), all bound to the same single-
// call hash function. The bench helpers below override per-seed
// Hash and BatchHash fields with fresh maker() pairs so each seed
// carries its own fixed key.
func makeEightSeeds128Ext(bits int, h itb.HashFunc128) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed128) {
	ns, _ = itb.NewSeed128(bits, h)
	ls, _ = itb.NewSeed128(bits, h)
	ds1, _ = itb.NewSeed128(bits, h)
	ds2, _ = itb.NewSeed128(bits, h)
	ds3, _ = itb.NewSeed128(bits, h)
	ss1, _ = itb.NewSeed128(bits, h)
	ss2, _ = itb.NewSeed128(bits, h)
	ss3, _ = itb.NewSeed128(bits, h)
	return
}

// makeEightSeeds256Ext is the 256-bit counterpart.
func makeEightSeeds256Ext(bits int, h itb.HashFunc256) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed256) {
	ns, _ = itb.NewSeed256(bits, h)
	ls, _ = itb.NewSeed256(bits, h)
	ds1, _ = itb.NewSeed256(bits, h)
	ds2, _ = itb.NewSeed256(bits, h)
	ds3, _ = itb.NewSeed256(bits, h)
	ss1, _ = itb.NewSeed256(bits, h)
	ss2, _ = itb.NewSeed256(bits, h)
	ss3, _ = itb.NewSeed256(bits, h)
	return
}

// makeEightSeeds512Ext is the 512-bit counterpart.
func makeEightSeeds512Ext(bits int, h itb.HashFunc512) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed512) {
	ns, _ = itb.NewSeed512(bits, h)
	ls, _ = itb.NewSeed512(bits, h)
	ds1, _ = itb.NewSeed512(bits, h)
	ds2, _ = itb.NewSeed512(bits, h)
	ds3, _ = itb.NewSeed512(bits, h)
	ss1, _ = itb.NewSeed512(bits, h)
	ss2, _ = itb.NewSeed512(bits, h)
	ss3, _ = itb.NewSeed512(bits, h)
	return
}

// benchEncrypt3x128CachedBatchedExt mirrors itb_ext_test.go's
// benchEncrypt128CachedBatchedExt for the Triple Ouroboros API.
// The maker is invoked seven times so each of the seven seeds
// (noise + 3 × data + 3 × start) carries its own fresh fixed key
// and (single, batched) pair; per-seed BatchHash is wired so
// itb.processChunk128 routes through the batched dispatch on every
// per-pixel hash call.
func benchEncrypt3x128CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc128, itb.BatchHashFunc128), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x128CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc128, itb.BatchHashFunc128), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, _ := itb.Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// benchEncrypt3x256CachedBatchedExt — Triple Ouroboros 256-bit
// counterpart. Mirrors benchEncrypt256CachedBatchedExt in
// itb_ext_test.go; same per-seed maker invocation pattern scaled
// to seven seeds.
func benchEncrypt3x256CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc256, itb.BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x256CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc256, itb.BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, _ := itb.Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// benchEncrypt3x512CachedBatchedExt — Triple Ouroboros 512-bit
// counterpart. Mirrors benchEncrypt512CachedBatchedExt in
// itb_ext_test.go.
func benchEncrypt3x512CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc512, itb.BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x512CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc512, itb.BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, _ := itb.Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// --- BLAKE2b-256 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleBLAKE2b256_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE2b256_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE2b256_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 64<<20)
}
func BenchmarkExtTripleBLAKE2b256_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE2b256_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE2b256_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 64<<20)
}

// --- BLAKE2b-512 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleBLAKE2b512_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE2b512_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE2b512_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 64<<20)
}
func BenchmarkExtTripleBLAKE2b512_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE2b512_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE2b512_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 64<<20)
}

// --- BLAKE2b-256 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleBLAKE2b256_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE2b256_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE2b256_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleBLAKE2b256_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE2b256_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE2b256_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 64<<20)
}

// --- BLAKE2b-512 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleBLAKE2b512_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE2b512_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE2b512_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleBLAKE2b512_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE2b512_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE2b512_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 64<<20)
}

// --- BLAKE2b-256 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleBLAKE2b256_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE2b256_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE2b256_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleBLAKE2b256_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE2b256_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE2b256_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 64<<20)
}

// --- BLAKE2b-512 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleBLAKE2b512_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE2b512_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE2b512_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleBLAKE2b512_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE2b512_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE2b512_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 64<<20)
}

// --- BLAKE2s-256 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleBLAKE2s_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE2s_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE2s_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 64<<20)
}
func BenchmarkExtTripleBLAKE2s_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE2s_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE2s_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 64<<20)
}

// --- BLAKE2s-256 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleBLAKE2s_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE2s_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE2s_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleBLAKE2s_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE2s_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE2s_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 64<<20)
}

// --- BLAKE2s-256 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleBLAKE2s_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE2s_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE2s_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleBLAKE2s_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE2s_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE2s_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 64<<20)
}

// --- BLAKE3-256 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleBLAKE3_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE3_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE3_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 64<<20)
}
func BenchmarkExtTripleBLAKE3_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleBLAKE3_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleBLAKE3_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 64<<20)
}

// --- BLAKE3-256 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleBLAKE3_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE3_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE3_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleBLAKE3_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleBLAKE3_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleBLAKE3_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 64<<20)
}

// --- BLAKE3-256 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleBLAKE3_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE3_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE3_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleBLAKE3_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleBLAKE3_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleBLAKE3_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 64<<20)
}

// --- ChaCha20-256 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleChaCha20_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleChaCha20_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleChaCha20_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 64<<20)
}
func BenchmarkExtTripleChaCha20_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleChaCha20_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleChaCha20_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 64<<20)
}

// --- ChaCha20-256 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleChaCha20_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleChaCha20_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleChaCha20_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleChaCha20_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleChaCha20_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleChaCha20_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 64<<20)
}

// --- ChaCha20-256 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleChaCha20_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleChaCha20_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleChaCha20_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleChaCha20_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleChaCha20_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleChaCha20_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 64<<20)
}

// --- AES-CMAC-128 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleAESCMAC_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 1<<20)
}
func BenchmarkExtTripleAESCMAC_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 16<<20)
}
func BenchmarkExtTripleAESCMAC_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 64<<20)
}
func BenchmarkExtTripleAESCMAC_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 1<<20)
}
func BenchmarkExtTripleAESCMAC_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 16<<20)
}
func BenchmarkExtTripleAESCMAC_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 64<<20)
}

// --- AES-CMAC-128 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleAESCMAC_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleAESCMAC_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleAESCMAC_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleAESCMAC_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleAESCMAC_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleAESCMAC_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 64<<20)
}

// --- AES-CMAC-128 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleAESCMAC_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleAESCMAC_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleAESCMAC_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleAESCMAC_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleAESCMAC_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleAESCMAC_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 64<<20)
}

// --- SipHash-2-4-128 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleSipHash24_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 1<<20)
}
func BenchmarkExtTripleSipHash24_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 16<<20)
}
func BenchmarkExtTripleSipHash24_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 64<<20)
}
func BenchmarkExtTripleSipHash24_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 1<<20)
}
func BenchmarkExtTripleSipHash24_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 16<<20)
}
func BenchmarkExtTripleSipHash24_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 64<<20)
}

// --- SipHash-2-4-128 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleSipHash24_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleSipHash24_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleSipHash24_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleSipHash24_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleSipHash24_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleSipHash24_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 64<<20)
}

// --- SipHash-2-4-128 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleSipHash24_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleSipHash24_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleSipHash24_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleSipHash24_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleSipHash24_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleSipHash24_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 64<<20)
}

// --- Areion-SoEM-256 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleAreion256_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleAreion256_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleAreion256_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 64<<20)
}
func BenchmarkExtTripleAreion256_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtTripleAreion256_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtTripleAreion256_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 64<<20)
}

// --- Areion-SoEM-512 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleAreion512_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 1<<20)
}
func BenchmarkExtTripleAreion512_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 16<<20)
}
func BenchmarkExtTripleAreion512_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 64<<20)
}
func BenchmarkExtTripleAreion512_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 1<<20)
}
func BenchmarkExtTripleAreion512_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 16<<20)
}
func BenchmarkExtTripleAreion512_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 64<<20)
}

// --- Areion-SoEM-256 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleAreion256_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleAreion256_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleAreion256_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleAreion256_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleAreion256_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleAreion256_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 64<<20)
}

// --- Areion-SoEM-512 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleAreion512_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleAreion512_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleAreion512_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 64<<20)
}
func BenchmarkExtTripleAreion512_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 1<<20)
}
func BenchmarkExtTripleAreion512_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 16<<20)
}
func BenchmarkExtTripleAreion512_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 64<<20)
}

// --- Areion-SoEM-256 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleAreion256_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleAreion256_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleAreion256_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleAreion256_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleAreion256_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleAreion256_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 64<<20)
}

// --- Areion-SoEM-512 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleAreion512_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleAreion512_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleAreion512_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 64<<20)
}
func BenchmarkExtTripleAreion512_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 1<<20)
}
func BenchmarkExtTripleAreion512_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 16<<20)
}
func BenchmarkExtTripleAreion512_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 64<<20)
}

// --- Dedicated lockSeed coverage, Triple Ouroboros (BLAKE3 256-bit) ---
//
// The 48-bit interlock overlay is always engaged, so every Triple
// encrypt call consumes the lockSeed argument in the slot immediately
// after noiseSeed. Coverage focuses on the round-trip and the
// mixed-primitive path (lockSeed keyed by a different primitive than
// noiseSeed, exercising the algorithm-diversity defence-in-depth on
// the bit-permutation channel).

// TestTripleLockSeedRoundtrip256 verifies that Triple Ouroboros
// Encrypt3x / Decrypt3x round-trip succeeds with a dedicated
// lockSeed threaded through the eight-seed API.
func TestTripleLockSeedRoundtrip256(t *testing.T) {
	ns := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ds1 := makeBlake3SeedAttachExt(t, 1024)
	ds2 := makeBlake3SeedAttachExt(t, 1024)
	ds3 := makeBlake3SeedAttachExt(t, 1024)
	ss1 := makeBlake3SeedAttachExt(t, 1024)
	ss2 := makeBlake3SeedAttachExt(t, 1024)
	ss3 := makeBlake3SeedAttachExt(t, 1024)

	plaintext := generateDataExt(1024)
	ct, err := itb.Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256: %v", err)
	}
	pt, err := itb.Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Triple lockSeed roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// BenchmarkExtTripleBLAKE3RoundTripLockSeed measures the itb root
// Encrypt3x + Decrypt3x round-trip throughput and per-iteration
// allocation footprint under the 8-seed API. The configuration
// mirrors the realistic shape:
//
//   - 1024-bit ITB key width (canonical mid-range).
//   - 64 MiB plaintext (large enough that the per-pixel hash
//     pipeline dominates and bench noise from the round-trip-
//     framing overhead is negligible).
//   - BLAKE3 keyed-hash primitive via [hashes.BLAKE3256Pair],
//     which on amd64 + AVX-512 dispatches the batched arm to the
//     ZMM-batched chain-absorb kernels in
//     hashes/internal/blake3asm. A fresh BLAKE3 fixed key is
//     generated for each of the eight seeds so all carry
//     independent keying material.
//
// Run as:
//
//	go test -bench=BenchmarkExtTripleBLAKE3RoundTripLockSeed \
//	    -benchmem -run=^$ -count=3 -benchtime=3x
func BenchmarkExtTripleBLAKE3RoundTripLockSeed(b *testing.B) {
	const (
		bits     = 1024
		dataSize = 64 << 20
	)

	mkSeed := func(role string) *itb.Seed256 {
		h, bh, _ := hashes.BLAKE3256Pair()
		s, err := itb.NewSeed256(bits, h)
		if err != nil {
			b.Fatalf("NewSeed256(%s): %v", role, err)
		}
		s.BatchHash = bh
		return s
	}
	ns := mkSeed("noiseSeed")
	ls := mkSeed("lockSeed")
	ds1 := mkSeed("dataSeed1")
	ds2 := mkSeed("dataSeed2")
	ds3 := mkSeed("dataSeed3")
	ss1 := mkSeed("startSeed1")
	ss2 := mkSeed("startSeed2")
	ss3 := mkSeed("startSeed3")

	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
		if err != nil {
			b.Fatalf("Encrypt3x256: %v", err)
		}
		if _, err := itb.Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted); err != nil {
			b.Fatalf("Decrypt3x256: %v", err)
		}
	}
}

// TestTripleLockSeedMixedPrimitive256 verifies that Triple round-trip
// succeeds with a BLAKE2s-keyed lockSeed alongside a BLAKE3-keyed
// noiseSeed (and BLAKE3 across the 3 dataSeeds + 3 startSeeds). The
// Triple build-PRF closure captures the lockSeed's Hash, so the
// bit-permutation overlay observably runs through the lockSeed
// primitive while the noise-injection channel runs through the
// noiseSeed primitive.
func TestTripleLockSeedMixedPrimitive256(t *testing.T) {
	ns := makeBlake3SeedAttachExt(t, 1024)
	ds1 := makeBlake3SeedAttachExt(t, 1024)
	ds2 := makeBlake3SeedAttachExt(t, 1024)
	ds3 := makeBlake3SeedAttachExt(t, 1024)
	ss1 := makeBlake3SeedAttachExt(t, 1024)
	ss2 := makeBlake3SeedAttachExt(t, 1024)
	ss3 := makeBlake3SeedAttachExt(t, 1024)

	hL, bL, _ := hashes.BLAKE2s256Pair()
	ls, err := itb.NewSeed256(1024, hL)
	if err != nil {
		t.Fatalf("NewSeed256 (BLAKE2s lockSeed): %v", err)
	}
	ls.BatchHash = bL

	plaintext := generateDataExt(2048)
	ct, err := itb.Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256 (mixed-primitive lockSeed): %v", err)
	}
	pt, err := itb.Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256 (mixed-primitive lockSeed): %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Triple mixed-primitive lockSeed roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// --- Fleet-shape benches: triple facade Pipeline, binding-comparable ---
//
// The BenchmarkFleetGoNative_* cohort measures the Go-native triple
// facade at the exact layer the binding shims drive: profile-based
// [triple.Init] plus [triple.Pipeline.EncryptMessage] /
// [triple.Pipeline.DecryptMessage] / [triple.Pipeline.EncryptStream] /
// [triple.Pipeline.DecryptStream]. The numbers are therefore directly
// comparable with binding-fleet bench output minus the FFI hop. Two
// configurations, matching the binding-fleet bench shape:
//
//   - Canonical:  No MAC profiles (Single Message / Streaming
//     Non-AEAD), parallax off, wrapper off — the fair-comparison
//     floor every binding bench targets by default.
//   - Production: MAC profiles (Single Message MAC / Streaming AEAD),
//     parallax on, wrapper on — the shipped production shape.
//
// Both configurations pin Areion-SoEM-512 inner hash, 1024-bit keys,
// and a 512-bit nonce.

// fleetBenchOpts builds the [triple.Opts] for the fleet-shape bench
// cohort. production toggles the parallax + wrapper layers; the
// remaining knobs pin the canonical binding bench configuration
// explicitly so profile-default drift cannot silently change the
// measured shape.
func fleetBenchOpts(production bool) triple.Opts {
	parallaxOn := production
	wrapperOn := production
	return triple.Opts{
		InnerHash:    "areion512",
		KeyBits:      1024,
		NonceBits:    512,
		WithParallax: &parallaxOn,
		WithWrapper:  &wrapperOn,
	}
}

// fleetBenchPipeline constructs the bench [triple.Pipeline] against
// the named profile with the fleet-shape Opts, registering Close via
// [testing.B.Cleanup]. Construction (seed generation, layer key
// derivation) happens once per bench function, outside the timed loop.
func fleetBenchPipeline(b *testing.B, profile string, production bool) *triple.Pipeline {
	b.Helper()
	pipe, _, err := triple.Init(profile, fleetBenchOpts(production))
	if err != nil {
		b.Fatalf("triple.Init(%s): %v", profile, err)
	}
	b.Cleanup(func() { _ = pipe.Close() })
	return pipe
}

// benchFleetMessageEncrypt drives [triple.Pipeline.EncryptMessage]
// over a CSPRNG-filled plaintext of dataSize bytes. One untimed call
// precedes the timed loop, mirroring the binding bench harnesses'
// warm-up round.
func benchFleetMessageEncrypt(b *testing.B, profile string, production bool, dataSize int) {
	pipe := fleetBenchPipeline(b, profile, production)
	data := generateDataExt(dataSize)
	if _, err := pipe.EncryptMessage(data); err != nil {
		b.Fatalf("EncryptMessage warm-up: %v", err)
	}
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pipe.EncryptMessage(data); err != nil {
			b.Fatalf("EncryptMessage: %v", err)
		}
	}
}

// benchFleetMessageDecrypt pre-encrypts one wire outside the timed
// loop, then drives [triple.Pipeline.DecryptMessage] on that wire.
// The pre-encrypt doubles as the warm-up round.
func benchFleetMessageDecrypt(b *testing.B, profile string, production bool, dataSize int) {
	pipe := fleetBenchPipeline(b, profile, production)
	data := generateDataExt(dataSize)
	wire, err := pipe.EncryptMessage(data)
	if err != nil {
		b.Fatalf("EncryptMessage (pre-encrypt): %v", err)
	}
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pipe.DecryptMessage(wire); err != nil {
			b.Fatalf("DecryptMessage: %v", err)
		}
	}
}

// benchFleetStreamEncrypt drives [triple.Pipeline.EncryptStream]
// through the same reader/buffer pump the binding stream shims use:
// [bytes.NewReader] on the plaintext feeding a wire [bytes.Buffer].
// The buffer is reset (not reallocated) per iteration; the untimed
// first pump warms the dispatch path and sizes the buffer.
func benchFleetStreamEncrypt(b *testing.B, profile string, production bool, dataSize int) {
	pipe := fleetBenchPipeline(b, profile, production)
	data := generateDataExt(dataSize)
	var wire bytes.Buffer
	wire.Grow(dataSize + dataSize/4 + 65536)
	if err := pipe.EncryptStream(bytes.NewReader(data), &wire); err != nil {
		b.Fatalf("EncryptStream warm-up: %v", err)
	}
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire.Reset()
		if err := pipe.EncryptStream(bytes.NewReader(data), &wire); err != nil {
			b.Fatalf("EncryptStream: %v", err)
		}
	}
}

// benchFleetStreamDecrypt pre-encrypts one wire outside the timed
// loop, then drives [triple.Pipeline.DecryptStream] on that wire into
// a reset-per-iteration plaintext [bytes.Buffer].
func benchFleetStreamDecrypt(b *testing.B, profile string, production bool, dataSize int) {
	pipe := fleetBenchPipeline(b, profile, production)
	data := generateDataExt(dataSize)
	var wireBuf bytes.Buffer
	wireBuf.Grow(dataSize + dataSize/4 + 65536)
	if err := pipe.EncryptStream(bytes.NewReader(data), &wireBuf); err != nil {
		b.Fatalf("EncryptStream (pre-encrypt): %v", err)
	}
	wire := wireBuf.Bytes()
	var plain bytes.Buffer
	plain.Grow(dataSize + 65536)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plain.Reset()
		if err := pipe.DecryptStream(bytes.NewReader(wire), &plain); err != nil {
			b.Fatalf("DecryptStream: %v", err)
		}
	}
}

// --- Fleet Canonical Message: Single Message No MAC, parallax off, wrapper off ---

func BenchmarkFleetGoNative_Canonical_Message_Encrypt_1MB(b *testing.B) {
	benchFleetMessageEncrypt(b, triple.ProfileSingleMsgTripleNoMACV1, false, 1<<20)
}
func BenchmarkFleetGoNative_Canonical_Message_Encrypt_16MB(b *testing.B) {
	benchFleetMessageEncrypt(b, triple.ProfileSingleMsgTripleNoMACV1, false, 16<<20)
}
func BenchmarkFleetGoNative_Canonical_Message_Encrypt_64MB(b *testing.B) {
	benchFleetMessageEncrypt(b, triple.ProfileSingleMsgTripleNoMACV1, false, 64<<20)
}
func BenchmarkFleetGoNative_Canonical_Message_Decrypt_1MB(b *testing.B) {
	benchFleetMessageDecrypt(b, triple.ProfileSingleMsgTripleNoMACV1, false, 1<<20)
}
func BenchmarkFleetGoNative_Canonical_Message_Decrypt_16MB(b *testing.B) {
	benchFleetMessageDecrypt(b, triple.ProfileSingleMsgTripleNoMACV1, false, 16<<20)
}
func BenchmarkFleetGoNative_Canonical_Message_Decrypt_64MB(b *testing.B) {
	benchFleetMessageDecrypt(b, triple.ProfileSingleMsgTripleNoMACV1, false, 64<<20)
}

// --- Fleet Canonical Stream: Streaming Non-AEAD, parallax off, wrapper off ---

func BenchmarkFleetGoNative_Canonical_Stream_Encrypt_1MB(b *testing.B) {
	benchFleetStreamEncrypt(b, triple.ProfileStreamingNoAEADTripleV1, false, 1<<20)
}
func BenchmarkFleetGoNative_Canonical_Stream_Encrypt_16MB(b *testing.B) {
	benchFleetStreamEncrypt(b, triple.ProfileStreamingNoAEADTripleV1, false, 16<<20)
}
func BenchmarkFleetGoNative_Canonical_Stream_Encrypt_64MB(b *testing.B) {
	benchFleetStreamEncrypt(b, triple.ProfileStreamingNoAEADTripleV1, false, 64<<20)
}
func BenchmarkFleetGoNative_Canonical_Stream_Decrypt_1MB(b *testing.B) {
	benchFleetStreamDecrypt(b, triple.ProfileStreamingNoAEADTripleV1, false, 1<<20)
}
func BenchmarkFleetGoNative_Canonical_Stream_Decrypt_16MB(b *testing.B) {
	benchFleetStreamDecrypt(b, triple.ProfileStreamingNoAEADTripleV1, false, 16<<20)
}
func BenchmarkFleetGoNative_Canonical_Stream_Decrypt_64MB(b *testing.B) {
	benchFleetStreamDecrypt(b, triple.ProfileStreamingNoAEADTripleV1, false, 64<<20)
}

// --- Fleet Production Message: Single Message MAC, parallax on, wrapper on ---

func BenchmarkFleetGoNative_Production_Message_Encrypt_1MB(b *testing.B) {
	benchFleetMessageEncrypt(b, triple.ProfileSingleMsgTripleMACV1, true, 1<<20)
}
func BenchmarkFleetGoNative_Production_Message_Encrypt_16MB(b *testing.B) {
	benchFleetMessageEncrypt(b, triple.ProfileSingleMsgTripleMACV1, true, 16<<20)
}
func BenchmarkFleetGoNative_Production_Message_Encrypt_64MB(b *testing.B) {
	benchFleetMessageEncrypt(b, triple.ProfileSingleMsgTripleMACV1, true, 64<<20)
}
func BenchmarkFleetGoNative_Production_Message_Decrypt_1MB(b *testing.B) {
	benchFleetMessageDecrypt(b, triple.ProfileSingleMsgTripleMACV1, true, 1<<20)
}
func BenchmarkFleetGoNative_Production_Message_Decrypt_16MB(b *testing.B) {
	benchFleetMessageDecrypt(b, triple.ProfileSingleMsgTripleMACV1, true, 16<<20)
}
func BenchmarkFleetGoNative_Production_Message_Decrypt_64MB(b *testing.B) {
	benchFleetMessageDecrypt(b, triple.ProfileSingleMsgTripleMACV1, true, 64<<20)
}

// --- Fleet Production Stream: Streaming AEAD MAC, parallax on, wrapper on ---

func BenchmarkFleetGoNative_Production_Stream_Encrypt_1MB(b *testing.B) {
	benchFleetStreamEncrypt(b, triple.ProfileStreamingAEADTripleMACV1, true, 1<<20)
}
func BenchmarkFleetGoNative_Production_Stream_Encrypt_16MB(b *testing.B) {
	benchFleetStreamEncrypt(b, triple.ProfileStreamingAEADTripleMACV1, true, 16<<20)
}
func BenchmarkFleetGoNative_Production_Stream_Encrypt_64MB(b *testing.B) {
	benchFleetStreamEncrypt(b, triple.ProfileStreamingAEADTripleMACV1, true, 64<<20)
}
func BenchmarkFleetGoNative_Production_Stream_Decrypt_1MB(b *testing.B) {
	benchFleetStreamDecrypt(b, triple.ProfileStreamingAEADTripleMACV1, true, 1<<20)
}
func BenchmarkFleetGoNative_Production_Stream_Decrypt_16MB(b *testing.B) {
	benchFleetStreamDecrypt(b, triple.ProfileStreamingAEADTripleMACV1, true, 16<<20)
}
func BenchmarkFleetGoNative_Production_Stream_Decrypt_64MB(b *testing.B) {
	benchFleetStreamDecrypt(b, triple.ProfileStreamingAEADTripleMACV1, true, 64<<20)
}
