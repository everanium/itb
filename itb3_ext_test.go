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
	"errors"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// makeSevenSeeds128Ext is the external-test counterpart of
// itb_test.go:makeSevenSeeds128. Constructs the seven independent
// 128-bit ITB seeds the Triple Ouroboros API consumes (1 noise +
// 3 data + 3 start), all bound to the same single-call hash
// function. The bench helpers below override per-seed Hash and
// BatchHash fields with fresh maker() pairs so each seed carries
// its own fixed key — same shape as the Single bench helpers in
// itb_ext_test.go scale up for seven seeds.
func makeSevenSeeds128Ext(bits int, h itb.HashFunc128) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed128) {
	ns, _ = itb.NewSeed128(bits, h)
	ds1, _ = itb.NewSeed128(bits, h)
	ds2, _ = itb.NewSeed128(bits, h)
	ds3, _ = itb.NewSeed128(bits, h)
	ss1, _ = itb.NewSeed128(bits, h)
	ss2, _ = itb.NewSeed128(bits, h)
	ss3, _ = itb.NewSeed128(bits, h)
	return
}

// makeSevenSeeds256Ext is the 256-bit counterpart.
func makeSevenSeeds256Ext(bits int, h itb.HashFunc256) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed256) {
	ns, _ = itb.NewSeed256(bits, h)
	ds1, _ = itb.NewSeed256(bits, h)
	ds2, _ = itb.NewSeed256(bits, h)
	ds3, _ = itb.NewSeed256(bits, h)
	ss1, _ = itb.NewSeed256(bits, h)
	ss2, _ = itb.NewSeed256(bits, h)
	ss3, _ = itb.NewSeed256(bits, h)
	return
}

// makeSevenSeeds512Ext is the 512-bit counterpart.
func makeSevenSeeds512Ext(bits int, h itb.HashFunc512) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed512) {
	ns, _ = itb.NewSeed512(bits, h)
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
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker(); ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker(); ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker(); ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker(); ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker(); ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker(); ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x128CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc128, itb.BatchHashFunc128), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker(); ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker(); ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker(); ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker(); ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker(); ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker(); ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	encrypted, _ := itb.Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// benchEncrypt3x256CachedBatchedExt — Triple Ouroboros 256-bit
// counterpart. Mirrors benchEncrypt256CachedBatchedExt in
// itb_ext_test.go; same per-seed maker invocation pattern scaled
// to seven seeds.
func benchEncrypt3x256CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc256, itb.BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker(); ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker(); ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker(); ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker(); ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker(); ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker(); ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x256CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc256, itb.BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker(); ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker(); ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker(); ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker(); ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker(); ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker(); ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	encrypted, _ := itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// benchEncrypt3x512CachedBatchedExt — Triple Ouroboros 512-bit
// counterpart. Mirrors benchEncrypt512CachedBatchedExt in
// itb_ext_test.go.
func benchEncrypt3x512CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc512, itb.BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker(); ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker(); ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker(); ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker(); ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker(); ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker(); ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchDecrypt3x512CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc512, itb.BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512Ext(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker(); ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker(); ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker(); ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker(); ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker(); ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker(); ss3.Hash, ss3.BatchHash = h, bf
	data := generateDataExt(dataSize)
	encrypted, _ := itb.Encrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
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

// --- AttachLockSeed coverage, Triple Ouroboros (BLAKE3 256-bit) ---
//
// Mirror of the AttachLockSeed test cohort in itb_ext_test.go for
// the Triple Ouroboros entry points (Encrypt3x256 / Decrypt3x256).
// The shared helpers makeBlake3SeedAttachExt and
// withLockSoupAttachExt (defined in itb_ext_test.go, same
// package itb_test) and the file-local generateDataExt are
// reused verbatim.
//
// Coverage is identical in shape to the Single cohort:
//
//   - Round-trip with a dedicated lockSeed attached to the sole
//     noiseSeed of the seven-seed Triple constellation (one
//     noise + three data + three start) under SetLockSoup(1).
//   - Self-attach safeguard panic (ErrLockSeedSelfAttach).
//   - Component-aliasing safeguard panic
//     (ErrLockSeedComponentAliasing).
//   - Post-Encrypt safeguard panic (ErrLockSeedAfterEncrypt) —
//     here the firstEncryptCalled gate is tripped through
//     Encrypt3x256 instead of Encrypt256, exercising the
//     Triple-side process function's encode-branch flag store.
//
// AttachLockSeed and its safeguards are width-symmetric, so the
// BLAKE3 256-bit primitive at 1024-bit ITB width is enough to
// catch shape regressions on the Triple side too.

// TestTripleAttachLockSeedRoundtrip256 verifies that Triple Ouroboros
// Encrypt3x / Decrypt3x round-trip succeeds with a dedicated
// lockSeed attached to the sole noiseSeed. SetLockSoup(1) engages
// the bit-permutation overlay via buildLockPRF256.
func TestTripleAttachLockSeedRoundtrip256(t *testing.T) {
	withLockSoupAttachExt(t)

	ns := makeBlake3SeedAttachExt(t, 1024)
	ds1 := makeBlake3SeedAttachExt(t, 1024)
	ds2 := makeBlake3SeedAttachExt(t, 1024)
	ds3 := makeBlake3SeedAttachExt(t, 1024)
	ss1 := makeBlake3SeedAttachExt(t, 1024)
	ss2 := makeBlake3SeedAttachExt(t, 1024)
	ss3 := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ns.AttachLockSeed(ls)

	plaintext := generateDataExt(1024)
	ct, err := itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256: %v", err)
	}
	pt, err := itb.Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Triple AttachLockSeed roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestTripleAttachLockSeedSelfAttachPanic verifies the self-attach
// safeguard from the Triple cohort — passing the receiver itself
// as the lockSeed argument panics with [itb.ErrLockSeedSelfAttach]
// rather than silently degrading to a no-op self-derivation. The
// safeguard is width / mode symmetric; the test runs as a Triple-
// flavoured smoke check parallel to itb_ext_test.go's
// TestAttachLockSeedSelfAttachPanic.
func TestTripleAttachLockSeedSelfAttachPanic(t *testing.T) {
	ns := makeBlake3SeedAttachExt(t, 1024)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("AttachLockSeed(ns): expected panic, got none")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, itb.ErrLockSeedSelfAttach) {
			t.Errorf("AttachLockSeed(ns): panic %v, want %v", r, itb.ErrLockSeedSelfAttach)
		}
	}()
	ns.AttachLockSeed(ns)
}

// TestTripleAttachLockSeedComponentAliasingPanic verifies the
// component-aliasing safeguard from the Triple cohort — when two
// distinct *Seed256 values share the same Components backing
// array, AttachLockSeed panics with
// [itb.ErrLockSeedComponentAliasing] rather than silently
// accepting the duplicated entropy source.
func TestTripleAttachLockSeedComponentAliasingPanic(t *testing.T) {
	ns := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ls.Components = ns.Components // alias the backing array

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("AttachLockSeed(aliased ls): expected panic, got none")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, itb.ErrLockSeedComponentAliasing) {
			t.Errorf("AttachLockSeed(aliased ls): panic %v, want %v",
				r, itb.ErrLockSeedComponentAliasing)
		}
	}()
	ns.AttachLockSeed(ls)
}

// TestTripleAttachLockSeedAfterEncryptPanic verifies the
// post-Encrypt safeguard from the Triple cohort. The
// firstEncryptCalled gate on the noiseSeed is tripped via
// Encrypt3x256 (instead of the Single Encrypt256 used in the
// itb_ext_test.go counterpart), confirming that the process3x
// path also stores the gate flag on the encode branch and the
// AttachLockSeed re-attach safeguard fires correctly afterwards.
func TestTripleAttachLockSeedAfterEncryptPanic(t *testing.T) {
	withLockSoupAttachExt(t)

	ns := makeBlake3SeedAttachExt(t, 1024)
	ds1 := makeBlake3SeedAttachExt(t, 1024)
	ds2 := makeBlake3SeedAttachExt(t, 1024)
	ds3 := makeBlake3SeedAttachExt(t, 1024)
	ss1 := makeBlake3SeedAttachExt(t, 1024)
	ss2 := makeBlake3SeedAttachExt(t, 1024)
	ss3 := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ns.AttachLockSeed(ls) // pre-Encrypt attach is fine

	plaintext := generateDataExt(64)
	if _, err := itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext); err != nil {
		t.Fatalf("pre-panic Encrypt3x256: %v", err)
	}

	ls2 := makeBlake3SeedAttachExt(t, 1024)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("AttachLockSeed(ls2) after Encrypt3x: expected panic, got none")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, itb.ErrLockSeedAfterEncrypt) {
			t.Errorf("AttachLockSeed(ls2) after Encrypt3x: panic %v, want %v",
				r, itb.ErrLockSeedAfterEncrypt)
		}
	}()
	ns.AttachLockSeed(ls2)
}

// BenchmarkExtTripleBLAKE3RoundTripAttachedLockSeed measures the
// legacy itb root Encrypt3x + Decrypt3x round-trip throughput and
// per-iteration allocation footprint when a dedicated lockSeed has
// been wired into the noiseSeed via [itb.Seed256.AttachLockSeed].
// Triple Ouroboros counterpart of
// [BenchmarkExtSingleBLAKE3RoundTripAttachedLockSeed] in
// itb_ext_test.go — same shape, same bench loop, the only
// difference is the seven-seed constellation (one noise + three
// data + three start) feeding Encrypt3x256 / Decrypt3x256 instead
// of the three-seed Single trio feeding Encrypt256 / Decrypt256.
//
// The configuration mirrors the realistic shape:
//
//   - 1024-bit ITB key width (canonical mid-range).
//   - 64 MiB plaintext (large enough that the per-pixel hash
//     pipeline dominates and bench noise from the round-trip-
//     framing overhead is negligible).
//   - BLAKE3 keyed-hash primitive via [hashes.BLAKE3256Pair],
//     which on amd64 + AVX-512 dispatches the batched arm to the
//     ZMM-batched chain-absorb kernels in
//     hashes/internal/blake3asm. A fresh BLAKE3 fixed key is
//     generated for each of the eight seeds (noise / 3× data /
//     3× start / lockSeed) so all eight seeds carry independent
//     keying material.
//   - Triple Ouroboros (1 noise + 3 data + 3 start = 7 seeds)
//     plus an 8th dedicated lockSeed attached via
//     ns.AttachLockSeed(ls).
//   - SetLockSoup(1) engaged so the bit-permutation overlay
//     actually consumes the attached lockSeed; otherwise the
//     attach call is a no-op and the bench measures plain
//     Encrypt3x + Decrypt3x without exercising the LockSeed
//     path.
//
// Run as:
//
//	go test -bench=BenchmarkExtTripleBLAKE3RoundTripAttachedLockSeed \
//	    -benchmem -run=^$ -count=3 -benchtime=3x
//
// to dump per-iteration ns/op + B/op + allocs/op for inspection.
func BenchmarkExtTripleBLAKE3RoundTripAttachedLockSeed(b *testing.B) {
	prevBS := itb.GetBitSoup()
	prevLS := itb.GetLockSoup()
	itb.SetLockSoup(1)
	b.Cleanup(func() {
		itb.SetBitSoup(prevBS)
		itb.SetLockSoup(prevLS)
	})

	const (
		bits     = 1024
		dataSize = 64 << 20
	)

	hN, bN, _ := hashes.BLAKE3256Pair()
	ns, err := itb.NewSeed256(bits, hN)
	if err != nil {
		b.Fatalf("NewSeed256(noiseSeed): %v", err)
	}
	ns.BatchHash = bN

	hD1, bD1, _ := hashes.BLAKE3256Pair()
	ds1, err := itb.NewSeed256(bits, hD1)
	if err != nil {
		b.Fatalf("NewSeed256(dataSeed1): %v", err)
	}
	ds1.BatchHash = bD1

	hD2, bD2, _ := hashes.BLAKE3256Pair()
	ds2, err := itb.NewSeed256(bits, hD2)
	if err != nil {
		b.Fatalf("NewSeed256(dataSeed2): %v", err)
	}
	ds2.BatchHash = bD2

	hD3, bD3, _ := hashes.BLAKE3256Pair()
	ds3, err := itb.NewSeed256(bits, hD3)
	if err != nil {
		b.Fatalf("NewSeed256(dataSeed3): %v", err)
	}
	ds3.BatchHash = bD3

	hS1, bS1, _ := hashes.BLAKE3256Pair()
	ss1, err := itb.NewSeed256(bits, hS1)
	if err != nil {
		b.Fatalf("NewSeed256(startSeed1): %v", err)
	}
	ss1.BatchHash = bS1

	hS2, bS2, _ := hashes.BLAKE3256Pair()
	ss2, err := itb.NewSeed256(bits, hS2)
	if err != nil {
		b.Fatalf("NewSeed256(startSeed2): %v", err)
	}
	ss2.BatchHash = bS2

	hS3, bS3, _ := hashes.BLAKE3256Pair()
	ss3, err := itb.NewSeed256(bits, hS3)
	if err != nil {
		b.Fatalf("NewSeed256(startSeed3): %v", err)
	}
	ss3.BatchHash = bS3

	hL, bL, _ := hashes.BLAKE3256Pair()
	ls, err := itb.NewSeed256(bits, hL)
	if err != nil {
		b.Fatalf("NewSeed256(lockSeed): %v", err)
	}
	ls.BatchHash = bL

	ns.AttachLockSeed(ls)

	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
		if err != nil {
			b.Fatalf("Encrypt3x256: %v", err)
		}
		if _, err := itb.Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted); err != nil {
			b.Fatalf("Decrypt3x256: %v", err)
		}
	}
}

// TestExtTripleAttachLockSeedOverlayOffPanic — Triple Ouroboros
// counterpart of [TestExtSingleAttachLockSeedOverlayOffPanic] in
// itb_ext_test.go. Same regression-pinning role for the
// itb.Encrypt3x256 public entry point: a noiseSeed carrying an
// attached dedicated lockSeed but reaching the bit-permutation PRF
// builder with neither global BitSoup nor global LockSoup engaged
// panics with [itb.ErrLockSeedOverlayOff] inside [buildLockPRF256]
// rather than silently producing byte-level ciphertext.
//
// Reuses [makeBlake3SeedAttachExt] / [generateDataExt] from
// itb_ext_test.go (same itb_test package) — both files share the
// helpers via package-level visibility.
func TestExtTripleAttachLockSeedOverlayOffPanic(t *testing.T) {
	prevBS := itb.GetBitSoup()
	prevLS := itb.GetLockSoup()
	itb.SetBitSoup(0)
	itb.SetLockSoup(0)
	t.Cleanup(func() {
		itb.SetBitSoup(prevBS)
		itb.SetLockSoup(prevLS)
	})

	ns := makeBlake3SeedAttachExt(t, 1024)
	ds1 := makeBlake3SeedAttachExt(t, 1024)
	ds2 := makeBlake3SeedAttachExt(t, 1024)
	ds3 := makeBlake3SeedAttachExt(t, 1024)
	ss1 := makeBlake3SeedAttachExt(t, 1024)
	ss2 := makeBlake3SeedAttachExt(t, 1024)
	ss3 := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ns.AttachLockSeed(ls)

	plaintext := generateDataExt(64)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("itb.Encrypt3x256 with attached lockSeed and overlay off: expected panic, got none")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, itb.ErrLockSeedOverlayOff) {
			t.Errorf("itb.Encrypt3x256: panic %v, want %v", r, itb.ErrLockSeedOverlayOff)
		}
	}()
	_, _ = itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
}

// TestTripleAttachLockSeedMixedPrimitive256 — Triple Ouroboros
// counterpart of [TestSingleAttachLockSeedMixedPrimitive256].
// Verifies that Triple round-trip succeeds with a BLAKE2s-keyed
// lockSeed attached to a BLAKE3-keyed noiseSeed (and BLAKE3 across
// the 3 dataSeeds + 3 startSeeds). Triple Lock Soup's build-PRF
// closure captures src.Hash, so the bit-permutation overlay
// observably runs through the lockSeed primitive while the noise-
// injection channel runs through the noiseSeed primitive.
func TestTripleAttachLockSeedMixedPrimitive256(t *testing.T) {
	withLockSoupAttachExt(t)

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
	ns.AttachLockSeed(ls)

	plaintext := generateDataExt(2048)
	ct, err := itb.Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256 (mixed-primitive lockSeed): %v", err)
	}
	pt, err := itb.Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256 (mixed-primitive lockSeed): %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Triple mixed-primitive AttachLockSeed roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}
