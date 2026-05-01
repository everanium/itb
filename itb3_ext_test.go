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
	"testing"

	"github.com/everanium/itb"
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
