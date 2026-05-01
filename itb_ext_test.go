// Package itb_test (external) hosts ITB integration benchmarks and
// helpers for hash primitives whose factories live in subpackages
// (e.g. github.com/everanium/itb/hashes) that import the itb root —
// importing them from the internal itb_test.go would create a cycle.
//
// The naming convention used here:
//
//   - lowercase helpers carry an "Ext" suffix (makeBlake2bHash256PairExt,
//     benchEncrypt256CachedBatchedExt, …) so they cannot collide with
//     same-name internal helpers in itb_test.go's package itb.
//   - exported benchmark functions carry an "Ext" infix immediately
//     after the "Benchmark" prefix
//     (BenchmarkExtSingleBLAKE2b256_512bit_Encrypt_1MB) so the test
//     harness reports them as a distinct cohort from the
//     BenchmarkSingleBLAKE2b… cohort emitted by itb_test.go.
//
// This file deliberately duplicates the bench-helper bodies
// (benchEncrypt/Decrypt256/512CachedBatchedExt, makeTripleSeed256/512Ext,
// generateDataExt) rather than capitalising the originals in
// itb_test.go — to avoid touching the existing test surface and keep
// internal helpers private. As more primitives migrate to the
// ZMM-batched chain-absorb path, their pair makers and benchmarks
// land in this file, reusing the duplicated bench helpers.
package itb_test

import (
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// makeTripleSeed128Ext is the external-test counterpart of
// itb_test.go:makeTripleSeed128. Constructs three independent
// 128-bit ITB seeds bound to the same single-call hash function.
func makeTripleSeed128Ext(bits int, h itb.HashFunc128) (noise, data, start *itb.Seed128) {
	noise, _ = itb.NewSeed128(bits, h)
	data, _ = itb.NewSeed128(bits, h)
	start, _ = itb.NewSeed128(bits, h)
	return
}

// makeTripleSeed256Ext is the external-test counterpart of
// itb_test.go:makeTripleSeed256. Constructs three independent
// 256-bit ITB seeds bound to the same single-call hash function.
func makeTripleSeed256Ext(bits int, h itb.HashFunc256) (noise, data, start *itb.Seed256) {
	noise, _ = itb.NewSeed256(bits, h)
	data, _ = itb.NewSeed256(bits, h)
	start, _ = itb.NewSeed256(bits, h)
	return
}

// makeTripleSeed512Ext is the 512-bit counterpart of makeTripleSeed256Ext.
func makeTripleSeed512Ext(bits int, h itb.HashFunc512) (noise, data, start *itb.Seed512) {
	noise, _ = itb.NewSeed512(bits, h)
	data, _ = itb.NewSeed512(bits, h)
	start, _ = itb.NewSeed512(bits, h)
	return
}

// generateDataExt fills an n-byte slice with crypto/rand bytes for
// bench plaintext.
func generateDataExt(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// makeBlake2bHash256PairExt returns a fresh BLAKE2b-256 (single, batched)
// pair routed through hashes.BLAKE2b256Pair — which on amd64 + AVX-512
// dispatches the batched arm to the ZMM-batched chain-absorb kernels in
// hashes/internal/blake2basm. The fixed key is generated fresh on every
// call (same shape as makeAreionSoEM256Pair); both arms share that key.
func makeBlake2bHash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.BLAKE2b256Pair()
	return h, b
}

// makeBlake2bHash512PairExt is the 512-bit counterpart.
func makeBlake2bHash512PairExt() (itb.HashFunc512, itb.BatchHashFunc512) {
	h, b, _ := hashes.BLAKE2b512Pair()
	return h, b
}

// benchEncrypt128CachedBatchedExt mirrors itb_test.go:benchEncrypt128CachedBatched
// using only itb's exported surface. Builds three independent ITB seeds,
// each with its own fresh (single, batched) pair via maker(); the
// batched arm sets Seed128.BatchHash so processChunk128 dispatches via
// the four-way batched path.
func benchEncrypt128CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc128, itb.BatchHashFunc128), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds, ss := makeTripleSeed128Ext(bits, nsH)
	ns.BatchHash = nsB
	dsH, dsB := maker()
	ds.Hash = dsH
	ds.BatchHash = dsB
	ssH, ssB := maker()
	ss.Hash = ssH
	ss.BatchHash = ssB
	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt128(ns, ds, ss, data)
	}
}

// benchDecrypt128CachedBatchedExt mirrors benchDecrypt128CachedBatched.
func benchDecrypt128CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc128, itb.BatchHashFunc128), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds, ss := makeTripleSeed128Ext(bits, nsH)
	ns.BatchHash = nsB
	dsH, dsB := maker()
	ds.Hash = dsH
	ds.BatchHash = dsB
	ssH, ssB := maker()
	ss.Hash = ssH
	ss.BatchHash = ssB
	data := generateDataExt(dataSize)
	encrypted, _ := itb.Encrypt128(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt128(ns, ds, ss, encrypted)
	}
}

// benchEncrypt256CachedBatchedExt mirrors itb_test.go:benchEncrypt256CachedBatched
// using only itb's exported surface. Builds three independent ITB seeds,
// each with its own fresh (single, batched) pair via maker(); the
// batched arm sets Seed256.BatchHash so processChunk256 dispatches via
// the four-way batched path.
func benchEncrypt256CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc256, itb.BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds, ss := makeTripleSeed256Ext(bits, nsH)
	ns.BatchHash = nsB
	dsH, dsB := maker()
	ds.Hash = dsH
	ds.BatchHash = dsB
	ssH, ssB := maker()
	ss.Hash = ssH
	ss.BatchHash = ssB
	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt256(ns, ds, ss, data)
	}
}

// benchDecrypt256CachedBatchedExt mirrors benchDecrypt256CachedBatched.
func benchDecrypt256CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc256, itb.BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds, ss := makeTripleSeed256Ext(bits, nsH)
	ns.BatchHash = nsB
	dsH, dsB := maker()
	ds.Hash = dsH
	ds.BatchHash = dsB
	ssH, ssB := maker()
	ss.Hash = ssH
	ss.BatchHash = ssB
	data := generateDataExt(dataSize)
	encrypted, _ := itb.Encrypt256(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt256(ns, ds, ss, encrypted)
	}
}

// benchEncrypt512CachedBatchedExt mirrors benchEncrypt512CachedBatched.
func benchEncrypt512CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc512, itb.BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds, ss := makeTripleSeed512Ext(bits, nsH)
	ns.BatchHash = nsB
	dsH, dsB := maker()
	ds.Hash = dsH
	ds.BatchHash = dsB
	ssH, ssB := maker()
	ss.Hash = ssH
	ss.BatchHash = ssB
	data := generateDataExt(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt512(ns, ds, ss, data)
	}
}

// benchDecrypt512CachedBatchedExt mirrors benchDecrypt512CachedBatched.
func benchDecrypt512CachedBatchedExt(b *testing.B, maker func() (itb.HashFunc512, itb.BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ds, ss := makeTripleSeed512Ext(bits, nsH)
	ns.BatchHash = nsB
	dsH, dsB := maker()
	ds.Hash = dsH
	ds.BatchHash = dsB
	ssH, ssB := maker()
	ss.Hash = ssH
	ss.BatchHash = ssB
	data := generateDataExt(dataSize)
	encrypted, _ := itb.Encrypt512(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt512(ns, ds, ss, encrypted)
	}
}

// --- BLAKE2b-256 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleBLAKE2b256_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE2b256_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE2b256_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 64<<20)
}
func BenchmarkExtSingleBLAKE2b256_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE2b256_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE2b256_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 512, 64<<20)
}

// --- BLAKE2b-512 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleBLAKE2b512_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE2b512_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE2b512_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 64<<20)
}
func BenchmarkExtSingleBLAKE2b512_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE2b512_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE2b512_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 512, 64<<20)
}

// --- BLAKE2b-256 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleBLAKE2b256_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE2b256_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE2b256_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleBLAKE2b256_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE2b256_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE2b256_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 1024, 64<<20)
}

// --- BLAKE2b-512 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleBLAKE2b512_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE2b512_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE2b512_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleBLAKE2b512_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE2b512_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE2b512_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 1024, 64<<20)
}

// --- BLAKE2b-256 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleBLAKE2b256_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE2b256_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE2b256_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleBLAKE2b256_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE2b256_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE2b256_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2bHash256PairExt, 2048, 64<<20)
}

// --- BLAKE2b-512 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleBLAKE2b512_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE2b512_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE2b512_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleBLAKE2b512_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE2b512_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE2b512_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeBlake2bHash512PairExt, 2048, 64<<20)
}

// makeBlake2sHash256PairExt returns a fresh BLAKE2s-256 (single, batched)
// pair routed through hashes.BLAKE2s256Pair — which on amd64 + AVX-512
// dispatches the batched arm to the ZMM-batched chain-absorb kernels in
// hashes/internal/blake2sasm. Same shape as makeBlake2bHash256PairExt;
// the fixed key is generated fresh on every call and shared by both arms.
func makeBlake2sHash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.BLAKE2s256Pair()
	return h, b
}

// --- BLAKE2s-256 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleBLAKE2s_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE2s_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE2s_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 64<<20)
}
func BenchmarkExtSingleBLAKE2s_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE2s_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE2s_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 512, 64<<20)
}

// --- BLAKE2s-256 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleBLAKE2s_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE2s_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE2s_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleBLAKE2s_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE2s_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE2s_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 1024, 64<<20)
}

// --- BLAKE2s-256 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleBLAKE2s_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE2s_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE2s_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleBLAKE2s_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE2s_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE2s_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake2sHash256PairExt, 2048, 64<<20)
}

// makeBlake3Hash256PairExt returns a fresh BLAKE3-256 (single, batched)
// pair routed through hashes.BLAKE3256Pair — which on amd64 + AVX-512
// dispatches the batched arm to the ZMM-batched chain-absorb kernels in
// hashes/internal/blake3asm. Same shape as makeBlake2{b,s}Hash256PairExt;
// the BLAKE3 keyed-hash key is generated fresh on every call and shared
// by both arms.
func makeBlake3Hash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.BLAKE3256Pair()
	return h, b
}

// --- BLAKE3-256 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleBLAKE3_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE3_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE3_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 64<<20)
}
func BenchmarkExtSingleBLAKE3_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleBLAKE3_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleBLAKE3_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 512, 64<<20)
}

// --- BLAKE3-256 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleBLAKE3_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE3_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE3_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleBLAKE3_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleBLAKE3_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleBLAKE3_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 1024, 64<<20)
}

// --- BLAKE3-256 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleBLAKE3_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE3_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE3_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleBLAKE3_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleBLAKE3_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleBLAKE3_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeBlake3Hash256PairExt, 2048, 64<<20)
}

// makeChaCha20Hash256PairExt returns a fresh ChaCha20-256 (single, batched)
// pair routed through hashes.ChaCha20256Pair — which on amd64 + AVX-512
// dispatches the batched arm to the ZMM-batched chain-absorb kernels in
// hashes/internal/chacha20asm. Same shape as makeBlake3Hash256PairExt;
// the ChaCha20 fixed key is generated fresh on every call and shared
// by both arms.
func makeChaCha20Hash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.ChaCha20256Pair()
	return h, b
}

// --- ChaCha20-256 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleChaCha20_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleChaCha20_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleChaCha20_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 64<<20)
}
func BenchmarkExtSingleChaCha20_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleChaCha20_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleChaCha20_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 512, 64<<20)
}

// --- ChaCha20-256 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleChaCha20_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleChaCha20_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleChaCha20_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleChaCha20_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleChaCha20_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleChaCha20_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 1024, 64<<20)
}

// --- ChaCha20-256 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleChaCha20_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleChaCha20_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleChaCha20_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleChaCha20_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleChaCha20_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleChaCha20_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeChaCha20Hash256PairExt, 2048, 64<<20)
}

// makeAESCMACHash128PairExt returns a fresh AES-CMAC-128 (single, batched)
// pair routed through hashes.AESCMACPair — which on amd64 + VAES + AVX-512
// dispatches the batched arm to the ZMM-batched chain-absorb kernels in
// hashes/internal/aescmacasm. The fixed 16-byte AES key is generated
// fresh on every call; both arms share that key, and the AES round-key
// schedule is pre-expanded once at Pair-factory time.
func makeAESCMACHash128PairExt() (itb.HashFunc128, itb.BatchHashFunc128) {
	h, b, _ := hashes.AESCMACPair()
	return h, b
}

// --- AES-CMAC-128 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleAESCMAC_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 1<<20)
}
func BenchmarkExtSingleAESCMAC_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 16<<20)
}
func BenchmarkExtSingleAESCMAC_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 64<<20)
}
func BenchmarkExtSingleAESCMAC_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 1<<20)
}
func BenchmarkExtSingleAESCMAC_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 16<<20)
}
func BenchmarkExtSingleAESCMAC_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 512, 64<<20)
}

// --- AES-CMAC-128 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleAESCMAC_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleAESCMAC_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleAESCMAC_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleAESCMAC_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleAESCMAC_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleAESCMAC_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 1024, 64<<20)
}

// --- AES-CMAC-128 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleAESCMAC_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleAESCMAC_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleAESCMAC_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleAESCMAC_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleAESCMAC_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleAESCMAC_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeAESCMACHash128PairExt, 2048, 64<<20)
}

// makeSipHash24Hash128PairExt returns a fresh SipHash-2-4-128 (single,
// batched) pair routed through hashes.SipHash24Pair — which on amd64
// + AVX-512 dispatches the batched arm to the ZMM-batched chain-
// absorb kernels in hashes/internal/siphashasm. SipHash has no
// fixed key — the per-call (seed0, seed1) pair is the entire SipHash
// key — so unlike makeAESCMACHash128PairExt no key generation
// happens here.
func makeSipHash24Hash128PairExt() (itb.HashFunc128, itb.BatchHashFunc128) {
	h, b := hashes.SipHash24Pair()
	return h, b
}

// --- SipHash-2-4-128 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleSipHash24_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 1<<20)
}
func BenchmarkExtSingleSipHash24_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 16<<20)
}
func BenchmarkExtSingleSipHash24_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 64<<20)
}
func BenchmarkExtSingleSipHash24_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 1<<20)
}
func BenchmarkExtSingleSipHash24_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 16<<20)
}
func BenchmarkExtSingleSipHash24_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 512, 64<<20)
}

// --- SipHash-2-4-128 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleSipHash24_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleSipHash24_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleSipHash24_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleSipHash24_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleSipHash24_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleSipHash24_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 1024, 64<<20)
}

// --- SipHash-2-4-128 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleSipHash24_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleSipHash24_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleSipHash24_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleSipHash24_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleSipHash24_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleSipHash24_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt128CachedBatchedExt(b, makeSipHash24Hash128PairExt, 2048, 64<<20)
}

// makeAreion256Hash256PairExt returns a fresh Areion-SoEM-256 (single,
// batched) pair routed through hashes.Areion256Pair — which on amd64
// + VAES + AVX-512 dispatches the batched arm to the fused chain-
// absorb VAES kernels in internal/areionasm. The 32-byte fixed key
// is generated fresh on every call; both arms share that key. AVX-2
// + VAES hosts dispatch to the YMM fallback tier (the only port in
// the registry that ships a per-buf-shape AVX-2 chain-absorb path —
// AES-CMAC and the BLAKE / ChaCha20 ports omit the YMM tier as the
// code-mass / uplift ratio does not justify it elsewhere).
func makeAreion256Hash256PairExt() (itb.HashFunc256, itb.BatchHashFunc256) {
	h, b, _ := hashes.Areion256Pair()
	return h, b
}

// makeAreion512Hash512PairExt is the 512-bit counterpart.
func makeAreion512Hash512PairExt() (itb.HashFunc512, itb.BatchHashFunc512) {
	h, b, _ := hashes.Areion512Pair()
	return h, b
}

// --- Areion-SoEM-256 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleAreion256_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleAreion256_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleAreion256_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 64<<20)
}
func BenchmarkExtSingleAreion256_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 1<<20)
}
func BenchmarkExtSingleAreion256_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 16<<20)
}
func BenchmarkExtSingleAreion256_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 512, 64<<20)
}

// --- Areion-SoEM-512 Pair benches: 512-bit ITB width ---

func BenchmarkExtSingleAreion512_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 1<<20)
}
func BenchmarkExtSingleAreion512_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 16<<20)
}
func BenchmarkExtSingleAreion512_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 64<<20)
}
func BenchmarkExtSingleAreion512_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 1<<20)
}
func BenchmarkExtSingleAreion512_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 16<<20)
}
func BenchmarkExtSingleAreion512_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 512, 64<<20)
}

// --- Areion-SoEM-256 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleAreion256_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleAreion256_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleAreion256_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleAreion256_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleAreion256_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleAreion256_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 1024, 64<<20)
}

// --- Areion-SoEM-512 Pair benches: 1024-bit ITB width ---

func BenchmarkExtSingleAreion512_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleAreion512_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleAreion512_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 64<<20)
}
func BenchmarkExtSingleAreion512_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 1<<20)
}
func BenchmarkExtSingleAreion512_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 16<<20)
}
func BenchmarkExtSingleAreion512_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 1024, 64<<20)
}

// --- Areion-SoEM-256 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleAreion256_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleAreion256_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleAreion256_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleAreion256_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleAreion256_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleAreion256_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt256CachedBatchedExt(b, makeAreion256Hash256PairExt, 2048, 64<<20)
}

// --- Areion-SoEM-512 Pair benches: 2048-bit ITB width ---

func BenchmarkExtSingleAreion512_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleAreion512_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleAreion512_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 64<<20)
}
func BenchmarkExtSingleAreion512_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 1<<20)
}
func BenchmarkExtSingleAreion512_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 16<<20)
}
func BenchmarkExtSingleAreion512_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt512CachedBatchedExt(b, makeAreion512Hash512PairExt, 2048, 64<<20)
}
