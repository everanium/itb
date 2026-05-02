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
	"bytes"
	"crypto/rand"
	"errors"
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

// --- AttachLockSeed coverage (BLAKE3 256-bit) ---
//
// The four AttachLockSeed-related symbols (ErrLockSeedSelfAttach,
// ErrLockSeedComponentAliasing, ErrLockSeedAfterEncrypt, and the
// AttachLockSeed / AttachedLockSeed methods on Seed{128,256,512})
// are exercised through the BLAKE3 256-bit primitive only — the
// safeguard checks and the attach-routed bit-permutation derivation
// are width-symmetric, so a single primitive at a single width is
// enough to catch shape regressions; the per-primitive bench
// surface and the easy-package matrix tests cover the throughput
// and primitive-coverage dimensions separately.
//
// The RoundTrip tests engage SetLockSoup(1) (which also coerces
// SetBitSoup(1) per the global setter behaviour) so the
// bit-permutation overlay is actually consumed by the encrypt /
// decrypt pipeline; without the overlay the AttachedLockSeed
// fallback in buildLockPRF{N} / buildPermutePRF{N} would produce
// observable output that is bit-identical to the no-attach path
// and the tests could not distinguish the attach-routed pipeline
// from a no-op.

// makeBlake3SeedAttachExt returns one BLAKE3-keyed *itb.Seed256 of
// the requested key_bits with both the single and batched arms
// wired. Each call generates a fresh BLAKE3 fixed key; the seed's
// Components are CSPRNG-generated by NewSeed256.
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

// withLockSoupAttachExt enables SetLockSoup(1) for the duration of
// the test (and consequently SetBitSoup(1) per the global setter
// coupling), restoring both flags via t.Cleanup. The bit-
// permutation overlay must be on for AttachLockSeed to have an
// observable effect on the wire output.
func withLockSoupAttachExt(t *testing.T) {
	t.Helper()
	prevBS := itb.GetBitSoup()
	prevLS := itb.GetLockSoup()
	itb.SetLockSoup(1)
	t.Cleanup(func() {
		itb.SetBitSoup(prevBS)
		itb.SetLockSoup(prevLS)
	})
}

// TestAttachLockSeedRoundtripSingle256 verifies that Single Ouroboros
// Encrypt / Decrypt round-trip succeeds with a dedicated lockSeed
// attached to the noiseSeed. SetLockSoup(1) is on so the bit-
// permutation overlay actually consumes the attached seed via
// buildPermutePRF256.
func TestAttachLockSeedRoundtripSingle256(t *testing.T) {
	withLockSoupAttachExt(t)

	ns := makeBlake3SeedAttachExt(t, 1024)
	ds := makeBlake3SeedAttachExt(t, 1024)
	ss := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ns.AttachLockSeed(ls)

	plaintext := generateDataExt(1024)
	ct, err := itb.Encrypt256(ns, ds, ss, plaintext)
	if err != nil {
		t.Fatalf("Encrypt256: %v", err)
	}
	pt, err := itb.Decrypt256(ns, ds, ss, ct)
	if err != nil {
		t.Fatalf("Decrypt256: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("AttachLockSeed Single roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestAttachLockSeedRoundtripTriple256 verifies that Triple Ouroboros
// Encrypt3x / Decrypt3x round-trip succeeds with a dedicated
// lockSeed attached to the sole noiseSeed. SetLockSoup(1) engages
// the bit-permutation overlay via buildLockPRF256.
func TestAttachLockSeedRoundtripTriple256(t *testing.T) {
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
		t.Errorf("AttachLockSeed Triple roundtrip mismatch: got %d bytes, want %d",
			len(pt), len(plaintext))
	}
}

// TestAttachLockSeedSelfAttachPanic verifies the self-attach
// safeguard — passing the receiver itself as the lockSeed argument
// panics with [itb.ErrLockSeedSelfAttach] rather than silently
// degrading to a no-op self-derivation.
func TestAttachLockSeedSelfAttachPanic(t *testing.T) {
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

// TestAttachLockSeedComponentAliasingPanic verifies the component-
// aliasing safeguard — when two distinct *Seed256 values share the
// same Components backing array, AttachLockSeed panics with
// [itb.ErrLockSeedComponentAliasing] rather than silently accepting
// the duplicated entropy source.
func TestAttachLockSeedComponentAliasingPanic(t *testing.T) {
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

// TestAttachLockSeedAfterEncryptPanic verifies the post-Encrypt
// safeguard — after the noiseSeed has been used in a successful
// Encrypt call, any subsequent AttachLockSeed (even idempotent or
// to a different ls) panics with [itb.ErrLockSeedAfterEncrypt] so
// the bit-permutation derivation path cannot change mid-session
// in a way that would break decryptability of pre-switch
// ciphertext.
func TestAttachLockSeedAfterEncryptPanic(t *testing.T) {
	withLockSoupAttachExt(t)

	ns := makeBlake3SeedAttachExt(t, 1024)
	ds := makeBlake3SeedAttachExt(t, 1024)
	ss := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ns.AttachLockSeed(ls) // pre-Encrypt attach is fine

	plaintext := generateDataExt(64)
	if _, err := itb.Encrypt256(ns, ds, ss, plaintext); err != nil {
		t.Fatalf("pre-panic Encrypt256: %v", err)
	}

	ls2 := makeBlake3SeedAttachExt(t, 1024)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("AttachLockSeed(ls2) after Encrypt: expected panic, got none")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, itb.ErrLockSeedAfterEncrypt) {
			t.Errorf("AttachLockSeed(ls2) after Encrypt: panic %v, want %v",
				r, itb.ErrLockSeedAfterEncrypt)
		}
	}()
	ns.AttachLockSeed(ls2)
}

// BenchmarkExtSingleBLAKE3RoundTripAttachedLockSeed measures the legacy
// itb root Encrypt + Decrypt round-trip throughput and per-
// iteration allocation footprint when a dedicated lockSeed has
// been wired into the noiseSeed via [itb.Seed256.AttachLockSeed].
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
//     generated for each of the four seeds (noise / data / start
//     / lockSeed) so all four seeds carry independent keying
//     material.
//   - Single Ouroboros (3 noise / data / start seeds) plus a 4th
//     dedicated lockSeed attached via ns.AttachLockSeed(ls).
//   - SetLockSoup(1) engaged so the bit-permutation overlay
//     actually consumes the attached lockSeed; otherwise the
//     attach call is a no-op and the bench measures plain
//     Encrypt + Decrypt without exercising the LockSeed path.
//
// Counterpart of BenchmarkBLAKE3RoundTripAttachedLockSeed in
// itb_test.go — same shape, same bench loop, the only difference
// is the BLAKE3 closure source: this file uses the
// github.com/everanium/itb/hashes registry factory (which
// dispatches the batched arm via the asm kernels), the in-package
// counterpart uses the native makeBlake3Hash256 test helper that
// wires only the single arm. The two benchmarks taken together
// provide a serial-vs-batched comparison for the AttachedLockSeed
// path on the legacy itb root API.
//
// Run as:
//
//	go test -bench=BenchmarkExtBLAKE3RoundTripAttachedLockSeed \
//	    -benchmem -run=^$ -count=3 -benchtime=3x
//
// to dump per-iteration ns/op + B/op + allocs/op for inspection.
func BenchmarkExtSingleBLAKE3RoundTripAttachedLockSeed(b *testing.B) {
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

	hD, bD, _ := hashes.BLAKE3256Pair()
	ds, err := itb.NewSeed256(bits, hD)
	if err != nil {
		b.Fatalf("NewSeed256(dataSeed): %v", err)
	}
	ds.BatchHash = bD

	hS, bS, _ := hashes.BLAKE3256Pair()
	ss, err := itb.NewSeed256(bits, hS)
	if err != nil {
		b.Fatalf("NewSeed256(startSeed): %v", err)
	}
	ss.BatchHash = bS

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
		encrypted, err := itb.Encrypt256(ns, ds, ss, data)
		if err != nil {
			b.Fatalf("Encrypt256: %v", err)
		}
		if _, err := itb.Decrypt256(ns, ds, ss, encrypted); err != nil {
			b.Fatalf("Decrypt256: %v", err)
		}
	}
}

// TestExtSingleAttachLockSeedOverlayOffPanic — external-package
// counterpart of [TestSingleAttachLockSeedOverlayOffPanic] in
// itb_test.go. Same regression-pinning role, exercised through the
// public itb.Encrypt256 entry point from outside the itb package so
// the guard is verified at the visible API surface a binding consumer
// would hit.
//
// Cleanup forces both flags off before the encrypt and restores the
// caller's prior state afterwards so the test is hermetic regardless
// of the global flag state on entry — important here because earlier
// AttachLockSeed tests in this file install [withLockSoupAttachExt]
// to flip LockSoup on.
func TestExtSingleAttachLockSeedOverlayOffPanic(t *testing.T) {
	prevBS := itb.GetBitSoup()
	prevLS := itb.GetLockSoup()
	itb.SetBitSoup(0)
	itb.SetLockSoup(0)
	t.Cleanup(func() {
		itb.SetBitSoup(prevBS)
		itb.SetLockSoup(prevLS)
	})

	ns := makeBlake3SeedAttachExt(t, 1024)
	ds := makeBlake3SeedAttachExt(t, 1024)
	ss := makeBlake3SeedAttachExt(t, 1024)
	ls := makeBlake3SeedAttachExt(t, 1024)
	ns.AttachLockSeed(ls)

	plaintext := generateDataExt(64)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("itb.Encrypt256 with attached lockSeed and overlay off: expected panic, got none")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, itb.ErrLockSeedOverlayOff) {
			t.Errorf("itb.Encrypt256: panic %v, want %v", r, itb.ErrLockSeedOverlayOff)
		}
	}()
	_, _ = itb.Encrypt256(ns, ds, ss, plaintext)
}
