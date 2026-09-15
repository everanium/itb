// Triple Ouroboros (8-seed) integration benchmarks for the aesitb128
// primitive, driving the Encrypt3x128Cfg / Decrypt3x128Cfg entry points
// in the same shape as the other primitives' cells in itb3_ext_test.go
// (BenchmarkExtTriple<Primitive>_<KeyBits>bit_<Direction>_<Size>MB), so
// the BENCH3.md mask `BenchmarkExtTriple.*_(1MB|16MB|64MB)$` picks the
// cells up alongside every other registry primitive.
//
// The generic bench{Encrypt,Decrypt}3x128CachedBatchedExt drivers wire
// only the (Hash, BatchHash) pair per seed. The shipping aesitb128 path
// additionally carries the fused ChainHash cascade hooks (FusedChain /
// BatchFusedChain) that the triple package installs through
// hashes.NewSeed128 at Init time; without them the Low-Level entry
// points fall back to the sequential per-round cascade. The drivers
// below therefore build each of the eight seeds through the same
// constructor, so the cells measure the path the Triple pipeline runs.
package itb_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// newAESITB128SeedExt returns one independently-keyed aesitb128 seed at
// the given ITB width with the single, batched, fused-cascade and
// batch-16 interlock fill hooks attached — the same wiring the triple
// package performs per slot.
func newAESITB128SeedExt(b *testing.B, bits int) *itb.Seed128 {
	b.Helper()
	s, _, err := hashes.NewSeed128(hashes.CipherAESITB128, bits)
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// makeEightAESITB128SeedsExt builds the eight-seed constellation
// (noise + lockSeed + 3 data + 3 start), each slot on its own fixed key.
func makeEightAESITB128SeedsExt(b *testing.B, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *itb.Seed128) {
	b.Helper()
	ns = newAESITB128SeedExt(b, bits)
	ls = newAESITB128SeedExt(b, bits)
	ds1 = newAESITB128SeedExt(b, bits)
	ds2 = newAESITB128SeedExt(b, bits)
	ds3 = newAESITB128SeedExt(b, bits)
	ss1 = newAESITB128SeedExt(b, bits)
	ss2 = newAESITB128SeedExt(b, bits)
	ss3 = newAESITB128SeedExt(b, bits)
	return
}

// benchEncrypt3x128AESITBExt mirrors benchEncrypt3x128CachedBatchedExt
// with the fused-cascade hooks attached on every seed.
func benchEncrypt3x128AESITBExt(b *testing.B, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightAESITB128SeedsExt(b, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

// benchDecrypt3x128AESITBExt mirrors benchDecrypt3x128CachedBatchedExt
// with the fused-cascade hooks attached on every seed.
func benchDecrypt3x128AESITBExt(b *testing.B, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightAESITB128SeedsExt(b, bits)
	data := generateDataExt(dataSize)
	cfg := extTripleBenchCfg()
	encrypted, err := itb.Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		b.Fatal(err)
	}
	// Verify the round trip once before timing so a forced dispatch
	// tier that produced garbage cannot report a throughput number.
	if back, err := itb.Decrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted); err != nil {
		b.Fatal(err)
	} else if !bytes.Equal(back, data) {
		b.Fatal("decrypt round trip mismatch")
	}
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = itb.Decrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// --- AES-ITB-128 Triple Pair benches: 512-bit ITB width ---

func BenchmarkExtTripleAESITB128_512bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 512, 1<<20)
}
func BenchmarkExtTripleAESITB128_512bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 512, 16<<20)
}
func BenchmarkExtTripleAESITB128_512bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 512, 64<<20)
}
func BenchmarkExtTripleAESITB128_512bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 512, 1<<20)
}
func BenchmarkExtTripleAESITB128_512bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 512, 16<<20)
}
func BenchmarkExtTripleAESITB128_512bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 512, 64<<20)
}

// --- AES-ITB-128 Triple Pair benches: 1024-bit ITB width ---

func BenchmarkExtTripleAESITB128_1024bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 1024, 1<<20)
}
func BenchmarkExtTripleAESITB128_1024bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 1024, 16<<20)
}
func BenchmarkExtTripleAESITB128_1024bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 1024, 64<<20)
}
func BenchmarkExtTripleAESITB128_1024bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 1024, 1<<20)
}
func BenchmarkExtTripleAESITB128_1024bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 1024, 16<<20)
}
func BenchmarkExtTripleAESITB128_1024bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 1024, 64<<20)
}

// --- AES-ITB-128 Triple Pair benches: 2048-bit ITB width ---

func BenchmarkExtTripleAESITB128_2048bit_Encrypt_1MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 2048, 1<<20)
}
func BenchmarkExtTripleAESITB128_2048bit_Encrypt_16MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 2048, 16<<20)
}
func BenchmarkExtTripleAESITB128_2048bit_Encrypt_64MB(b *testing.B) {
	benchEncrypt3x128AESITBExt(b, 2048, 64<<20)
}
func BenchmarkExtTripleAESITB128_2048bit_Decrypt_1MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 2048, 1<<20)
}
func BenchmarkExtTripleAESITB128_2048bit_Decrypt_16MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 2048, 16<<20)
}
func BenchmarkExtTripleAESITB128_2048bit_Decrypt_64MB(b *testing.B) {
	benchDecrypt3x128AESITBExt(b, 2048, 64<<20)
}
