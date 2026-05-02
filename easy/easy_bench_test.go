// easy_bench_test.go hosts the throughput benchmarks for the
// [easy.Encryptor] surface. Coverage mirrors itb_ext_test.go's
// per-primitive cohort — every PRF-grade primitive at widths 512 /
// 1024 / 2048 bits, both Encrypt and Decrypt, at 1 MiB / 16 MiB /
// 64 MiB payloads — but produced through the high-level
// easy.New(...) constructor instead of the manual
// hash-factory + NewSeed{N} ceremony.
//
// Authenticated-encryption and streaming benchmarks are
// intentionally omitted from this file — the per-pixel hash
// machinery is the dominant cost in those flows too, and
// replicating them here would just duplicate numbers derivable
// from the plain Encrypt / Decrypt cohort.
//
// Function-naming convention parallels itb_ext_test.go: helpers
// carry the "Easy" suffix (benchEasyEncrypt, benchEasyDecrypt),
// exported benchmarks carry the "BenchmarkEasySingle" prefix —
// "Easy" denoting the easy sub-package cohort, "Single" the
// Single Ouroboros mode the plain Encrypt / Decrypt benchmarks
// exercise.
package easy_test

import (
	"testing"

	"github.com/everanium/itb/easy"
)

// benchEasyEncrypt runs N rounds of [easy.Encryptor.Encrypt] on a
// dataSize-byte plaintext, reporting bytes-per-second via
// b.SetBytes. The encryptor is constructed with default
// configuration so the measurement reflects the baseline shipped
// throughput; the loop runs after b.ResetTimer so the constructor
// + key-material generation cost is excluded from the measurement.
func benchEasyEncrypt(b *testing.B, primitive string, keyBits, dataSize int) {
	enc := easy.New(primitive, keyBits)
	data := generateDataEasy(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encrypt(data)
	}
}

// benchEasyDecrypt runs N rounds of [easy.Encryptor.Decrypt] on a
// pre-encrypted ciphertext, reporting bytes-per-second. The
// encrypt step runs once before b.ResetTimer; the decrypt loop
// runs after.
func benchEasyDecrypt(b *testing.B, primitive string, keyBits, dataSize int) {
	enc := easy.New(primitive, keyBits)
	data := generateDataEasy(dataSize)
	encrypted, _ := enc.Encrypt(data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Decrypt(encrypted)
	}
}

// --- Areion-SoEM-256 benches: 512-bit ITB width ---

func BenchmarkEasySingleAreion256_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 512, 1<<20)
}
func BenchmarkEasySingleAreion256_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 512, 16<<20)
}
func BenchmarkEasySingleAreion256_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 512, 64<<20)
}
func BenchmarkEasySingleAreion256_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 512, 1<<20)
}
func BenchmarkEasySingleAreion256_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 512, 16<<20)
}
func BenchmarkEasySingleAreion256_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 512, 64<<20)
}

// --- Areion-SoEM-256 benches: 1024-bit ITB width ---

func BenchmarkEasySingleAreion256_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 1024, 1<<20)
}
func BenchmarkEasySingleAreion256_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 1024, 16<<20)
}
func BenchmarkEasySingleAreion256_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 1024, 64<<20)
}
func BenchmarkEasySingleAreion256_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 1024, 1<<20)
}
func BenchmarkEasySingleAreion256_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 1024, 16<<20)
}
func BenchmarkEasySingleAreion256_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 1024, 64<<20)
}

// --- Areion-SoEM-256 benches: 2048-bit ITB width ---

func BenchmarkEasySingleAreion256_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 2048, 1<<20)
}
func BenchmarkEasySingleAreion256_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 2048, 16<<20)
}
func BenchmarkEasySingleAreion256_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "areion256", 2048, 64<<20)
}
func BenchmarkEasySingleAreion256_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 2048, 1<<20)
}
func BenchmarkEasySingleAreion256_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 2048, 16<<20)
}
func BenchmarkEasySingleAreion256_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "areion256", 2048, 64<<20)
}

// --- Areion-SoEM-512 benches: 512-bit ITB width ---

func BenchmarkEasySingleAreion512_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 512, 1<<20)
}
func BenchmarkEasySingleAreion512_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 512, 16<<20)
}
func BenchmarkEasySingleAreion512_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 512, 64<<20)
}
func BenchmarkEasySingleAreion512_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 512, 1<<20)
}
func BenchmarkEasySingleAreion512_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 512, 16<<20)
}
func BenchmarkEasySingleAreion512_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 512, 64<<20)
}

// --- Areion-SoEM-512 benches: 1024-bit ITB width ---

func BenchmarkEasySingleAreion512_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 1024, 1<<20)
}
func BenchmarkEasySingleAreion512_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 1024, 16<<20)
}
func BenchmarkEasySingleAreion512_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 1024, 64<<20)
}
func BenchmarkEasySingleAreion512_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 1024, 1<<20)
}
func BenchmarkEasySingleAreion512_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 1024, 16<<20)
}
func BenchmarkEasySingleAreion512_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 1024, 64<<20)
}

// --- Areion-SoEM-512 benches: 2048-bit ITB width ---

func BenchmarkEasySingleAreion512_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 2048, 1<<20)
}
func BenchmarkEasySingleAreion512_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 2048, 16<<20)
}
func BenchmarkEasySingleAreion512_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "areion512", 2048, 64<<20)
}
func BenchmarkEasySingleAreion512_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 2048, 1<<20)
}
func BenchmarkEasySingleAreion512_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 2048, 16<<20)
}
func BenchmarkEasySingleAreion512_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "areion512", 2048, 64<<20)
}

// --- BLAKE2b-256 benches: 512-bit ITB width ---

func BenchmarkEasySingleBLAKE2b256_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE2b256_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE2b256_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 512, 64<<20)
}
func BenchmarkEasySingleBLAKE2b256_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE2b256_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE2b256_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 512, 64<<20)
}

// --- BLAKE2b-256 benches: 1024-bit ITB width ---

func BenchmarkEasySingleBLAKE2b256_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE2b256_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE2b256_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 1024, 64<<20)
}
func BenchmarkEasySingleBLAKE2b256_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE2b256_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE2b256_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 1024, 64<<20)
}

// --- BLAKE2b-256 benches: 2048-bit ITB width ---

func BenchmarkEasySingleBLAKE2b256_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE2b256_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE2b256_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b256", 2048, 64<<20)
}
func BenchmarkEasySingleBLAKE2b256_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE2b256_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE2b256_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b256", 2048, 64<<20)
}

// --- BLAKE2b-512 benches: 512-bit ITB width ---

func BenchmarkEasySingleBLAKE2b512_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE2b512_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE2b512_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 512, 64<<20)
}
func BenchmarkEasySingleBLAKE2b512_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE2b512_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE2b512_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 512, 64<<20)
}

// --- BLAKE2b-512 benches: 1024-bit ITB width ---

func BenchmarkEasySingleBLAKE2b512_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE2b512_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE2b512_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 1024, 64<<20)
}
func BenchmarkEasySingleBLAKE2b512_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE2b512_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE2b512_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 1024, 64<<20)
}

// --- BLAKE2b-512 benches: 2048-bit ITB width ---

func BenchmarkEasySingleBLAKE2b512_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE2b512_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE2b512_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2b512", 2048, 64<<20)
}
func BenchmarkEasySingleBLAKE2b512_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE2b512_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE2b512_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2b512", 2048, 64<<20)
}

// --- BLAKE2s benches: 512-bit ITB width ---

func BenchmarkEasySingleBLAKE2s_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE2s_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE2s_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 512, 64<<20)
}
func BenchmarkEasySingleBLAKE2s_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE2s_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE2s_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 512, 64<<20)
}

// --- BLAKE2s benches: 1024-bit ITB width ---

func BenchmarkEasySingleBLAKE2s_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE2s_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE2s_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 1024, 64<<20)
}
func BenchmarkEasySingleBLAKE2s_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE2s_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE2s_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 1024, 64<<20)
}

// --- BLAKE2s benches: 2048-bit ITB width ---

func BenchmarkEasySingleBLAKE2s_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE2s_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE2s_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake2s", 2048, 64<<20)
}
func BenchmarkEasySingleBLAKE2s_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE2s_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE2s_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake2s", 2048, 64<<20)
}

// --- BLAKE3 benches: 512-bit ITB width ---

func BenchmarkEasySingleBLAKE3_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE3_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE3_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 512, 64<<20)
}
func BenchmarkEasySingleBLAKE3_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 512, 1<<20)
}
func BenchmarkEasySingleBLAKE3_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 512, 16<<20)
}
func BenchmarkEasySingleBLAKE3_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 512, 64<<20)
}

// --- BLAKE3 benches: 1024-bit ITB width ---

func BenchmarkEasySingleBLAKE3_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE3_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE3_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 1024, 64<<20)
}
func BenchmarkEasySingleBLAKE3_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 1024, 1<<20)
}
func BenchmarkEasySingleBLAKE3_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 1024, 16<<20)
}
func BenchmarkEasySingleBLAKE3_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 1024, 64<<20)
}

// --- BLAKE3 benches: 2048-bit ITB width ---

func BenchmarkEasySingleBLAKE3_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE3_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE3_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "blake3", 2048, 64<<20)
}
func BenchmarkEasySingleBLAKE3_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 2048, 1<<20)
}
func BenchmarkEasySingleBLAKE3_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 2048, 16<<20)
}
func BenchmarkEasySingleBLAKE3_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "blake3", 2048, 64<<20)
}

// --- ChaCha20 benches: 512-bit ITB width ---

func BenchmarkEasySingleChaCha20_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 512, 1<<20)
}
func BenchmarkEasySingleChaCha20_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 512, 16<<20)
}
func BenchmarkEasySingleChaCha20_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 512, 64<<20)
}
func BenchmarkEasySingleChaCha20_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 512, 1<<20)
}
func BenchmarkEasySingleChaCha20_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 512, 16<<20)
}
func BenchmarkEasySingleChaCha20_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 512, 64<<20)
}

// --- ChaCha20 benches: 1024-bit ITB width ---

func BenchmarkEasySingleChaCha20_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 1024, 1<<20)
}
func BenchmarkEasySingleChaCha20_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 1024, 16<<20)
}
func BenchmarkEasySingleChaCha20_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 1024, 64<<20)
}
func BenchmarkEasySingleChaCha20_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 1024, 1<<20)
}
func BenchmarkEasySingleChaCha20_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 1024, 16<<20)
}
func BenchmarkEasySingleChaCha20_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 1024, 64<<20)
}

// --- ChaCha20 benches: 2048-bit ITB width ---

func BenchmarkEasySingleChaCha20_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 2048, 1<<20)
}
func BenchmarkEasySingleChaCha20_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 2048, 16<<20)
}
func BenchmarkEasySingleChaCha20_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "chacha20", 2048, 64<<20)
}
func BenchmarkEasySingleChaCha20_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 2048, 1<<20)
}
func BenchmarkEasySingleChaCha20_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 2048, 16<<20)
}
func BenchmarkEasySingleChaCha20_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "chacha20", 2048, 64<<20)
}

// --- AES-CMAC benches: 512-bit ITB width ---

func BenchmarkEasySingleAESCMAC_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 512, 1<<20)
}
func BenchmarkEasySingleAESCMAC_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 512, 16<<20)
}
func BenchmarkEasySingleAESCMAC_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 512, 64<<20)
}
func BenchmarkEasySingleAESCMAC_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 512, 1<<20)
}
func BenchmarkEasySingleAESCMAC_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 512, 16<<20)
}
func BenchmarkEasySingleAESCMAC_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 512, 64<<20)
}

// --- AES-CMAC benches: 1024-bit ITB width ---

func BenchmarkEasySingleAESCMAC_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 1024, 1<<20)
}
func BenchmarkEasySingleAESCMAC_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 1024, 16<<20)
}
func BenchmarkEasySingleAESCMAC_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 1024, 64<<20)
}
func BenchmarkEasySingleAESCMAC_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 1024, 1<<20)
}
func BenchmarkEasySingleAESCMAC_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 1024, 16<<20)
}
func BenchmarkEasySingleAESCMAC_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 1024, 64<<20)
}

// --- AES-CMAC benches: 2048-bit ITB width ---

func BenchmarkEasySingleAESCMAC_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 2048, 1<<20)
}
func BenchmarkEasySingleAESCMAC_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 2048, 16<<20)
}
func BenchmarkEasySingleAESCMAC_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "aescmac", 2048, 64<<20)
}
func BenchmarkEasySingleAESCMAC_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 2048, 1<<20)
}
func BenchmarkEasySingleAESCMAC_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 2048, 16<<20)
}
func BenchmarkEasySingleAESCMAC_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "aescmac", 2048, 64<<20)
}

// --- SipHash-2-4 benches: 512-bit ITB width ---

func BenchmarkEasySingleSipHash24_512bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 512, 1<<20)
}
func BenchmarkEasySingleSipHash24_512bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 512, 16<<20)
}
func BenchmarkEasySingleSipHash24_512bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 512, 64<<20)
}
func BenchmarkEasySingleSipHash24_512bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 512, 1<<20)
}
func BenchmarkEasySingleSipHash24_512bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 512, 16<<20)
}
func BenchmarkEasySingleSipHash24_512bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 512, 64<<20)
}

// --- SipHash-2-4 benches: 1024-bit ITB width ---

func BenchmarkEasySingleSipHash24_1024bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 1024, 1<<20)
}
func BenchmarkEasySingleSipHash24_1024bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 1024, 16<<20)
}
func BenchmarkEasySingleSipHash24_1024bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 1024, 64<<20)
}
func BenchmarkEasySingleSipHash24_1024bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 1024, 1<<20)
}
func BenchmarkEasySingleSipHash24_1024bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 1024, 16<<20)
}
func BenchmarkEasySingleSipHash24_1024bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 1024, 64<<20)
}

// --- SipHash-2-4 benches: 2048-bit ITB width ---

func BenchmarkEasySingleSipHash24_2048bit_Encrypt_1MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 2048, 1<<20)
}
func BenchmarkEasySingleSipHash24_2048bit_Encrypt_16MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 2048, 16<<20)
}
func BenchmarkEasySingleSipHash24_2048bit_Encrypt_64MB(b *testing.B) {
	benchEasyEncrypt(b, "siphash24", 2048, 64<<20)
}
func BenchmarkEasySingleSipHash24_2048bit_Decrypt_1MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 2048, 1<<20)
}
func BenchmarkEasySingleSipHash24_2048bit_Decrypt_16MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 2048, 16<<20)
}
func BenchmarkEasySingleSipHash24_2048bit_Decrypt_64MB(b *testing.B) {
	benchEasyDecrypt(b, "siphash24", 2048, 64<<20)
}
