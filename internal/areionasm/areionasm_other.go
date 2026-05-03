//go:build !amd64 || purego || noitbasm

// Stub package on platforms where the AVX-512 + VAES assembly path
// does not apply. The parent `itb` package always uses its portable
// Go fallback in this case; nothing here is exercised.
package areionasm

import "github.com/jedisct1/go-aes"

var (
	// AreionRC4x is unused on non-amd64 builds; declared for symbol
	// consistency with the amd64 build only.
	AreionRC4x [15 * 64]byte
	// HasVAESAVX512 is always false on non-amd64 builds.
	HasVAESAVX512 = false
	// HasVAESAVX2NoAVX512 is always false on non-amd64 builds.
	HasVAESAVX2NoAVX512 = false
)

// Areion256Permutex4 should never be called on non-amd64 builds — the
// parent package's dispatch routes to the portable Go fallback when
// HasVAESAVX512 is false. Kept as a callable stub so the import
// resolves cleanly.
func Areion256Permutex4(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permutex4 unavailable on non-amd64 build")
}

func Areion256Permutex4Avx2(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permutex4Avx2 unavailable on non-amd64 build")
}

func Areion512Permutex4Avx2(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permutex4Avx2 unavailable on non-amd64 build")
}

func Areion512Permutex4(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permutex4 unavailable on non-amd64 build")
}
