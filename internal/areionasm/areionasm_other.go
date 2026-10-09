//go:build (!amd64 && !arm64) || purego || noitbasm

// Stub package on platforms where the AVX-512 + VAES assembly path
// does not apply (and the arm64 ARM Crypto Extension batched path
// is also unavailable or disabled by the purego / noitbasm tag).
// The parent `itb` package always uses its portable Go fallback in
// this case; nothing here is exercised.
package areionasm

import "github.com/everanium/itb/third/goaes"

var (
	// AreionRC4x / AreionRC4x2 are unused on these builds; declared for
	// symbol consistency with the amd64 build only.
	AreionRC4x  [15 * 64]byte
	AreionRC4x2 [15 * 64]byte
	// HasVAESAVX512 is always false on these builds.
	HasVAESAVX512 = false
	// HasVAESAVX2NoAVX512 is always false on these builds.
	HasVAESAVX2NoAVX512 = false
	// HasAESNIBatched is always false on these builds.
	HasAESNIBatched = false
	// HasARMAESBatched is always false on these builds (the arm64
	// production path defines this in areionasm_arm64.go).
	HasARMAESBatched = false
)

// Areion256Permutex4 should never be called on these builds — the
// parent package's dispatch routes to the portable Go fallback when
// HasVAESAVX512 is false. Kept as a callable stub so the import
// resolves cleanly.
func Areion256Permutex4(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permutex4 unavailable on this build")
}

func Areion256Permute2x4(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permute2x4 unavailable on this build")
}

func Areion256Permutex4Avx2(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permutex4Avx2 unavailable on this build")
}

func Areion256Permute2x4Avx2(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permute2x4Avx2 unavailable on this build")
}

func Areion256Permutex4AesNi(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permutex4AesNi unavailable on this build")
}

func Areion256Permute2x4AesNi(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permute2x4AesNi unavailable on this build")
}

func Areion512Permutex4Avx2(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permutex4Avx2 unavailable on this build")
}

func Areion512Permute2x4Avx2(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permute2x4Avx2 unavailable on this build")
}

func Areion512Permutex4AesNi(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permutex4AesNi unavailable on this build")
}

func Areion512Permute2x4AesNi(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permute2x4AesNi unavailable on this build")
}

func Areion512Permutex4(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permutex4 unavailable on this build")
}

func Areion512Permute2x4(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permute2x4 unavailable on this build")
}
