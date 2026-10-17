package aescmacasm

import (
	"runtime"

	"github.com/everanium/areion"
)

// ExpandKeyAES128 produces the 176-byte AES-128 forward round-key
// schedule (11 × 16-byte round keys K0..K10) from a caller-supplied
// 16-byte master key, following FIPS 197 §5.2 verbatim via
// [areion.ExpandKey128].
//
// Used by NewSchedule: expands the 16-byte fixed key into the
// 176-byte schedule in Schedule.roundKeys consumed by all assembly
// tiers (AVX-512, VAES+AVX2, VEX, AES-NI) and references. In SIMD kernels,
// the round keys are broadcast to lanes or loaded into registers at
// kernel entry; the actual VAESENC / AESENC per-pixel work consumes
// the round keys without re-touching the schedule buffer.
//
// The expansion is bit-identical to the round keys produced
// internally by crypto/aes.NewCipher; the parity test in
// aescmacasm_test.go cross-checks the kernel output against a
// scalar reference that calls cipher.Block.Encrypt, indirectly
// validating the schedule.
func ExpandKeyAES128(key [16]byte) [176]byte {
	var rk [11][16]byte
	areion.ExpandKey128(&key, &rk)
	var out [176]byte
	for r := 0; r < 11; r++ {
		copy(out[r*16:(r+1)*16], rk[r][:])
	}
	clear(rk[:])
	runtime.KeepAlive(&rk)
	clear(key[:])
	runtime.KeepAlive(&key)
	return out
}
