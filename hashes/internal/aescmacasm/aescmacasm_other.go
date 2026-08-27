//go:build !amd64 || purego || noitbasm

// Stub package on platforms where the AVX-512 + VAES chain-absorb
// kernels do not apply. The parent hashes/ package falls back to
// the AESCMACWithKey closure (itself crypto/aes-backed, which uses
// AES-NI on hosts that expose the AES round instructions) in this
// case; nothing here is exercised.
package aescmacasm

// HasVAESAVX512 is always false on non-amd64 / purego builds.
var HasVAESAVX512 = false

// HasAESNIBatched is always false on non-amd64 / purego builds — the
// XMM AES-NI chain-absorb kernels are amd64-only. The parent package
// falls back to the scalar batched reference in this case.
var HasAESNIBatched = false
