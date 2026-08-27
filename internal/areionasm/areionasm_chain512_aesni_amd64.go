//go:build amd64 && !purego && !noitbasm

package areionasm

// This file declares the XMM AES-NI (no VAES) fused chained-absorb
// kernels for Areion-SoEM-512. They are the fallback batched path for
// AES-NI-only hosts (HasAESNIBatched == true). Each kernel processes
// one pixel lane per pass (four passes); Areion-SoEM-512 exposes four
// independent 128-bit AES chains within a single lane (state1 / state2
// × the round's a-block / c-block sub-chains), enough to hide the
// AESENC latency on a single AES issue port (playbook §8). Output is
// bit-exact with the VAES Areion512ChainAbsorb*x4 kernels and the Go
// single closure; verified by the tests in
// areionasm_chain512_aesni_amd64_test.go.

// Areion512ChainAbsorb13x4AesNi — 13-byte Interlocked Barrier PRF fill
// shape (single SoEM round).
//
//go:noescape
func Areion512ChainAbsorb13x4AesNi(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb20x4AesNi — 20-byte 128-bit nonce shape (single
// SoEM round).
//
//go:noescape
func Areion512ChainAbsorb20x4AesNi(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb36x4AesNi — 36-byte 256-bit nonce shape (single
// SoEM round).
//
//go:noescape
func Areion512ChainAbsorb36x4AesNi(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb68x4AesNi — 68-byte 512-bit nonce shape (two
// SoEM rounds).
//
//go:noescape
func Areion512ChainAbsorb68x4AesNi(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)
