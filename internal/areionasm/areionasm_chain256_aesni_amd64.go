//go:build amd64 && !purego && !noitbasm

package areionasm

// This file declares the XMM AES-NI (no VAES) fused chained-absorb
// kernels for Areion-SoEM-256. They are the fallback batched path for
// AES-NI-only hosts (HasAESNIBatched == true): Cascade Lake Xeon Gold,
// AMD Zen 3, and every AVX2-no-VAES cloud VM. Each kernel processes the
// four pixel lanes in two passes of two lanes; within a pass both
// lanes' SoEM state1 / state2 permutations run interleaved as four
// independent 128-bit AES dependency chains (playbook §8 ILP restore),
// hiding the AESENC latency on a single AES issue port. Output is
// bit-exact with the VAES Areion256ChainAbsorb*x4 kernels and the Go
// single closure; verified by the parity / bit-sensitivity tests in
// areionasm_chain256_aesni_amd64_test.go.

// Areion256ChainAbsorb13x4AesNi — 13-byte Interlocked Barrier PRF fill
// shape (single SoEM round).
//
//go:noescape
func Areion256ChainAbsorb13x4AesNi(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb20x4AesNi — 20-byte 128-bit nonce shape (single
// SoEM round).
//
//go:noescape
func Areion256ChainAbsorb20x4AesNi(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb36x4AesNi — 36-byte 256-bit nonce shape (two
// SoEM rounds).
//
//go:noescape
func Areion256ChainAbsorb36x4AesNi(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb68x4AesNi — 68-byte 512-bit nonce shape (three
// SoEM rounds).
//
//go:noescape
func Areion256ChainAbsorb68x4AesNi(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)
