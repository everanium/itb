//go:build amd64 && !purego && !noitbasm

package areionasm

// This file declares the YMM VAES (no AVX-512) fused chained-absorb
// kernels for Areion-SoEM-512. They are the batched path for hosts that
// expose VAES on YMM but lack AVX-512 (HasVAESAVX2Batched == true).
// Each kernel processes the four pixel lanes in two passes of two lanes;
// within a pass the SoEM state1 / state2 permutations expose four
// independent VAES chains (each Areion512 round's a-block and c-block
// sub-chains across both SoEM halves), saturating a single VAES issue
// port. Output is bit-exact with the ZMM Areion512ChainAbsorb*x4
// kernels, the XMM AES-NI Areion512ChainAbsorb*x4AesNi kernels, and the
// Go single closure; verified by the tests in
// areionasm_chain512_vaesavx2_amd64_test.go.

// Areion512ChainAbsorb13x4VaesAvx2 — 13-byte Interlocked Barrier PRF
// fill shape (single SoEM round).
//
//go:noescape
func Areion512ChainAbsorb13x4VaesAvx2(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb20x4VaesAvx2 — 20-byte 128-bit nonce shape (single
// SoEM round).
//
//go:noescape
func Areion512ChainAbsorb20x4VaesAvx2(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb36x4VaesAvx2 — 36-byte 256-bit nonce shape (single
// SoEM round).
//
//go:noescape
func Areion512ChainAbsorb36x4VaesAvx2(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb68x4VaesAvx2 — 68-byte 512-bit nonce shape (two
// SoEM rounds).
//
//go:noescape
func Areion512ChainAbsorb68x4VaesAvx2(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)
