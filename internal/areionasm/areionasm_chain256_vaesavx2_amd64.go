//go:build amd64 && !purego && !noitbasm

package areionasm

// This file declares the YMM VAES (no AVX-512) fused chained-absorb
// kernels for Areion-SoEM-256. They are the batched path for hosts that
// expose VAES on YMM but lack AVX-512 (HasVAESAVX2Batched == true):
// Alder Lake / Raptor Lake / Meteor Lake / Lunar Lake / Arrow Lake
// E-cores, P-cores with BIOS-disabled AVX-512, some enterprise SKUs.
// Each kernel processes the four pixel lanes in two passes of two lanes;
// within a pass both lanes' SoEM state1 / state2 permutations run
// interleaved as four independent VAES chains (playbook §8 ILP restore),
// enough to saturate a single VAES issue port at the ~4-cycle VAESENC
// latency. Output is bit-exact with the ZMM Areion256ChainAbsorb*x4
// kernels, the XMM AES-NI Areion256ChainAbsorb*x4AesNi kernels, and the
// Go single closure; verified by the parity / bit-sensitivity tests in
// areionasm_chain256_vaesavx2_amd64_test.go.

// Areion256ChainAbsorb13x4VaesAvx2 — 13-byte Interlocked Barrier PRF
// fill shape (single SoEM round).
//
//go:noescape
func Areion256ChainAbsorb13x4VaesAvx2(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb20x4VaesAvx2 — 20-byte 128-bit nonce shape (single
// SoEM round).
//
//go:noescape
func Areion256ChainAbsorb20x4VaesAvx2(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb36x4VaesAvx2 — 36-byte 256-bit nonce shape (two
// SoEM rounds).
//
//go:noescape
func Areion256ChainAbsorb36x4VaesAvx2(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb68x4VaesAvx2 — 68-byte 512-bit nonce shape (three
// SoEM rounds).
//
//go:noescape
func Areion256ChainAbsorb68x4VaesAvx2(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)
