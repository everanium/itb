//go:build amd64 && !purego && !noitbasm

package aesitbasm

import aes "github.com/jedisct1/go-aes"

// Batch-16 tier flags: auto-select the widest VAES tier the host offers.
// The flags are package variables so the forcetier init and the
// in-package dispatch tests can override the auto-selection. Sixteen
// lanes amortise the per-call cost across the register width: VAES ZMM
// measured 2.1–2.6× and VAES YMM 1.5–1.9× the XMM throughput on Rocket
// Lake / Ice Lake / Sapphire Rapids / Zen 4 (BenchmarkTierX16; the kernel
// takes its arguments by value and synthesises the fill blocks
// in-register, so no store sits ahead of its loads). Only one flag is
// true; the cascade keeps the "one consistent set" invariant the
// forcetier init relies on.
//
// The per-pixel shapes are carried by the fused cascade family
// (aesitbasm_fused_amd64.go); the four-lane dispatchers below are the
// scalar reference over ChainAbsorb.
var (
	HasVAESAVX512X16 = aes.CPU.HasVAES && aes.CPU.HasAVX512
	HasVAESAVX2X16   = aes.CPU.HasVAES && aes.CPU.HasAVX2 && !HasVAESAVX512X16

	// HasAVXAESNIX16 selects the VEX-encoded XMM batch-16 kernel on
	// AES-NI + AVX hosts without VAES (AVX2 is used as the detection
	// superset); HasAESNIX16 selects the legacy-SSE-encoded XMM batch-16
	// kernel on AES-NI hosts without AVX.
	HasAVXAESNIX16 = aes.CPU.HasAESNI && aes.CPU.HasAVX2 && !HasVAESAVX512X16 && !HasVAESAVX2X16
	HasAESNIX16    = aes.CPU.HasAESNI && !aes.CPU.HasAVX2

	// HasARMAESX16 is always false on amd64 builds.
	HasARMAESX16 = false
)

// The batch-16 flags above select the arm of FusedChain13x16
// (aesitbasm_fused_amd64.go), the Interlocked Barrier fill kernel.

// AESITB128ChainAbsorb13x4 evaluates the 13-byte shape on four lanes.
func AESITB128ChainAbsorb13x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 13, out)
}

// AESITB128ChainAbsorb20x4 evaluates the 20-byte shape on four lanes.
func AESITB128ChainAbsorb20x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 20, out)
}

// AESITB128ChainAbsorb36x4 evaluates the 36-byte shape on four lanes.
func AESITB128ChainAbsorb36x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 36, out)
}

// AESITB128ChainAbsorb68x4 evaluates the 68-byte shape on four lanes.
func AESITB128ChainAbsorb68x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 68, out)
}
