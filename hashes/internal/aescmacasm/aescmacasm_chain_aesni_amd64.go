//go:build amd64 && !purego && !noitbasm

package aescmacasm

// This file declares the XMM AES-NI (no VAES) 4-lane fused chain-absorb
// kernels for AES-CMAC-128. They are the fallback batched path for
// hosts that expose AES-NI but lack the VAES + AVX-512 ZMM tier
// (HasAESNIBatched == true): Cascade Lake Xeon Gold, AMD Zen 3, and
// every AVX2-no-VAES cloud VM. Each kernel holds the four lane states
// in XMM registers X0..X3 and advances all four AES-CMAC chains under a
// shared round-key stream (round keys preloaded into X5..X15), the four
// disjoint chains hiding the ~4-cycle AESENC latency on a single AES
// issue port (playbook §8: ILP restore).
//
// Bit-exact parity against the scalar reference (and, on VAES hosts,
// against the ZMM kernel) is verified by the x4 AES-NI parity tests in
// aescmacasm_chain_aesni_test.go.

// aesCMAC128ChainAbsorb13x4AesNiAsm — 13-byte Interlocked Barrier PRF
// fill shape (single CBC-MAC block).
//
//go:noescape
func aesCMAC128ChainAbsorb13x4AesNiAsm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// aesCMAC128ChainAbsorb20x4AesNiAsm — 20-byte 128-bit nonce shape
// (2 CBC-MAC rounds).
//
//go:noescape
func aesCMAC128ChainAbsorb20x4AesNiAsm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// aesCMAC128ChainAbsorb36x4AesNiAsm — 36-byte 256-bit nonce shape
// (3 CBC-MAC rounds).
//
//go:noescape
func aesCMAC128ChainAbsorb36x4AesNiAsm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// aesCMAC128ChainAbsorb68x4AesNiAsm — 68-byte 512-bit nonce shape
// (5 CBC-MAC rounds).
//
//go:noescape
func aesCMAC128ChainAbsorb68x4AesNiAsm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)
