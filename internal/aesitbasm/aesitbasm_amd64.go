//go:build amd64 && !purego && !noitbasm

package aesitbasm

import aes "github.com/jedisct1/go-aes"

// Tier flags. At most one of the four is true; all four are false on a
// host without AES-NI (scalar path). The flags are package variables so
// the forcetier init and the in-package dispatch tests can override the
// auto-selection.
//
// Auto-selection takes the XMM tier on every AES-NI host: with 3 to 7
// AES rounds per lane the kernels are call-overhead bound, and the
// wider register tiers measured no faster than four XMM chains — the
// VAES ZMM kernels ran 4–7 % slower and the VAES YMM kernels within
// ±3 % of XMM on the Rocket Lake / Ice Lake / Zen 4 hosts of the tier
// sweep, and on Sapphire Rapids both ZMM and YMM measured roughly 2×
// slower than XMM (lane gather / VZEROUPPER cost exceeds the per-round
// saving, and the SPR dirty-upper transition penalty compounds it).
// Both wider tiers stay built and are reachable through
// ITB_FORCE_HASH_TIER=avx512 / vaesavx2 for parity coverage.
var (
	// HasVAESAVX512 selects the ZMM kernels: all four lanes in one
	// 512-bit register, one VAESENC per round. Needs VAES + AVX-512.
	// Not auto-selected (see above).
	HasVAESAVX512 = false

	// HasVAESAVX2NoAVX512 selects the YMM kernels: two lanes per
	// 256-bit register, two VAESENC per round. Needs VAES + AVX2.
	// Not auto-selected (see above).
	HasVAESAVX2NoAVX512 = false

	// HasAVXAESNIBatched selects the VEX-encoded XMM kernels
	// (VAESENC xmm, xmm, xmm — the AVX form of AES-NI, not VAES): one
	// lane per register, four independent chains. Needs AES-NI + AVX
	// (AVX2 is used as the detection superset). Preferred over the
	// legacy-SSE encoding on AVX hosts so no SSE/AVX state transition
	// sits between the kernel and the surrounding VEX-encoded code.
	HasAVXAESNIBatched = aes.CPU.HasAESNI && aes.CPU.HasAVX2

	// HasAESNIBatched selects the legacy-SSE-encoded XMM kernels
	// (AESENC xmm, xmm) on AES-NI hosts without AVX.
	HasAESNIBatched = aes.CPU.HasAESNI && !aes.CPU.HasAVX2

	// Batch-16 tier flags: auto-select the widest VAES tier the host
	// offers. Sixteen lanes amortise the per-call cost across the register
	// width, so the batch-16 kernels scale where the four-lane per-round
	// kernels above do not: VAES ZMM measured 2.1–2.6× and VAES YMM
	// 1.5–1.9× the XMM throughput on Rocket Lake / Ice Lake / Sapphire
	// Rapids / Zen 4, including on Sapphire Rapids where the four-lane
	// wide tiers are slower than XMM. Only one flag is true; the cascade
	// keeps the "one consistent set" invariant the forcetier init relies on.
	HasVAESAVX512X16 = aes.CPU.HasVAES && aes.CPU.HasAVX512
	HasVAESAVX2X16   = aes.CPU.HasVAES && aes.CPU.HasAVX2 && !HasVAESAVX512X16

	// HasAVXAESNIX16 / HasAESNIX16 pick up on hosts without VAES, mirroring
	// the x4 ranking there.
	HasAVXAESNIX16 = HasAVXAESNIBatched && !HasVAESAVX512X16 && !HasVAESAVX2X16
	HasAESNIX16    = HasAESNIBatched

	// HasARMAESBatched / HasARMAESX16 are always false on amd64 builds.
	HasARMAESBatched = false
	HasARMAESX16     = false
)

// AESITB128ChainAbsorb13x4 evaluates the 13-byte shape on four lanes.
func AESITB128ChainAbsorb13x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	switch {
	case HasVAESAVX512:
		aesITB128ChainAbsorb13x4Avx512Asm(key, seeds, dataPtrs, out)
	case HasVAESAVX2NoAVX512:
		aesITB128ChainAbsorb13x4VaesAvx2Asm(key, seeds, dataPtrs, out)
	case HasAVXAESNIBatched:
		aesITB128ChainAbsorb13x4VexAsm(key, seeds, dataPtrs, out)
	case HasAESNIBatched:
		aesITB128ChainAbsorb13x4AesNiAsm(key, seeds, dataPtrs, out)
	default:
		scalarBatch(key, seeds, dataPtrs, 13, out)
	}
}

// AESITB128ChainAbsorb20x4 evaluates the 20-byte shape on four lanes.
func AESITB128ChainAbsorb20x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	switch {
	case HasVAESAVX512:
		aesITB128ChainAbsorb20x4Avx512Asm(key, seeds, dataPtrs, out)
	case HasVAESAVX2NoAVX512:
		aesITB128ChainAbsorb20x4VaesAvx2Asm(key, seeds, dataPtrs, out)
	case HasAVXAESNIBatched:
		aesITB128ChainAbsorb20x4VexAsm(key, seeds, dataPtrs, out)
	case HasAESNIBatched:
		aesITB128ChainAbsorb20x4AesNiAsm(key, seeds, dataPtrs, out)
	default:
		scalarBatch(key, seeds, dataPtrs, 20, out)
	}
}

// AESITB128ChainAbsorb36x4 evaluates the 36-byte shape on four lanes.
func AESITB128ChainAbsorb36x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	switch {
	case HasVAESAVX512:
		aesITB128ChainAbsorb36x4Avx512Asm(key, seeds, dataPtrs, out)
	case HasVAESAVX2NoAVX512:
		aesITB128ChainAbsorb36x4VaesAvx2Asm(key, seeds, dataPtrs, out)
	case HasAVXAESNIBatched:
		aesITB128ChainAbsorb36x4VexAsm(key, seeds, dataPtrs, out)
	case HasAESNIBatched:
		aesITB128ChainAbsorb36x4AesNiAsm(key, seeds, dataPtrs, out)
	default:
		scalarBatch(key, seeds, dataPtrs, 36, out)
	}
}

// AESITB128ChainAbsorb68x4 evaluates the 68-byte shape on four lanes.
func AESITB128ChainAbsorb68x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	switch {
	case HasVAESAVX512:
		aesITB128ChainAbsorb68x4Avx512Asm(key, seeds, dataPtrs, out)
	case HasVAESAVX2NoAVX512:
		aesITB128ChainAbsorb68x4VaesAvx2Asm(key, seeds, dataPtrs, out)
	case HasAVXAESNIBatched:
		aesITB128ChainAbsorb68x4VexAsm(key, seeds, dataPtrs, out)
	case HasAESNIBatched:
		aesITB128ChainAbsorb68x4AesNiAsm(key, seeds, dataPtrs, out)
	default:
		scalarBatch(key, seeds, dataPtrs, 68, out)
	}
}

// Legacy-SSE AES-NI XMM kernels (aesitb_chain128_*_aesni_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x4AesNiAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb20x4AesNiAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb36x4AesNiAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb68x4AesNiAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

// VEX-encoded AES-NI XMM kernels (aesitb_chain128_*_vex_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x4VexAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb20x4VexAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb36x4VexAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb68x4VexAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

// VAES YMM kernels, two lanes per register (aesitb_chain128_*_vaesavx2_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x4VaesAvx2Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb20x4VaesAvx2Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb36x4VaesAvx2Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb68x4VaesAvx2Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

// VAES ZMM kernels, four lanes per register (aesitb_chain128_*_avx512_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x4Avx512Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb20x4Avx512Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb36x4Avx512Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb68x4Avx512Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

// VEX-encoded AES-NI XMM 16-lane kernel (aesitb_chain128_13x16_vex_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x16VexAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)

// Legacy-SSE AES-NI XMM 16-lane kernel (aesitb_chain128_13x16_aesni_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x16AesNiAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)

// VAES ZMM 16-lane kernel (aesitb_chain128_13x16_avx512_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x16VaesAvx512Asm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)

// VAES YMM 16-lane kernel (aesitb_chain128_13x16_vaesavx2_amd64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x16VaesAvx2Asm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)

// AESITB128ChainAbsorb13x16 evaluates the 13-byte shape on 16 lanes.
func AESITB128ChainAbsorb13x16(key *[16]byte, seed0, seed1 uint64, groupIdxBase uint64, out *[16][2]uint64) {
	switch {
	case HasVAESAVX512X16:
		aesITB128ChainAbsorb13x16VaesAvx512Asm(key, seed0, seed1, groupIdxBase, out)
	case HasVAESAVX2X16:
		aesITB128ChainAbsorb13x16VaesAvx2Asm(key, seed0, seed1, groupIdxBase, out)
	case HasAVXAESNIX16:
		aesITB128ChainAbsorb13x16VexAsm(key, seed0, seed1, groupIdxBase, out)
	case HasAESNIX16:
		aesITB128ChainAbsorb13x16AesNiAsm(key, seed0, seed1, groupIdxBase, out)
	default:
		scalarBatchX16(key, groupIdxBase, seed0, seed1, out)
	}
}
