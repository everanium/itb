//go:build amd64 && !purego && !noitbasm

// Package keccakasm holds a vendored Keccak-f[1600] permutation with an
// AVX-512 (EVEX 128-bit) kernel plus the minimal cSHAKE256-domain sponge
// layer the parent macs/ package needs for KMAC256.
//
// Kernel construction (keccakf_amd64.s, generated fully unrolled): one
// 64-bit lane per XMM register — 25 lanes across X0..X24 with five
// rotating temporaries and one scratch register. The layout makes the
// pi step pure register renaming (zero shuffle instructions across all
// 24 rounds); theta column parities fold through VPTERNLOGQ $0x96
// three-way XORs, chi is one VPTERNLOGQ $0xD2 (a ^ (~b & c)) per lane,
// rho is immediate-count VPROLQ, and iota is a single VPXORQ.BCST from
// the public round-constant table. EVEX 128-bit forms keep the ops on
// the widest port set while the active data is a single qword per
// register.
//
// Below the AVX-512 tier the parent macs/ package keeps using the
// stdlib-backed x/crypto cSHAKE256 (scalar amd64 assembly) — the
// generic permutation in this package then only serves the parity
// oracle in tests.
package keccakasm

import "golang.org/x/sys/cpu"

// HasAVX512Fused reports whether the runtime CPU supports the AVX-512
// Keccak-f[1600] kernel. VPROLQ / VPTERNLOGQ / VPXORQ in EVEX 128-bit
// form need AVX512F + AVX512VL; BW and DQ are required alongside per
// the fleet-wide gating discipline (every shipping AVX-512F part
// carries the full F/BW/VL/DQ baseline).
var HasAVX512Fused = cpu.X86.HasAVX512F && cpu.X86.HasAVX512BW &&
	cpu.X86.HasAVX512VL && cpu.X86.HasAVX512DQ

// asmCompiled reports whether this build carries the AVX-512 kernel
// at all (build-tag arm), independent of runtime CPU capability.
const asmCompiled = true

// keccakF1600AVX512 applies the Keccak-f[1600] permutation in place.
// Implemented in keccakf_amd64.s. Must only be called when
// HasAVX512Fused is true.
//
//go:noescape
func keccakF1600AVX512(a *[25]uint64)

// keccakAbsorb136AVX512 XORs one 136-byte rate block into lanes 0..16
// and applies the permutation in one pass (single state load/store
// round-trip). Implemented in keccakf_amd64.s. Must only be called
// when HasAVX512Fused is true.
//
//go:noescape
func keccakAbsorb136AVX512(a *[25]uint64, block *byte)

// keccakF1600 dispatches to the AVX-512 kernel when available and to
// the portable scalar permutation otherwise. The branch condition is
// public CPU capability — never secret data.
func keccakF1600(a *[25]uint64) {
	if HasAVX512Fused {
		keccakF1600AVX512(a)
		return
	}
	keccakF1600Generic(a)
}

// absorbBlock dispatches one full-rate-block absorb: the fused
// XOR+permute kernel on the AVX-512 tier, the portable arm otherwise.
func absorbBlock(a *[25]uint64, block []byte) {
	if HasAVX512Fused {
		keccakAbsorb136AVX512(a, &block[0])
		return
	}
	absorbBlockGeneric(a, block)
}
