//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// FusedHasVAESAVX512X8 arms the eight-lane ZMM fused kernels (two
// four-lane state groups per call, cascade rounds interleaved). Needs
// VAES + AVX-512; cleared at init by ITB_FORCE_CHAINHASH_X4 so a parity
// or benchmark run can pin the four-lane ZMM kernels on a host that
// would otherwise select x8. The flag is a package variable so the
// in-package tests and the parent package's wire-parity tests can
// toggle the arm within one process.
//
// The eight-lane arm is selected only together with the ZMM fused tier
// (see [FusedX8Active]); it does not add a tier of its own to the
// exclusive fused flag set of aescmacasm_fused_amd64.go.
var FusedHasVAESAVX512X8 = cpuid.VAESZMM && !forcetier.ChainHashX4()

// FusedHasAESNIX8 arms the eight-lane fused kernels of the AES-NI tiers
// below ZMM: four YMM states of two lanes on the VAES YMM tier, eight
// XMM states of one lane on the VEX and legacy-SSE tiers, the cascade
// rounds of the states interleaved. Needs AES-NI; cleared at init by
// ITB_FORCE_CHAINHASH_X4 exactly as [FusedHasVAESAVX512X8] is, and
// selected only together with one of those three fused tiers.
var FusedHasAESNIX8 = cpuid.AESNI && !forcetier.ChainHashX4()

// FusedX8Active reports whether an eight-lane fused arm is the selected
// arm: [FusedHasVAESAVX512X8] together with [FusedHasVAESAVX512], or
// [FusedHasAESNIX8] together with one of [FusedHasVAESAVX2],
// [FusedHasAVXAESNI] and [FusedHasAESNI], so ITB_FORCE_HASH_TIER —
// which reassigns the fused tier flags as one set — steers the
// eight-lane arm with the rest of the family. Under any other flag state
// the eight-lane dispatchers run two four-lane calls of the selected
// tier; under ITB_FORCE_CHAINHASH_X4 they do so on every tier. The
// parent package's attach step consults this predicate, so a seed built
// on a host or tier without an arm carries no eight-lane hook and its
// pixel loop keeps the four-lane stride.
func FusedX8Active() bool {
	return (FusedHasVAESAVX512X8 && FusedHasVAESAVX512) ||
		(FusedHasAESNIX8 && (FusedHasVAESAVX2 || FusedHasAVXAESNI || FusedHasAESNI))
}

// FusedChain20x8 runs the cascade on eight 20-byte lanes.
func FusedChain20x8(s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if validComponents(components) {
		c, np := &components[0], len(components)/2
		switch {
		case FusedHasVAESAVX512X8 && FusedHasVAESAVX512:
			aesCMAC128FusedChain20x8Avx512Asm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasVAESAVX2:
			aesCMAC128FusedChain20x8VaesAvx2Asm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasAVXAESNI:
			aesCMAC128FusedChain20x8VexAsm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasAESNI:
			aesCMAC128FusedChain20x8AesNiAsm(&s.roundKeys, c, np, dataPtrs, out)
			return
		}
	}
	fusedChainX8ViaX4(FusedChain20x4, s, components, dataPtrs, out)
}

// FusedChain36x8 runs the cascade on eight 36-byte lanes.
func FusedChain36x8(s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if validComponents(components) {
		c, np := &components[0], len(components)/2
		switch {
		case FusedHasVAESAVX512X8 && FusedHasVAESAVX512:
			aesCMAC128FusedChain36x8Avx512Asm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasVAESAVX2:
			aesCMAC128FusedChain36x8VaesAvx2Asm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasAVXAESNI:
			aesCMAC128FusedChain36x8VexAsm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasAESNI:
			aesCMAC128FusedChain36x8AesNiAsm(&s.roundKeys, c, np, dataPtrs, out)
			return
		}
	}
	fusedChainX8ViaX4(FusedChain36x4, s, components, dataPtrs, out)
}

// FusedChain68x8 runs the cascade on eight 68-byte lanes.
func FusedChain68x8(s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if validComponents(components) {
		c, np := &components[0], len(components)/2
		switch {
		case FusedHasVAESAVX512X8 && FusedHasVAESAVX512:
			aesCMAC128FusedChain68x8Avx512Asm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasVAESAVX2:
			aesCMAC128FusedChain68x8VaesAvx2Asm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasAVXAESNI:
			aesCMAC128FusedChain68x8VexAsm(&s.roundKeys, c, np, dataPtrs, out)
			return
		case FusedHasAESNIX8 && FusedHasAESNI:
			aesCMAC128FusedChain68x8AesNiAsm(&s.roundKeys, c, np, dataPtrs, out)
			return
		}
	}
	fusedChainX8ViaX4(FusedChain68x4, s, components, dataPtrs, out)
}

// Eight-lane fused kernels (aescmac_fusedchain128_<shape>x8_<tier>_amd64.s).
//
//go:noescape
func aesCMAC128FusedChain20x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x8VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x8VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x8VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x8VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x8VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x8VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x8AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x8AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x8AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)
