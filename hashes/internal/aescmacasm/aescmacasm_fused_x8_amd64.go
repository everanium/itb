//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	aes "github.com/jedisct1/go-aes"

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
var FusedHasVAESAVX512X8 = aes.CPU.HasVAES && aes.CPU.HasAVX512 && !forcetier.ChainHashX4()

// FusedX8Active reports whether the eight-lane ZMM fused kernels are the
// selected arm: [FusedHasVAESAVX512X8] together with [FusedHasVAESAVX512],
// so ITB_FORCE_HASH_TIER — which reassigns the fused tier flags as one
// set — steers the eight-lane arm with the rest of the family. Under a
// forced narrower tier the eight-lane dispatchers run two four-lane
// calls of that tier; under ITB_FORCE_CHAINHASH_X4 they run two
// four-lane ZMM calls. The parent package's attach step consults this
// predicate, so a seed built on a host or tier without the arm carries
// no eight-lane hook and its pixel loop keeps the four-lane stride.
func FusedX8Active() bool { return FusedHasVAESAVX512X8 && FusedHasVAESAVX512 }

// FusedChain20x8 runs the cascade on eight 20-byte lanes.
func FusedChain20x8(s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if FusedX8Active() && validComponents(components) {
		aesCMAC128FusedChain20x8Avx512Asm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	fusedChainX8ViaX4(FusedChain20x4, s, components, dataPtrs, out)
}

// FusedChain36x8 runs the cascade on eight 36-byte lanes.
func FusedChain36x8(s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if FusedX8Active() && validComponents(components) {
		aesCMAC128FusedChain36x8Avx512Asm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	fusedChainX8ViaX4(FusedChain36x4, s, components, dataPtrs, out)
}

// FusedChain68x8 runs the cascade on eight 68-byte lanes.
func FusedChain68x8(s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if FusedX8Active() && validComponents(components) {
		aesCMAC128FusedChain68x8Avx512Asm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	fusedChainX8ViaX4(FusedChain68x4, s, components, dataPtrs, out)
}

// Eight-lane fused kernels (aescmac_fusedchain128_<shape>x8_avx512_amd64.s).
//
//go:noescape
func aesCMAC128FusedChain20x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)
