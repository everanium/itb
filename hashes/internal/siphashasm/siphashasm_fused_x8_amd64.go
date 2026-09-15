//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// FusedHasAVX512X8 arms the eight-lane ZMM fused kernels (eight lanes in
// one qword each of the state registers). Needs AVX-512F; cleared at
// init by ITB_FORCE_CHAINHASH_X4 so a parity or benchmark run can pin the
// four-lane YMM kernels on a host that would otherwise select x8. The
// flag is a package variable so the in-package tests and the parent
// package's wire-parity tests can toggle the arm within one process.
//
// The eight-lane arm is selected only together with the AVX-512 fused
// tier (see [FusedX8Active]); it does not add a tier of its own to the
// exclusive fused flag set of siphashasm_fused_amd64.go.
var FusedHasAVX512X8 = cpu.X86.HasAVX512F && !forcetier.ChainHashX4()

// FusedX8Active reports whether the eight-lane ZMM fused kernels are the
// selected arm: [FusedHasAVX512X8] together with [FusedHasAVX512], so
// ITB_FORCE_HASH_TIER — which reassigns the fused tier flags as one set —
// steers the eight-lane arm with the rest of the family. Under a forced
// narrower tier the eight-lane dispatchers run two four-lane calls of
// that tier; under ITB_FORCE_CHAINHASH_X4 they run two four-lane YMM
// calls. The parent package's attach step consults this predicate, so a
// seed built on a host or tier without the arm carries no eight-lane
// hook and its pixel loop keeps the four-lane stride.
func FusedX8Active() bool { return FusedHasAVX512X8 && FusedHasAVX512 }

// FusedChain20x8 runs the cascade on eight 20-byte lanes.
func FusedChain20x8(components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if FusedX8Active() && validComponents(components) {
		sipHash24FusedChain20x8Avx512Asm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	fusedChainX8ViaX4(20, components, dataPtrs, out)
}

// FusedChain36x8 runs the cascade on eight 36-byte lanes.
func FusedChain36x8(components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if FusedX8Active() && validComponents(components) {
		sipHash24FusedChain36x8Avx512Asm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	fusedChainX8ViaX4(36, components, dataPtrs, out)
}

// FusedChain68x8 runs the cascade on eight 68-byte lanes.
func FusedChain68x8(components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	if FusedX8Active() && validComponents(components) {
		sipHash24FusedChain68x8Avx512Asm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	fusedChainX8ViaX4(68, components, dataPtrs, out)
}

// Eight-lane fused kernels (siphash_fusedchain128_<shape>x8_avx512_amd64.s).
//
//go:noescape
func sipHash24FusedChain20x8Avx512Asm(comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func sipHash24FusedChain36x8Avx512Asm(comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)

//go:noescape
func sipHash24FusedChain68x8Avx512Asm(comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)
