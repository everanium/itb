//go:build amd64 && !purego && !noitbasm

package blake2sasm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// Fused-cascade tier flags of the BLAKE2s kernels. At most one flag of
// the family is true; auto-selection takes the EVEX tier on AVX-512F
// hosts and the VEX XMM tier on AVX2 hosts without it. The forcetier init
// keeps this family and the batch-16 fill family consistent.
var (
	// FusedHasAVX512 selects the EVEX fused kernels (XMM at four lanes,
	// YMM at eight). Needs AVX-512F.
	FusedHasAVX512 = cpu.X86.HasAVX512F

	// FusedHasAVX2 selects the VEX XMM fused kernels on AVX2 hosts
	// without AVX-512F.
	FusedHasAVX2 = cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F

	// FusedHasNEON is always false on amd64 builds.
	FusedHasNEON = false
)

// Fill tier flags: the tier of the Interlocked Barrier fill hook
// (Fused256Fill13x8), overridable on its own through
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER. The AVX-512 tier runs the dedicated
// eight-lane YMM kernel; the AVX2 tier runs two four-lane kernel calls
// over Go-synthesised fill blocks.
var (
	HasAVX512X16 = cpu.X86.HasAVX512F
	HasAVX2X16   = cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F
	HasNEONX16   = false
)

// FusedAvailable reports whether any assembly tier of the fused cascade
// family is selected.
func FusedAvailable() bool { return FusedHasAVX512 || FusedHasAVX2 }

// Fused256Chain13x4 runs the cascade on four 13-byte lanes.
func Fused256Chain13x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasAVX512:
		blake2sFusedChain13x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAVX2:
		blake2sFusedChain13x4Avx2Asm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
	}
}

// Fused256Chain13x1 runs the cascade on one 13-byte lane through the
// general-purpose-register kernel, the single-lane arm of every tier.
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		blake2sFusedChain13x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 13))
}

// Fused256Chain20x4 runs the cascade on four 20-byte lanes.
func Fused256Chain20x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasAVX512:
		blake2sFusedChain20x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAVX2:
		blake2sFusedChain20x4Avx2Asm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
	}
}

// Fused256Chain20x1 runs the cascade on one 20-byte lane through the
// general-purpose-register kernel.
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		blake2sFusedChain20x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 20))
}

// Fused256Chain36x4 runs the cascade on four 36-byte lanes.
func Fused256Chain36x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasAVX512:
		blake2sFusedChain36x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAVX2:
		blake2sFusedChain36x4Avx2Asm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
	}
}

// Fused256Chain36x1 runs the cascade on one 36-byte lane through the
// general-purpose-register kernel.
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		blake2sFusedChain36x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 36))
}

// Fused256Chain68x4 runs the cascade on four 68-byte lanes.
func Fused256Chain68x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasAVX512:
		blake2sFusedChain68x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAVX2:
		blake2sFusedChain68x4Avx2Asm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
	}
}

// Fused256Chain68x1 runs the cascade on one 68-byte lane through the
// general-purpose-register kernel.
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		blake2sFusedChain68x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 68))
}

// Fused256Fill13x8 is the batch-16 Interlocked Barrier fill hook: lane i
// (0..7) runs the cascade over the fill block of group groupIdxBase+i.
// The AVX-512 tier synthesises the blocks in-register and runs the
// eight-lane YMM kernel; the AVX2 tier runs two four-lane kernel calls
// over Go-synthesised blocks. The dispatch follows the batch-16 flags so
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER selects the arm.
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	if !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case HasAVX512X16:
		blake2sFusedChain13x8Avx512Asm(fixedKey, c, ng, groupIdxBase, out)
	case HasAVX2X16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
			blake2sFusedChain13x4Avx2Asm(fixedKey, c, ng, &ptrs, out8x256Half(out, h))
		}
	default:
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
	}
}

// FusedHasAVX512X8 arms the eight-lane YMM per-pixel kernels
// (Fused256Chain{20,36,68}x8: the four-lane EVEX plan on YMM registers,
// one dword lane per pixel). Needs AVX-512F; cleared at init by
// ITB_FORCE_CHAINHASH_X4 so a parity or benchmark run can pin the
// four-lane kernels on a host that would otherwise select x8. The flag
// is a package variable so the in-package tests and the parent package's
// wire-parity tests can toggle the arm within one process.
//
// The eight-lane arm is selected only together with the AVX-512 fused
// tier (see [FusedX8Active]); it does not add a tier of its own to the
// exclusive fused flag set above.
var FusedHasAVX512X8 = cpu.X86.HasAVX512F && !forcetier.ChainHashX4()

// FusedX8Active reports whether the eight-lane YMM per-pixel kernels are
// the selected arm: [FusedHasAVX512X8] together with [FusedHasAVX512], so
// ITB_FORCE_HASH_TIER — which reassigns the fused tier flags as one set —
// steers the eight-lane arm with the rest of the family. Under any other
// flag state the eight-lane dispatchers run two four-lane calls of the
// selected tier. The parent package's attach step consults this
// predicate, so a seed built on a host or tier without the arm carries no
// eight-lane hook and its pixel loop keeps the four-lane stride.
func FusedX8Active() bool { return FusedHasAVX512X8 && FusedHasAVX512 }

// Fused256Chain20x8 runs the cascade on eight 20-byte lanes.
func Fused256Chain20x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	if FusedX8Active() && validComponents256(components) {
		blake2sFusedChain20x8Avx512Asm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	Fused256Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Fused256Chain36x8 runs the cascade on eight 36-byte lanes.
func Fused256Chain36x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	if FusedX8Active() && validComponents256(components) {
		blake2sFusedChain36x8Avx512Asm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	Fused256Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Fused256Chain68x8 runs the cascade on eight 68-byte lanes.
func Fused256Chain68x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	if FusedX8Active() && validComponents256(components) {
		blake2sFusedChain68x8Avx512Asm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	Fused256Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Kernels (blake2s_fusedchain256_<shape>x4_<tier>_amd64.s, the eight-lane
// per-pixel and fill kernels blake2s_fusedchain256_<shape>x8_avx512_amd64.s
// and the single-lane kernels blake2s_fusedchain256_<shape>x1_gpr_amd64.s).
//
//go:noescape
func blake2sFusedChain13x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain13x4Avx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain20x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain20x4Avx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain36x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain36x4Avx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain68x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain68x4Avx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain13x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][4]uint64)

//
//go:noescape
func blake2sFusedChain20x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][4]uint64)

//
//go:noescape
func blake2sFusedChain36x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][4]uint64)

//
//go:noescape
func blake2sFusedChain68x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][4]uint64)

//
//go:noescape
func blake2sFusedChain13x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2sFusedChain20x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2sFusedChain36x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2sFusedChain68x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)
