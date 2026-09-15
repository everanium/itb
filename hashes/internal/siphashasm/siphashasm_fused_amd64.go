//go:build amd64 && !purego && !noitbasm

package siphashasm

import "golang.org/x/sys/cpu"

// Fused-cascade tier flags. The fused kernels amortise lane gather and
// word packing over every cascade round and keep the (lo, hi) carry in
// registers; the forcetier init keeps the fused-cascade and batch-16
// fill flag families mutually consistent. At most one flag in this
// family is true.
//
// Auto-selection takes the AVX-512 tier when the host offers it (the
// EVEX kernels rotate with VPROLQ and reach registers 16..31), else the
// AVX2 tier (VEX kernels with synthesised rotates). The single-lane GPR
// kernel needs neither and runs under either selected tier.
var (
	// FusedHasAVX512 selects the EVEX YMM four-lane kernels, the ZMM
	// eight-lane kernels and the ZMM batch-16 kernel. Needs AVX-512F
	// (with DQ, present on every shipping AVX-512F part).
	FusedHasAVX512 = cpu.X86.HasAVX512F

	// FusedHasAVX2 selects the VEX YMM four-lane kernels on AVX2 hosts
	// without AVX-512F; yields to the AVX-512 tier.
	FusedHasAVX2 = cpu.X86.HasAVX2 && !FusedHasAVX512

	// FusedHasNEON is always false on amd64 builds.
	FusedHasNEON = false
)

// FusedHasGPR arms the single-lane general-purpose-register kernels, the
// single-lane arm of every tier: true on every amd64 build, cleared by
// ITB_FORCE_HASH_TIER=scalar. Where no SIMD tier is selected the
// four-lane dispatchers run four single-lane calls under this flag, so a
// host without AVX2 keeps the cascade in assembly.
var FusedHasGPR = true

// HasGPRX16 is the general-purpose-register arm of the batch-16 fill
// hook: single-lane calls over Go-synthesised fill blocks where no SIMD
// fill tier is selected. Cleared by ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar
// and by ITB_FORCE_HASH_TIER=scalar.
var HasGPRX16 = true

// FusedAvailable reports whether any assembly arm of the fused cascade
// family is selected — a SIMD tier or the single-lane GPR arm.
func FusedAvailable() bool {
	return FusedHasAVX512 || FusedHasAVX2 || FusedHasGPR
}

// FusedChain13x4 runs the cascade on four 13-byte lanes.
func FusedChain13x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 13, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasAVX512:
		sipHash24FusedChain13x4Avx512Asm(c, n, dataPtrs, out)
	case FusedHasAVX2:
		sipHash24FusedChain13x4Avx2Asm(c, n, dataPtrs, out)
	default:
		if !FusedHasGPR {
			scalarFusedBatch(components, dataPtrs, 13, out)
			return
		}
		for l := range dataPtrs {
			sipHash24FusedChain13x1GprAsm(c, n, dataPtrs[l], &out[l])
		}
	}
}

// FusedChain20x4 runs the cascade on four 20-byte lanes.
func FusedChain20x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 20, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasAVX512:
		sipHash24FusedChain20x4Avx512Asm(c, n, dataPtrs, out)
	case FusedHasAVX2:
		sipHash24FusedChain20x4Avx2Asm(c, n, dataPtrs, out)
	default:
		if !FusedHasGPR {
			scalarFusedBatch(components, dataPtrs, 20, out)
			return
		}
		for l := range dataPtrs {
			sipHash24FusedChain20x1GprAsm(c, n, dataPtrs[l], &out[l])
		}
	}
}

// FusedChain36x4 runs the cascade on four 36-byte lanes.
func FusedChain36x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 36, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasAVX512:
		sipHash24FusedChain36x4Avx512Asm(c, n, dataPtrs, out)
	case FusedHasAVX2:
		sipHash24FusedChain36x4Avx2Asm(c, n, dataPtrs, out)
	default:
		if !FusedHasGPR {
			scalarFusedBatch(components, dataPtrs, 36, out)
			return
		}
		for l := range dataPtrs {
			sipHash24FusedChain36x1GprAsm(c, n, dataPtrs[l], &out[l])
		}
	}
}

// FusedChain68x4 runs the cascade on four 68-byte lanes.
func FusedChain68x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 68, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasAVX512:
		sipHash24FusedChain68x4Avx512Asm(c, n, dataPtrs, out)
	case FusedHasAVX2:
		sipHash24FusedChain68x4Avx2Asm(c, n, dataPtrs, out)
	default:
		if !FusedHasGPR {
			scalarFusedBatch(components, dataPtrs, 68, out)
			return
		}
		for l := range dataPtrs {
			sipHash24FusedChain68x1GprAsm(c, n, dataPtrs[l], &out[l])
		}
	}
}

// FusedChain13x1 runs the cascade on one 13-byte input.
func FusedChain13x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain13x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 13, out)
}

// FusedChain20x1 runs the cascade on one 20-byte input.
func FusedChain20x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain20x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 20, out)
}

// FusedChain36x1 runs the cascade on one 36-byte input.
func FusedChain36x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain36x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 36, out)
}

// FusedChain68x1 runs the cascade on one 68-byte input.
func FusedChain68x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain68x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 68, out)
}

// FusedChain13x16 runs the cascade on the 16 lanes of the Interlocked
// Barrier fill: lane i carries the 13-byte fill block
// [0x03 | LE64(groupIdxBase+i) | 4×0x00] and every lane runs the whole
// cascade over components. The dispatch follows the batch-16 tier flags
// (HasAVX512X16 / HasAVX2X16) rather than the fused x4 flags, so
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER selects the arm. Both kernels
// synthesise the blocks in-register: the ZMM kernel covers the sixteen
// lanes in one call, the AVX2 eight-lane YMM kernel runs twice (lanes
// 0..7 at groupIdxBase, lanes 8..15 at groupIdxBase + 8); without a SIMD
// fill tier the GPR arm runs sixteen single-lane calls over Go-synthesised
// blocks.
func FusedChain13x16(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if !validComponents(components) {
		scalarFusedX16(components, groupIdxBase, out)
		return
	}
	switch {
	case HasAVX512X16:
		sipHash24FusedChain13x16Avx512Asm(&components[0], len(components)/2, groupIdxBase, out)
	case HasAVX2X16:
		sipHash24FusedChain13x8Avx2Asm(&components[0], len(components)/2, groupIdxBase, x16Half(out, 0))
		sipHash24FusedChain13x8Avx2Asm(&components[0], len(components)/2, groupIdxBase+8, x16Half(out, 1))
	default:
		if !HasGPRX16 {
			scalarFusedX16(components, groupIdxBase, out)
			return
		}
		blocks := fillBlocks16(groupIdxBase)
		c, np := &components[0], len(components)/2
		for i := range blocks {
			sipHash24FusedChain13x1GprAsm(c, np, &blocks[i][0], &out[i])
		}
	}
}

// Four-lane fused kernels (siphash_fusedchain128_<shape>x4_<tier>_amd64.s).
//
//go:noescape
func sipHash24FusedChain13x4Avx512Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain20x4Avx512Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain36x4Avx512Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain68x4Avx512Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain13x4Avx2Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain20x4Avx2Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain36x4Avx2Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain68x4Avx2Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

// Single-lane fused kernels (siphash_fusedchain128_<shape>x1_gpr_amd64.s).
//
//go:noescape
func sipHash24FusedChain13x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func sipHash24FusedChain20x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func sipHash24FusedChain36x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func sipHash24FusedChain68x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

// Sixteen-lane fused fill kernel (siphash_fusedchain128_13x16_avx512_amd64.s)
// and the eight-lane fill kernel of the AVX2 tier
// (siphash_fusedchain128_13x8_avx2_amd64.s).
//
//go:noescape
func sipHash24FusedChain13x16Avx512Asm(comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)

//go:noescape
func sipHash24FusedChain13x8Avx2Asm(comps *uint64, nPairs int, groupIdxBase uint64, out *[8][2]uint64)
