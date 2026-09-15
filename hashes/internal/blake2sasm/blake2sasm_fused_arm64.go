//go:build arm64 && !purego && !noitbasm

package blake2sasm

import "golang.org/x/sys/cpu"

// Fused-cascade tier flags on arm64: the NEON kernels (four dword lanes
// per register, one pass) run on every ARMv8-A host; the amd64 flags are
// always false.
var (
	FusedHasAVX512 = false
	FusedHasAVX2   = false
	FusedHasNEON   = cpu.ARM64.HasASIMD
)

// Batch-16 fill tier flags: the NEON arm runs two four-lane kernel calls
// over Go-synthesised fill blocks.
var (
	HasAVX512X16 = false
	HasAVX2X16   = false
	HasNEONX16   = cpu.ARM64.HasASIMD
)

// FusedHasGPR arms the single-lane general-purpose-register kernels, the
// single-lane arm of every tier: true on every arm64 build, cleared by
// ITB_FORCE_HASH_TIER=scalar.
var FusedHasGPR = true

// HasGPRX16 is the general-purpose-register arm of the batch-16 fill
// hook; cleared by ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar and by
// ITB_FORCE_HASH_TIER=scalar.
var HasGPRX16 = true

// FusedAvailable reports whether the NEON tier or the GPR arm is selected.
func FusedAvailable() bool { return FusedHasNEON || FusedHasGPR }

// Fused256Chain13x4 runs the cascade on four 13-byte lanes.
func Fused256Chain13x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasNEON:
		blake2sFusedChain13x4NeonAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			blake2sFusedChain13x1GprAsm(fixedKey, c, ng, dataPtrs[l], &out[l])
		}
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
	}
}

// Fused256Chain13x1 runs the cascade on one 13-byte lane through the
// general-purpose-register kernel.
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasGPR && validComponents256(components) {
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
	case FusedHasNEON:
		blake2sFusedChain20x4NeonAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			blake2sFusedChain20x1GprAsm(fixedKey, c, ng, dataPtrs[l], &out[l])
		}
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
	}
}

// Fused256Chain20x1 runs the cascade on one 20-byte lane through the
// general-purpose-register kernel.
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasGPR && validComponents256(components) {
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
	case FusedHasNEON:
		blake2sFusedChain36x4NeonAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			blake2sFusedChain36x1GprAsm(fixedKey, c, ng, dataPtrs[l], &out[l])
		}
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
	}
}

// Fused256Chain36x1 runs the cascade on one 36-byte lane through the
// general-purpose-register kernel.
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasGPR && validComponents256(components) {
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
	case FusedHasNEON:
		blake2sFusedChain68x4NeonAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			blake2sFusedChain68x1GprAsm(fixedKey, c, ng, dataPtrs[l], &out[l])
		}
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
	}
}

// Fused256Chain68x1 runs the cascade on one 68-byte lane through the
// general-purpose-register kernel.
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasGPR && validComponents256(components) {
		blake2sFusedChain68x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 68))
}

// Fused256Fill13x8 is the batch-16 Interlocked Barrier fill hook on the
// NEON tier: two four-lane kernel calls over Go-synthesised fill blocks.
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	if !HasNEONX16 || !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/4
	var blocks [4][13]byte
	for h := 0; h < 2; h++ {
		ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
		blake2sFusedChain13x4NeonAsm(fixedKey, c, ng, &ptrs, out8x256Half(out, h))
	}
}

// Eight-lane per-pixel arm: no NEON eight-lane kernel exists; the
// eight-lane dispatchers run two four-lane NEON calls.
var FusedHasAVX512X8 = false

// FusedX8Active is always false on arm64 builds.
func FusedX8Active() bool { return false }

func Fused256Chain20x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	Fused256Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}
func Fused256Chain36x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	Fused256Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}
func Fused256Chain68x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	Fused256Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Kernels (blake2s_fusedchain256_<shape>x4_neon_arm64.s and the
// single-lane kernels blake2s_fusedchain256_<shape>x1_gpr_arm64.s).
//
//go:noescape
func blake2sFusedChain13x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain20x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain36x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2sFusedChain68x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

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
