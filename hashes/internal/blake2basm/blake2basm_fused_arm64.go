//go:build arm64 && !purego && !noitbasm

package blake2basm

import "golang.org/x/sys/cpu"

// Fused-cascade tier flags on arm64: the NEON kernels (two lanes per
// pass, two passes) run on every ARMv8-A host; the amd64 flags are
// always false.
var (
	FusedHasAVX512 = false
	FusedHasAVX2   = false
	FusedHasNEON   = cpu.ARM64.HasASIMD
)

// Batch-16 fill tier flags: the NEON arm runs four-lane kernel calls over
// Go-synthesised fill blocks.
var (
	HasAVX512X16 = false
	HasAVX2X16   = false
	HasNEONX16   = cpu.ARM64.HasASIMD
)

// FusedAvailable reports whether the NEON tier is selected.
func FusedAvailable() bool { return FusedHasNEON }

// Fused256Chain13x4 runs the width-256 cascade on four 13-byte lanes.
func Fused256Chain13x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain13x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
}

// Fused256Chain13x1 runs the width-256 cascade on one 13-byte lane
// through the four-lane kernel with the lane replicated.
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain13x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 13))
}

// Fused256Chain20x4 runs the width-256 cascade on four 20-byte lanes.
func Fused256Chain20x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain20x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
}

// Fused256Chain20x1 runs the width-256 cascade on one 20-byte lane
// through the four-lane kernel with the lane replicated.
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain20x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 20))
}

// Fused256Chain36x4 runs the width-256 cascade on four 36-byte lanes.
func Fused256Chain36x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain36x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
}

// Fused256Chain36x1 runs the width-256 cascade on one 36-byte lane
// through the four-lane kernel with the lane replicated.
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain36x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 36))
}

// Fused256Chain68x4 runs the width-256 cascade on four 68-byte lanes.
func Fused256Chain68x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain68x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
}

// Fused256Chain68x1 runs the width-256 cascade on one 68-byte lane
// through the four-lane kernel with the lane replicated.
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasNEON && validComponents256(components) {
		blake2b256FusedChain68x1GprAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 68))
}

// Fused512Chain13x4 runs the width-512 cascade on four 13-byte lanes.
func Fused512Chain13x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain13x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 13, out)
}

// Fused512Chain13x1 runs the width-512 cascade on one 13-byte lane
// through the four-lane kernel with the lane replicated.
func Fused512Chain13x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain13x1GprAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 13))
}

// Fused512Chain20x4 runs the width-512 cascade on four 20-byte lanes.
func Fused512Chain20x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain20x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 20, out)
}

// Fused512Chain20x1 runs the width-512 cascade on one 20-byte lane
// through the four-lane kernel with the lane replicated.
func Fused512Chain20x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain20x1GprAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 20))
}

// Fused512Chain36x4 runs the width-512 cascade on four 36-byte lanes.
func Fused512Chain36x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain36x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 36, out)
}

// Fused512Chain36x1 runs the width-512 cascade on one 36-byte lane
// through the four-lane kernel with the lane replicated.
func Fused512Chain36x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain36x1GprAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 36))
}

// Fused512Chain68x4 runs the width-512 cascade on four 68-byte lanes.
func Fused512Chain68x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain68x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 68, out)
}

// Fused512Chain68x1 runs the width-512 cascade on one 68-byte lane
// through the four-lane kernel with the lane replicated.
func Fused512Chain68x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasNEON && validComponents512(components) {
		blake2b512FusedChain68x1GprAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 68))
}

// Fused256Fill13x8 is the batch-16 Interlocked Barrier fill hook of
// width 256 on the NEON tier: two four-lane kernel calls over
// Go-synthesised fill blocks.
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	if !HasNEONX16 || !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/4
	var blocks [4][13]byte
	for h := 0; h < 2; h++ {
		ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
		blake2b256FusedChain13x4NeonAsm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
	}
}

// Fused512Fill13x4 is the batch-16 Interlocked Barrier fill hook of
// width 512 on the NEON tier: one four-lane kernel call over
// Go-synthesised fill blocks.
func Fused512Fill13x4(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[4][8]uint64) {
	if !HasNEONX16 || !validComponents512(components) {
		scalarFill512X4(fixedKey, components, groupIdxBase, out)
		return
	}
	var blocks [4][13]byte
	ptrs := fillPtrs4(&blocks, groupIdxBase)
	blake2b512FusedChain13x4NeonAsm(fixedKey, &components[0], len(components)/8, &ptrs, out)
}

// Kernels (blake2b_fusedchain{256,512}_<shape>x4_neon_arm64.s).
//
//go:noescape
func blake2b256FusedChain13x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2b256FusedChain20x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2b256FusedChain36x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2b256FusedChain68x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func blake2b512FusedChain13x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func blake2b512FusedChain20x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func blake2b512FusedChain36x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func blake2b512FusedChain68x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

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
func Fused512Chain20x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	Fused512Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x512Half(out, 0))
	Fused512Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x512Half(out, 1))
}
func Fused512Chain36x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	Fused512Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x512Half(out, 0))
	Fused512Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x512Half(out, 1))
}
func Fused512Chain68x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	Fused512Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x512Half(out, 0))
	Fused512Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x512Half(out, 1))
}

// Fused512Fill13x8 is the batch-32 Interlocked Barrier fill hook of
// width 512 on the NEON tier: two four-lane kernel calls over
// Go-synthesised fill blocks.
func Fused512Fill13x8(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[8][8]uint64) {
	if !HasNEONX16 || !validComponents512(components) {
		scalarFill512X8(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/8
	var blocks [4][13]byte
	for h := 0; h < 2; h++ {
		ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
		blake2b512FusedChain13x4NeonAsm(fixedKey, c, ng, &ptrs, out8x512Half(out, h))
	}
}

// Single-lane kernels (blake2b_fusedchain{256,512}_<shape>x1_gpr_arm64.s).
//
//go:noescape
func blake2b256FusedChain13x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2b256FusedChain20x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2b256FusedChain36x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2b256FusedChain68x1GprAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func blake2b512FusedChain13x1GprAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func blake2b512FusedChain20x1GprAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func blake2b512FusedChain36x1GprAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func blake2b512FusedChain68x1GprAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)
