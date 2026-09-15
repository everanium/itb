//go:build arm64 && !purego && !noitbasm

package areionasm

import aes "github.com/jedisct1/go-aes"

var (
	// FusedHasARMAES selects the NEON fused kernels on arm64 hosts that
	// carry the AES crypto extension; the pure-Go cascade runs on cores
	// without it. The batch-16 fill arms are gated separately through
	// HasARMAESX16.
	FusedHasARMAES = aes.CPU.HasARMCrypto

	FusedHasVAESAVX512 = false
	FusedHasVAESAVX2   = false
	FusedHasAESNI      = false
)

// Batch-16 / batch-32 fill tier flag of the NEON arm: the width-256
// batch-16 hook and the width-512 batch-32 hook run the eight-lane NEON
// fill kernels (blocks synthesised in the frame), the width-512
// batch-16 hook a four-lane kernel call over Go-synthesised blocks.
var (
	HasARMAESX16     = aes.CPU.HasARMCrypto
	HasVAESAVX512X16 = false
	HasVAESAVX2X16   = false
	HasAESNIX16      = false
)

// FusedAvailable reports whether the NEON fused cascade tier is selected.
func FusedAvailable() bool { return FusedHasARMAES }

func Fused256Chain13x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain13x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
}
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain13x1NeonAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 13))
}

func Fused256Chain20x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain20x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
}
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain20x1NeonAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 20))
}

func Fused256Chain36x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain36x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
}
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain36x1NeonAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 36))
}

func Fused256Chain68x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain68x4NeonAsm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
}
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedHasARMAES && validComponents256(components) {
		areion256FusedChain68x1NeonAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 68))
}

func Fused512Chain13x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain13x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 13, out)
}
func Fused512Chain13x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain13x1NeonAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 13))
}

func Fused512Chain20x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain20x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 20, out)
}
func Fused512Chain20x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain20x1NeonAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 20))
}

func Fused512Chain36x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain36x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 36, out)
}
func Fused512Chain36x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain36x1NeonAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 36))
}

func Fused512Chain68x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain68x4NeonAsm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	scalarFused512X4(fixedKey, components, dataPtrs, 68, out)
}
func Fused512Chain68x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedHasARMAES && validComponents512(components) {
		areion512FusedChain68x1NeonAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 68))
}

// Fused256Fill13x8 runs the width-256 batch-16 fill through the
// eight-lane NEON kernel (four lanes per pass, two passes, fill blocks
// synthesised in the frame).
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	if !HasARMAESX16 || !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
		return
	}
	areion256FusedChain13x8NeonAsm(fixedKey, &components[0], len(components)/4, groupIdxBase, out)
}

// Fused512Fill13x4 runs the width-512 batch-16 fill as one four-lane
// NEON kernel call over Go-synthesised fill blocks.
func Fused512Fill13x4(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[4][8]uint64) {
	if !HasARMAESX16 || !validComponents512(components) {
		scalarFill512X4(fixedKey, components, groupIdxBase, out)
		return
	}
	var blocks [4][13]byte
	ptrs := fillPtrs4(&blocks, groupIdxBase)
	areion512FusedChain13x4NeonAsm(fixedKey, &components[0], len(components)/8, &ptrs, out)
}

// Kernels (areion_fusedchain{256,512}_<shape>x{4,1}_neon_arm64.s).
//
//go:noescape
func areion256FusedChain13x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain13x1NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion256FusedChain20x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain20x1NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion256FusedChain36x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain36x1NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion256FusedChain68x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain68x1NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion512FusedChain13x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain13x1NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion512FusedChain20x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain20x1NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion512FusedChain36x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain36x1NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion512FusedChain68x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain68x1NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

// Eight-lane per-pixel arm: no NEON eight-lane per-pixel kernel exists;
// the eight-lane dispatchers run two four-lane NEON calls.
var FusedHasVAESAVX512X8 = false

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

// Fused512Fill13x8 runs the width-512 batch-32 fill through the
// eight-lane NEON kernel (two lanes per pass, four passes, fill blocks
// synthesised in the frame).
func Fused512Fill13x8(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[8][8]uint64) {
	if !HasARMAESX16 || !validComponents512(components) {
		scalarFill512X8(fixedKey, components, groupIdxBase, out)
		return
	}
	areion512FusedChain13x8NeonAsm(fixedKey, &components[0], len(components)/8, groupIdxBase, out)
}

// Eight-lane fill kernels (areion_fusedchain{256,512}_13x8_neon_arm64.s).
//
//go:noescape
func areion256FusedChain13x8NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][4]uint64)

//go:noescape
func areion512FusedChain13x8NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][8]uint64)
