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

// Batch-16 fill tier flag of the NEON arm: the fill hooks run four-lane
// NEON kernel calls over Go-synthesised fill blocks.
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

// Fused256Fill13x8 runs the width-256 batch-16 fill as two four-lane
// NEON kernel calls over Go-synthesised fill blocks.
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	if !HasARMAESX16 || !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/4
	var blocks [4][13]byte
	for h := 0; h < 2; h++ {
		ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
		areion256FusedChain13x4NeonAsm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
	}
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
