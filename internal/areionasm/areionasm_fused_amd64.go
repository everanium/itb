//go:build amd64 && !purego && !noitbasm

package areionasm

import aes "github.com/jedisct1/go-aes"

// Fused-cascade tier flags of the Areion-SoEM kernels. At most one flag
// of the family is true; auto-selection takes the widest VAES tier the
// host offers — ZMM, then YMM, then the legacy-SSE AES-NI XMM kernels
// (the single-lane arm of every tier, and the four-lane arm of AES-NI
// hosts without VAES). The forcetier init keeps this family and the
// batch-16 fill family consistent with the chain-absorb arm flags.
var (
	// FusedHasVAESAVX512 selects the ZMM fused kernels (four lanes per
	// register). Needs VAES + AVX-512.
	FusedHasVAESAVX512 = aes.CPU.HasVAES && aes.CPU.HasAVX512

	// FusedHasVAESAVX2 selects the YMM fused kernels (two lanes per
	// pass). Needs VAES + AVX2; yields to the ZMM tier.
	FusedHasVAESAVX2 = aes.CPU.HasVAES && aes.CPU.HasAVX2 && !aes.CPU.HasAVX512

	// FusedHasAESNI selects the XMM AES-NI fused kernels on hosts
	// without VAES.
	FusedHasAESNI = aes.CPU.HasAESNI && !aes.CPU.HasVAES

	// FusedHasARMAES is always false on amd64 builds.
	FusedHasARMAES = false
)

// Batch-16 fill tier flags: the tier of the Interlocked Barrier fill
// hooks (Fused256Fill13x8 / Fused512Fill13x4), overridable on their own
// through ITB_FORCE_INTERLOCK_PRF_FILL_TIER. The ZMM tier of width 256
// runs the dedicated eight-lane kernel; every other arm runs four-lane
// kernel calls over Go-synthesised fill blocks.
var (
	HasVAESAVX512X16 = aes.CPU.HasVAES && aes.CPU.HasAVX512
	HasVAESAVX2X16   = aes.CPU.HasVAES && aes.CPU.HasAVX2 && !aes.CPU.HasAVX512
	HasAESNIX16      = aes.CPU.HasAESNI && !aes.CPU.HasVAES
	HasARMAESX16     = false
)

// FusedAvailable reports whether any assembly tier of the fused cascade
// family is selected.
func FusedAvailable() bool { return FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAESNI }

// Fused256Chain13x4 runs the width-256 cascade on four 13-byte lanes.
func Fused256Chain13x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasVAESAVX512:
		areion256FusedChain13x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion256FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain13x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
	}
}

// Fused256Chain13x1 runs the width-256 cascade on one 13-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		areion256FusedChain13x1AesNiAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 13))
}

// Fused256Chain20x4 runs the width-256 cascade on four 20-byte lanes.
func Fused256Chain20x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasVAESAVX512:
		areion256FusedChain20x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion256FusedChain20x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain20x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
	}
}

// Fused256Chain20x1 runs the width-256 cascade on one 20-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		areion256FusedChain20x1AesNiAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 20))
}

// Fused256Chain36x4 runs the width-256 cascade on four 36-byte lanes.
func Fused256Chain36x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasVAESAVX512:
		areion256FusedChain36x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion256FusedChain36x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain36x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
	}
}

// Fused256Chain36x1 runs the width-256 cascade on one 36-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		areion256FusedChain36x1AesNiAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 36))
}

// Fused256Chain68x4 runs the width-256 cascade on four 68-byte lanes.
func Fused256Chain68x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	if !validComponents256(components) {
		scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case FusedHasVAESAVX512:
		areion256FusedChain68x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion256FusedChain68x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain68x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
	}
}

// Fused256Chain68x1 runs the width-256 cascade on one 68-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if FusedAvailable() && validComponents256(components) {
		areion256FusedChain68x1AesNiAsm(fixedKey, &components[0], len(components)/4, data, out)
		return
	}
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 68))
}

// Fused512Chain13x4 runs the width-512 cascade on four 13-byte lanes.
func Fused512Chain13x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if !validComponents512(components) {
		scalarFused512X4(fixedKey, components, dataPtrs, 13, out)
		return
	}
	c, ng := &components[0], len(components)/8
	switch {
	case FusedHasVAESAVX512:
		areion512FusedChain13x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion512FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain13x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 13, out)
	}
}

// Fused512Chain13x1 runs the width-512 cascade on one 13-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused512Chain13x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedAvailable() && validComponents512(components) {
		areion512FusedChain13x1AesNiAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 13))
}

// Fused512Chain20x4 runs the width-512 cascade on four 20-byte lanes.
func Fused512Chain20x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if !validComponents512(components) {
		scalarFused512X4(fixedKey, components, dataPtrs, 20, out)
		return
	}
	c, ng := &components[0], len(components)/8
	switch {
	case FusedHasVAESAVX512:
		areion512FusedChain20x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion512FusedChain20x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain20x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 20, out)
	}
}

// Fused512Chain20x1 runs the width-512 cascade on one 20-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused512Chain20x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedAvailable() && validComponents512(components) {
		areion512FusedChain20x1AesNiAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 20))
}

// Fused512Chain36x4 runs the width-512 cascade on four 36-byte lanes.
func Fused512Chain36x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if !validComponents512(components) {
		scalarFused512X4(fixedKey, components, dataPtrs, 36, out)
		return
	}
	c, ng := &components[0], len(components)/8
	switch {
	case FusedHasVAESAVX512:
		areion512FusedChain36x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion512FusedChain36x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain36x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 36, out)
	}
}

// Fused512Chain36x1 runs the width-512 cascade on one 36-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused512Chain36x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedAvailable() && validComponents512(components) {
		areion512FusedChain36x1AesNiAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 36))
}

// Fused512Chain68x4 runs the width-512 cascade on four 68-byte lanes.
func Fused512Chain68x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	if !validComponents512(components) {
		scalarFused512X4(fixedKey, components, dataPtrs, 68, out)
		return
	}
	c, ng := &components[0], len(components)/8
	switch {
	case FusedHasVAESAVX512:
		areion512FusedChain68x4Avx512Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasVAESAVX2:
		areion512FusedChain68x4VaesAvx2Asm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain68x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 68, out)
	}
}

// Fused512Chain68x1 runs the width-512 cascade on one 68-byte lane
// through the XMM AES-NI kernel, the single-lane arm of every tier.
func Fused512Chain68x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if FusedAvailable() && validComponents512(components) {
		areion512FusedChain68x1AesNiAsm(fixedKey, &components[0], len(components)/8, data, out)
		return
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 68))
}

// Fused256Fill13x8 is the batch-16 Interlocked Barrier fill hook of
// width 256: lane i (0..7) runs the cascade over the fill block of group
// groupIdxBase+i. The ZMM tier synthesises the blocks in-register and
// runs two interleaved four-lane groups; the YMM and XMM tiers run two
// four-lane kernel calls over Go-synthesised blocks. The dispatch
// follows the batch-16 flags so ITB_FORCE_INTERLOCK_PRF_FILL_TIER selects
// the arm.
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	if !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case HasVAESAVX512X16:
		areion256FusedChain13x8Avx512Asm(fixedKey, c, ng, groupIdxBase, out)
	case HasVAESAVX2X16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
			areion256FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
		}
	case HasAESNIX16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h))
			areion256FusedChain13x4AesNiAsm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
		}
	default:
		scalarFill256X8(fixedKey, components, groupIdxBase, out)
	}
}

// Fused512Fill13x4 is the batch-16 Interlocked Barrier fill hook of
// width 512: lane i (0..3) runs the cascade over the fill block of group
// groupIdxBase+i, one four-lane kernel call over Go-synthesised blocks
// on every tier.
func Fused512Fill13x4(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[4][8]uint64) {
	if !validComponents512(components) {
		scalarFill512X4(fixedKey, components, groupIdxBase, out)
		return
	}
	c, ng := &components[0], len(components)/8
	var blocks [4][13]byte
	ptrs := fillPtrs4(&blocks, groupIdxBase)
	switch {
	case HasVAESAVX512X16:
		areion512FusedChain13x4Avx512Asm(fixedKey, c, ng, &ptrs, out)
	case HasVAESAVX2X16:
		areion512FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, &ptrs, out)
	case HasAESNIX16:
		areion512FusedChain13x4AesNiAsm(fixedKey, c, ng, &ptrs, out)
	default:
		scalarFill512X4(fixedKey, components, groupIdxBase, out)
	}
}

// Kernels (areion_fusedchain{256,512}_<shape>x{4,1}_<tier>_amd64.s).
//
//go:noescape
func areion256FusedChain13x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain13x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain13x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain13x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion256FusedChain20x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain20x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain20x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain20x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion256FusedChain36x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain36x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain36x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain36x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion256FusedChain68x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain68x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain68x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//
//go:noescape
func areion256FusedChain68x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//
//go:noescape
func areion512FusedChain13x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain13x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain13x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain13x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion512FusedChain20x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain20x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain20x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain20x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion512FusedChain36x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain36x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain36x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain36x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion512FusedChain68x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain68x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain68x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//
//go:noescape
func areion512FusedChain68x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//
//go:noescape
func areion256FusedChain13x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][4]uint64)
