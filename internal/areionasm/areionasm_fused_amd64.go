//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// Fused-cascade tier flags of the Areion-SoEM kernels. At most one flag
// of the family is true; auto-selection takes the widest tier the host
// offers — ZMM (VAES + AVX-512), then YMM (VAES + AVX2), then 3-operand
// VEX XMM (AVX2 + AES-NI), then legacy-SSE AES-NI XMM kernels. The
// forcetier init keeps this family and the batch-16 fill family
// consistent with the chain-absorb arm flags.
var (
	// FusedHasVAESAVX512 selects the ZMM fused kernels (four lanes per
	// register). Needs VAES + AVX-512.
	FusedHasVAESAVX512 = cpuid.VAESZMM

	// FusedHasVAESAVX2 selects the YMM fused kernels (two lanes per
	// pass). Needs VAES + AVX2; yields to the ZMM tier.
	FusedHasVAESAVX2 = cpuid.VAESYMM && !cpuid.AVX512F

	// FusedHasAVXAESNI selects the 3-operand VEX XMM fused kernels on
	// hosts with AVX2 + AES-NI but without VAES.
	FusedHasAVXAESNI = cpuid.AESNI && cpuid.AVX2 && !FusedHasVAESAVX512 && !FusedHasVAESAVX2

	// FusedHasAESNI selects the legacy-SSE XMM AES-NI fused kernels on
	// hosts without AVX2 or VAES.
	FusedHasAESNI = cpuid.AESNI && !FusedHasVAESAVX512 && !FusedHasVAESAVX2 && !FusedHasAVXAESNI

	// FusedHasARMAES is always false on amd64 builds.
	FusedHasARMAES = false
)

// Fill tier flags: the tier of the Interlocked Barrier fill hooks
// (Fused256Fill13x8 / Fused512Fill13x4 / Fused512Fill13x8), overridable
// on their own through ITB_FORCE_INTERLOCK_PRF_FILL_TIER.
var (
	HasVAESAVX512X16 = cpuid.VAESZMM
	HasVAESAVX2X16   = cpuid.VAESYMM && !cpuid.AVX512F
	HasAVXAESNIX16   = cpuid.AESNI && cpuid.AVX2 && !HasVAESAVX512X16 && !HasVAESAVX2X16
	HasAESNIX16      = cpuid.AESNI && !HasVAESAVX512X16 && !HasVAESAVX2X16 && !HasAVXAESNIX16
	HasARMAESX16     = false
)

// FusedAvailable reports whether any assembly tier of the fused cascade
// family is selected.
func FusedAvailable() bool {
	return FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAVXAESNI || FusedHasAESNI
}

func fusedSingleVex() bool {
	return FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAVXAESNI
}

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
	case FusedHasAVXAESNI:
		areion256FusedChain13x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain13x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
	}
}

// Fused256Chain13x1 runs the width-256 cascade on one 13-byte lane.
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if validComponents256(components) {
		c, ng := &components[0], len(components)/4
		switch {
		case fusedSingleVex():
			areion256FusedChain13x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion256FusedChain13x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion256FusedChain20x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain20x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
	}
}

// Fused256Chain20x1 runs the width-256 cascade on one 20-byte lane.
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if validComponents256(components) {
		c, ng := &components[0], len(components)/4
		switch {
		case fusedSingleVex():
			areion256FusedChain20x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion256FusedChain20x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion256FusedChain36x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain36x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
	}
}

// Fused256Chain36x1 runs the width-256 cascade on one 36-byte lane.
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if validComponents256(components) {
		c, ng := &components[0], len(components)/4
		switch {
		case fusedSingleVex():
			areion256FusedChain36x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion256FusedChain36x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion256FusedChain68x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion256FusedChain68x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
	}
}

// Fused256Chain68x1 runs the width-256 cascade on one 68-byte lane.
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	if validComponents256(components) {
		c, ng := &components[0], len(components)/4
		switch {
		case fusedSingleVex():
			areion256FusedChain68x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion256FusedChain68x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion512FusedChain13x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain13x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 13, out)
	}
}

// Fused512Chain13x1 runs the width-512 cascade on one 13-byte lane.
func Fused512Chain13x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if validComponents512(components) {
		c, ng := &components[0], len(components)/8
		switch {
		case fusedSingleVex():
			areion512FusedChain13x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion512FusedChain13x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion512FusedChain20x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain20x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 20, out)
	}
}

// Fused512Chain20x1 runs the width-512 cascade on one 20-byte lane.
func Fused512Chain20x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if validComponents512(components) {
		c, ng := &components[0], len(components)/8
		switch {
		case fusedSingleVex():
			areion512FusedChain20x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion512FusedChain20x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion512FusedChain36x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain36x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 36, out)
	}
}

// Fused512Chain36x1 runs the width-512 cascade on one 36-byte lane.
func Fused512Chain36x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if validComponents512(components) {
		c, ng := &components[0], len(components)/8
		switch {
		case fusedSingleVex():
			areion512FusedChain36x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion512FusedChain36x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
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
	case FusedHasAVXAESNI:
		areion512FusedChain68x4VexAsm(fixedKey, c, ng, dataPtrs, out)
	case FusedHasAESNI:
		areion512FusedChain68x4AesNiAsm(fixedKey, c, ng, dataPtrs, out)
	default:
		scalarFused512X4(fixedKey, components, dataPtrs, 68, out)
	}
}

// Fused512Chain68x1 runs the width-512 cascade on one 68-byte lane.
func Fused512Chain68x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	if validComponents512(components) {
		c, ng := &components[0], len(components)/8
		switch {
		case fusedSingleVex():
			areion512FusedChain68x1VexAsm(fixedKey, c, ng, data, out)
			return
		case FusedHasAESNI:
			areion512FusedChain68x1AesNiAsm(fixedKey, c, ng, data, out)
			return
		}
	}
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 68))
}

// Fused256Fill13x8 is the batch-16 Interlocked Barrier fill hook of
// width 256: lane i (0..7) runs the cascade over the fill block
// [0x03 | LE64(groupIdxBase+i) | LE32(v)] of group groupIdxBase+i, v
// being the per-message interlock-nonce fold.
func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, v uint32, out *[8][4]uint64) {
	if !validComponents256(components) {
		scalarFill256X8(fixedKey, components, groupIdxBase, v, out)
		return
	}
	c, ng := &components[0], len(components)/4
	switch {
	case HasVAESAVX512X16:
		areion256FusedChain13x8Avx512Asm(fixedKey, c, ng, groupIdxBase, out, v)
	case HasVAESAVX2X16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h), v)
			areion256FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
		}
	case HasAVXAESNIX16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h), v)
			areion256FusedChain13x4VexAsm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
		}
	case HasAESNIX16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h), v)
			areion256FusedChain13x4AesNiAsm(fixedKey, c, ng, &ptrs, (*[4][4]uint64)(out[4*h:4*h+4]))
		}
	default:
		scalarFill256X8(fixedKey, components, groupIdxBase, v, out)
	}
}

// Fused512Fill13x4 is the batch-16 Interlocked Barrier fill hook of
// width 512: lane i (0..3) runs the cascade over the fill block
// [0x03 | LE64(groupIdxBase+i) | LE32(v)] of group groupIdxBase+i, one
// four-lane kernel call over Go-synthesised blocks on every tier.
func Fused512Fill13x4(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, v uint32, out *[4][8]uint64) {
	if !validComponents512(components) {
		scalarFill512X4(fixedKey, components, groupIdxBase, v, out)
		return
	}
	c, ng := &components[0], len(components)/8
	var blocks [4][13]byte
	ptrs := fillPtrs4(&blocks, groupIdxBase, v)
	switch {
	case HasVAESAVX512X16:
		areion512FusedChain13x4Avx512Asm(fixedKey, c, ng, &ptrs, out)
	case HasVAESAVX2X16:
		areion512FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, &ptrs, out)
	case HasAVXAESNIX16:
		areion512FusedChain13x4VexAsm(fixedKey, c, ng, &ptrs, out)
	case HasAESNIX16:
		areion512FusedChain13x4AesNiAsm(fixedKey, c, ng, &ptrs, out)
	default:
		scalarFill512X4(fixedKey, components, groupIdxBase, v, out)
	}
}

// Kernels (areion_fusedchain{256,512}_<shape>x{4,1}_<tier>_amd64.s).
//
//go:noescape
func areion256FusedChain13x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain13x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain13x4VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain13x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain13x1VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain13x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain20x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain20x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain20x4VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain20x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain20x1VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain20x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain36x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain36x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain36x4VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain36x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain36x1VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain36x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain68x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain68x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain68x4VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain68x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func areion256FusedChain68x1VexAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion256FusedChain68x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)

//go:noescape
func areion512FusedChain13x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain13x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain13x4VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain13x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain13x1VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain13x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain20x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain20x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain20x4VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain20x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain20x1VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain20x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain36x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain36x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain36x4VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain36x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain36x1VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain36x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain68x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain68x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain68x4VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain68x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)

//go:noescape
func areion512FusedChain68x1VexAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion512FusedChain68x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)

//go:noescape
func areion256FusedChain13x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][4]uint64, v uint32)

// FusedHasVAESAVX512X8 arms the eight-lane ZMM per-pixel kernels
// (Fused{256,512}Chain{20,36,68}x8: two four-lane groups with
// interleaved round streams). Needs VAES + AVX-512; cleared at init by
// ITB_FORCE_CHAINHASH_X4 so a parity or benchmark run can pin the
// four-lane kernels on a host that would otherwise select x8.
var FusedHasVAESAVX512X8 = cpuid.VAESZMM && !forcetier.ChainHashX4()

// FusedHasAESNIX8 arms the eight-lane per-pixel arm of the VAES YMM,
// VEX XMM and AES-NI XMM tiers: two calls of the tier's four-lane
// kernel on the lane halves.
var FusedHasAESNIX8 = cpuid.AESNI && !forcetier.ChainHashX4()

// FusedX8Active reports whether an eight-lane per-pixel arm is the
// selected arm.
func FusedX8Active() bool {
	return (FusedHasVAESAVX512X8 && FusedHasVAESAVX512) || (FusedHasAESNIX8 && (FusedHasVAESAVX2 || FusedHasAVXAESNI || FusedHasAESNI))
}

// Fused256Chain20x8 runs the width-256 cascade on eight 20-byte lanes.
func Fused256Chain20x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	if FusedHasVAESAVX512X8 && FusedHasVAESAVX512 && validComponents256(components) {
		areion256FusedChain20x8Avx512Asm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	Fused256Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Fused256Chain36x8 runs the width-256 cascade on eight 36-byte lanes.
func Fused256Chain36x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	if FusedHasVAESAVX512X8 && FusedHasVAESAVX512 && validComponents256(components) {
		areion256FusedChain36x8Avx512Asm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	Fused256Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Fused256Chain68x8 runs the width-256 cascade on eight 68-byte lanes.
func Fused256Chain68x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	if FusedHasVAESAVX512X8 && FusedHasVAESAVX512 && validComponents256(components) {
		areion256FusedChain68x8Avx512Asm(fixedKey, &components[0], len(components)/4, dataPtrs, out)
		return
	}
	Fused256Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x256Half(out, 0))
	Fused256Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x256Half(out, 1))
}

// Fused512Chain20x8 runs the width-512 cascade on eight 20-byte lanes.
func Fused512Chain20x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	if FusedHasVAESAVX512X8 && FusedHasVAESAVX512 && validComponents512(components) {
		areion512FusedChain20x8Avx512Asm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	Fused512Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x512Half(out, 0))
	Fused512Chain20x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x512Half(out, 1))
}

// Fused512Chain36x8 runs the width-512 cascade on eight 36-byte lanes.
func Fused512Chain36x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	if FusedHasVAESAVX512X8 && FusedHasVAESAVX512 && validComponents512(components) {
		areion512FusedChain36x8Avx512Asm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	Fused512Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x512Half(out, 0))
	Fused512Chain36x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x512Half(out, 1))
}

// Fused512Chain68x8 runs the width-512 cascade on eight 68-byte lanes.
func Fused512Chain68x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	if FusedHasVAESAVX512X8 && FusedHasVAESAVX512 && validComponents512(components) {
		areion512FusedChain68x8Avx512Asm(fixedKey, &components[0], len(components)/8, dataPtrs, out)
		return
	}
	Fused512Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 0), out8x512Half(out, 0))
	Fused512Chain68x4(fixedKey, components, ptrs8Half(dataPtrs, 1), out8x512Half(out, 1))
}

// Fused512Fill13x8 is the batch-32 Interlocked Barrier fill hook of
// width 512: lane i (0..7) runs the cascade over the fill block
// [0x03 | LE64(groupIdxBase+i) | LE32(v)] of group groupIdxBase+i, v
// being the per-message interlock-nonce fold.
func Fused512Fill13x8(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, v uint32, out *[8][8]uint64) {
	if !validComponents512(components) {
		scalarFill512X8(fixedKey, components, groupIdxBase, v, out)
		return
	}
	c, ng := &components[0], len(components)/8
	switch {
	case HasVAESAVX512X16:
		areion512FusedChain13x8Avx512Asm(fixedKey, c, ng, groupIdxBase, out, v)
	case HasVAESAVX2X16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h), v)
			areion512FusedChain13x4VaesAvx2Asm(fixedKey, c, ng, &ptrs, out8x512Half(out, h))
		}
	case HasAVXAESNIX16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h), v)
			areion512FusedChain13x4VexAsm(fixedKey, c, ng, &ptrs, out8x512Half(out, h))
		}
	case HasAESNIX16:
		var blocks [4][13]byte
		for h := 0; h < 2; h++ {
			ptrs := fillPtrs4(&blocks, groupIdxBase+uint64(4*h), v)
			areion512FusedChain13x4AesNiAsm(fixedKey, c, ng, &ptrs, out8x512Half(out, h))
		}
	default:
		scalarFill512X8(fixedKey, components, groupIdxBase, v, out)
	}
}

// Wide kernels (areion_fusedchain{256,512}_<shape>x8_avx512_amd64.s).
//
//go:noescape
func areion256FusedChain20x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][4]uint64)

//go:noescape
func areion256FusedChain36x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][4]uint64)

//go:noescape
func areion256FusedChain68x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][4]uint64)

//go:noescape
func areion512FusedChain20x8Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][8]uint64)

//go:noescape
func areion512FusedChain36x8Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][8]uint64)

//go:noescape
func areion512FusedChain68x8Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[8]*byte, out *[8][8]uint64)

//go:noescape
func areion512FusedChain13x8Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][8]uint64, v uint32)
