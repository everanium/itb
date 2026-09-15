//go:build amd64 && !purego && !noitbasm

package aescmacasm

import aes "github.com/jedisct1/go-aes"

// Fused-cascade tier flags. The fused kernels amortise lane gather,
// staging and the round-key broadcast over every cascade round; the
// forcetier init keeps the fused-cascade and batch-16 fill flag
// families mutually consistent. At most one flag in this family is
// true.
//
// Auto-selection takes the widest VAES tier the host offers: ZMM, then
// YMM, then the VEX-encoded XMM kernels, then legacy-SSE. Every tier
// stays built and is reachable through ITB_FORCE_HASH_TIER.
var (
	// FusedHasVAESAVX512 selects the ZMM fused kernels (four lanes in
	// one register). Needs VAES + AVX-512.
	FusedHasVAESAVX512 = aes.CPU.HasVAES && aes.CPU.HasAVX512

	// FusedHasVAESAVX2 selects the YMM fused kernels (two lanes per
	// register). Needs VAES + AVX2; yields to the ZMM tier.
	FusedHasVAESAVX2 = aes.CPU.HasVAES && aes.CPU.HasAVX2 && !FusedHasVAESAVX512

	// FusedHasAVXAESNI selects the VEX-encoded XMM fused kernels.
	// Needs AES-NI + AVX (AVX2 used as the detection superset); yields
	// to both VAES tiers.
	FusedHasAVXAESNI = aes.CPU.HasAESNI && aes.CPU.HasAVX2 && !FusedHasVAESAVX512 && !FusedHasVAESAVX2

	// FusedHasAESNI selects the legacy-SSE XMM fused kernels on AES-NI
	// hosts without AVX.
	FusedHasAESNI = aes.CPU.HasAESNI && !aes.CPU.HasAVX2

	// FusedHasARMAES is always false on amd64 builds.
	FusedHasARMAES = false
)

// FusedAvailable reports whether any assembly tier of the fused cascade
// family is selected.
func FusedAvailable() bool {
	return FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAVXAESNI || FusedHasAESNI
}

// The single-lane kernels exist in the two XMM encodings only; the wide
// tiers route their single-lane calls to the VEX kernel.
func fusedSingleVex() bool { return FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAVXAESNI }

// FusedChain13x4 runs the cascade on four 13-byte lanes.
func FusedChain13x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(s, components, dataPtrs, 13, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesCMAC128FusedChain13x4Avx512Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesCMAC128FusedChain13x4VaesAvx2Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesCMAC128FusedChain13x4VexAsm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain13x4AesNiAsm(&s.roundKeys, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(s, components, dataPtrs, 13, out)
	}
}

// FusedChain20x4 runs the cascade on four 20-byte lanes.
func FusedChain20x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(s, components, dataPtrs, 20, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesCMAC128FusedChain20x4Avx512Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesCMAC128FusedChain20x4VaesAvx2Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesCMAC128FusedChain20x4VexAsm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain20x4AesNiAsm(&s.roundKeys, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(s, components, dataPtrs, 20, out)
	}
}

// FusedChain36x4 runs the cascade on four 36-byte lanes.
func FusedChain36x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(s, components, dataPtrs, 36, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesCMAC128FusedChain36x4Avx512Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesCMAC128FusedChain36x4VaesAvx2Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesCMAC128FusedChain36x4VexAsm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain36x4AesNiAsm(&s.roundKeys, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(s, components, dataPtrs, 36, out)
	}
}

// FusedChain68x4 runs the cascade on four 68-byte lanes.
func FusedChain68x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(s, components, dataPtrs, 68, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesCMAC128FusedChain68x4Avx512Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesCMAC128FusedChain68x4VaesAvx2Asm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesCMAC128FusedChain68x4VexAsm(&s.roundKeys, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain68x4AesNiAsm(&s.roundKeys, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(s, components, dataPtrs, 68, out)
	}
}

// FusedChain13x1 runs the cascade on one 13-byte input.
func FusedChain13x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(s, components, data, 13, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesCMAC128FusedChain13x1VexAsm(&s.roundKeys, c, n, data, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain13x1AesNiAsm(&s.roundKeys, c, n, data, out)
	default:
		scalarFusedSingle(s, components, data, 13, out)
	}
}

// FusedChain20x1 runs the cascade on one 20-byte input.
func FusedChain20x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(s, components, data, 20, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesCMAC128FusedChain20x1VexAsm(&s.roundKeys, c, n, data, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain20x1AesNiAsm(&s.roundKeys, c, n, data, out)
	default:
		scalarFusedSingle(s, components, data, 20, out)
	}
}

// FusedChain36x1 runs the cascade on one 36-byte input.
func FusedChain36x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(s, components, data, 36, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesCMAC128FusedChain36x1VexAsm(&s.roundKeys, c, n, data, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain36x1AesNiAsm(&s.roundKeys, c, n, data, out)
	default:
		scalarFusedSingle(s, components, data, 36, out)
	}
}

// FusedChain68x1 runs the cascade on one 68-byte input.
func FusedChain68x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(s, components, data, 68, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesCMAC128FusedChain68x1VexAsm(&s.roundKeys, c, n, data, out)
	case FusedHasAESNI:
		aesCMAC128FusedChain68x1AesNiAsm(&s.roundKeys, c, n, data, out)
	default:
		scalarFusedSingle(s, components, data, 68, out)
	}
}

// Four-lane fused kernels (aescmac_fusedchain128_<shape>x4_<tier>_amd64.s).
//
//go:noescape
func aesCMAC128FusedChain13x4AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x4AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x4AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x4AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x4VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x4VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x4VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x4VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x4VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x4VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x4VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x4VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x4Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x4Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x4Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x4Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

// Single-lane fused kernels (aescmac_fusedchain128_<shape>x1_<tier>_amd64.s).
//
//go:noescape
func aesCMAC128FusedChain13x1AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain20x1AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain36x1AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain68x1AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain13x1VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain20x1VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain36x1VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain68x1VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

// FusedChain13x16 runs the cascade on the 16 lanes of the Interlocked
// Barrier fill: lane i carries the 13-byte fill block
// [0x03 | LE64(groupIdxBase+i) | 4×0x00], synthesised in-register by
// the kernel, and every lane runs the whole cascade over components.
// The dispatch follows the batch-16 tier flags (HasVAESAVX512X16 and
// siblings, the widest VAES tier the host offers) rather than the fused
// x1 / x4 flags, so ITB_FORCE_INTERLOCK_PRF_FILL_TIER selects the arm.
func FusedChain13x16(s *Schedule, components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if !validComponents(components) {
		scalarFusedX16(s, components, groupIdxBase, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case HasVAESAVX512X16:
		aesCMAC128FusedChain13x16Avx512Asm(&s.roundKeys, c, n, groupIdxBase, out)
	case HasVAESAVX2X16:
		aesCMAC128FusedChain13x16VaesAvx2Asm(&s.roundKeys, c, n, groupIdxBase, out)
	case HasAVXAESNIX16:
		aesCMAC128FusedChain13x16VexAsm(&s.roundKeys, c, n, groupIdxBase, out)
	case HasAESNIX16:
		aesCMAC128FusedChain13x16AesNiAsm(&s.roundKeys, c, n, groupIdxBase, out)
	default:
		scalarFusedX16(s, components, groupIdxBase, out)
	}
}

// Sixteen-lane fused fill kernels (aescmac_fusedchain128_13x16_<tier>_amd64.s).
//
//go:noescape
func aesCMAC128FusedChain13x16AesNiAsm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x16VexAsm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x16VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x16Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
