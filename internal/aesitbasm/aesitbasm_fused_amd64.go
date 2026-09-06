//go:build amd64 && !purego && !noitbasm

package aesitbasm

import aes "github.com/jedisct1/go-aes"

// Fused-cascade tier flags. The fused kernels amortise lane gather and
// staging over every cascade round, so their tier ranking is measured
// separately from the per-round kernels; the forcetier init sets both
// flag families as one consistent set. At most one flag is true.
//
// Auto-selection takes the widest VAES tier the host offers: ZMM, then
// YMM, then the VEX-encoded XMM kernels, then legacy-SSE. Under the
// production call pattern (BenchmarkFusedTierPix: a 4-byte pixel-index
// store into every lane buffer immediately ahead of the call) the ZMM
// fused kernels run 1.6–1.7× and the YMM kernels 1.25–1.4× the XMM
// throughput at the 512-bit nonce shape (shape 68, 8 component pairs)
// on Rocket Lake and Sapphire Rapids, and 1.26× / 1.19× on Zen 4, where
// the two VAES tiers trade places by shape (YMM ahead at 4 component
// pairs, ZMM at 8) and both lead XMM by 13–35 % across the measured
// shape / pair cells. The wide kernels stage
// the data blocks in registers and size every load to the caller's
// store, so no wide load spans a narrower in-flight store. All three
// measured hosts select ZMM; the YMM tier is auto-selected only on VAES
// hosts without AVX-512, which are not among the measured hosts. Every
// tier stays built and is reachable through ITB_FORCE_HASH_TIER.
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

// The single-lane kernels exist in the two XMM encodings only; the wide
// tiers route their single-lane calls to the VEX kernel.
func fusedSingleVex() bool { return FusedHasVAESAVX512 || FusedHasVAESAVX2 || FusedHasAVXAESNI }

// FusedChain13x4 runs the cascade on four 13-byte lanes.
func FusedChain13x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(key, components, dataPtrs, 13, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesITB128FusedChain13x4Avx512Asm(key, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesITB128FusedChain13x4VaesAvx2Asm(key, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesITB128FusedChain13x4VexAsm(key, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesITB128FusedChain13x4AesNiAsm(key, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(key, components, dataPtrs, 13, out)
	}
}

// FusedChain20x4 runs the cascade on four 20-byte lanes.
func FusedChain20x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(key, components, dataPtrs, 20, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesITB128FusedChain20x4Avx512Asm(key, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesITB128FusedChain20x4VaesAvx2Asm(key, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesITB128FusedChain20x4VexAsm(key, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesITB128FusedChain20x4AesNiAsm(key, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(key, components, dataPtrs, 20, out)
	}
}

// FusedChain36x4 runs the cascade on four 36-byte lanes.
func FusedChain36x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(key, components, dataPtrs, 36, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesITB128FusedChain36x4Avx512Asm(key, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesITB128FusedChain36x4VaesAvx2Asm(key, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesITB128FusedChain36x4VexAsm(key, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesITB128FusedChain36x4AesNiAsm(key, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(key, components, dataPtrs, 36, out)
	}
}

// FusedChain68x4 runs the cascade on four 68-byte lanes.
func FusedChain68x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(key, components, dataPtrs, 68, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case FusedHasVAESAVX512:
		aesITB128FusedChain68x4Avx512Asm(key, c, n, dataPtrs, out)
	case FusedHasVAESAVX2:
		aesITB128FusedChain68x4VaesAvx2Asm(key, c, n, dataPtrs, out)
	case FusedHasAVXAESNI:
		aesITB128FusedChain68x4VexAsm(key, c, n, dataPtrs, out)
	case FusedHasAESNI:
		aesITB128FusedChain68x4AesNiAsm(key, c, n, dataPtrs, out)
	default:
		scalarFusedBatch(key, components, dataPtrs, 68, out)
	}
}

// FusedChain13x1 runs the cascade on one 13-byte input.
func FusedChain13x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(key, components, data, 13, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesITB128FusedChain13x1VexAsm(key, c, n, data, out)
	case FusedHasAESNI:
		aesITB128FusedChain13x1AesNiAsm(key, c, n, data, out)
	default:
		scalarFusedSingle(key, components, data, 13, out)
	}
}

// FusedChain20x1 runs the cascade on one 20-byte input.
func FusedChain20x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(key, components, data, 20, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesITB128FusedChain20x1VexAsm(key, c, n, data, out)
	case FusedHasAESNI:
		aesITB128FusedChain20x1AesNiAsm(key, c, n, data, out)
	default:
		scalarFusedSingle(key, components, data, 20, out)
	}
}

// FusedChain36x1 runs the cascade on one 36-byte input.
func FusedChain36x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(key, components, data, 36, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesITB128FusedChain36x1VexAsm(key, c, n, data, out)
	case FusedHasAESNI:
		aesITB128FusedChain36x1AesNiAsm(key, c, n, data, out)
	default:
		scalarFusedSingle(key, components, data, 36, out)
	}
}

// FusedChain68x1 runs the cascade on one 68-byte input.
func FusedChain68x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if !validComponents(components) {
		scalarFusedSingle(key, components, data, 68, out)
		return
	}
	c, n := &components[0], len(components)/2
	switch {
	case fusedSingleVex():
		aesITB128FusedChain68x1VexAsm(key, c, n, data, out)
	case FusedHasAESNI:
		aesITB128FusedChain68x1AesNiAsm(key, c, n, data, out)
	default:
		scalarFusedSingle(key, components, data, 68, out)
	}
}

// Four-lane fused kernels (aesitb_fusedchain128_<shape>x4_<tier>_amd64.s).
//
//go:noescape
func aesITB128FusedChain13x4AesNiAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain20x4AesNiAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain36x4AesNiAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain68x4AesNiAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain13x4VexAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain20x4VexAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain36x4VexAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain68x4VexAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain13x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain20x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain36x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain68x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain13x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain20x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain36x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain68x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

// Single-lane fused kernels (aesitb_fusedchain128_<shape>x1_<tier>_amd64.s).
//
//go:noescape
func aesITB128FusedChain13x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain20x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain36x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain68x1AesNiAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain13x1VexAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain20x1VexAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain36x1VexAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain68x1VexAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)
