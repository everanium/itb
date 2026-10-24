//go:build amd64 && !purego && !noitbasm

package siphash24

import (
	"runtime"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

var (
	// HasAVX512 reports whether the AVX-512 (F + VL) SipHash-2-4-128 CTR and
	// 4-lane batch PRF kernels are active on the running host.
	HasAVX512 = cpuid.AVX512F && cpuid.AVX512VL
	// HasAVX2 reports whether the AVX2 SipHash-2-4-128 CTR and 4-lane batch
	// PRF kernels are active on the running host.
	HasAVX2 = cpuid.AVX2
)

func init() {
	applyHashTier()
}

func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "avx512":
		if cpuid.AVX512F && cpuid.AVX512VL {
			HasAVX512, HasAVX2 = true, false
		}
	case "avx2", "vex":
		if cpuid.AVX2 {
			HasAVX512, HasAVX2 = false, true
		}
	case "gpr", "scalar":
		HasAVX512, HasAVX2 = false, false
	}
}

//go:noescape
func siphashXORBlocksAvx512Asm(vInit *[4]uint64, nonceLo, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func siphashXORBlocksAvx2Asm(vInit *[4]uint64, nonceLo, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func siphashSum128x4Avx512Asm(dst, in *[4][]byte, k0, k1 uint64, nBytes int)

//go:noescape
func siphashSum128x4Avx2Asm(dst, in *[4][]byte, k0, k1 uint64, nBytes int)

// XORKeyStreamBlocksWithState XORs nBlocks = len(src) / 16 blocks of 16-byte
// SipHash-2-4-128 counter-mode keystream into dst starting from the
// precomputed post-nonceHi state vInit and block counter.
func XORKeyStreamBlocksWithState(dst, src []byte, vInit *[4]uint64, nonceLo, counter uint64) {
	nBlocks := len(src) / Size128
	if nBlocks <= 0 {
		return
	}
	if len(dst) < nBlocks*Size128 {
		panic("siphash24: dst smaller than src")
	}
	dstPtr := &dst[0]
	srcPtr := &src[0]
	if HasAVX512 {
		siphashXORBlocksAvx512Asm(vInit, nonceLo, counter, dstPtr, srcPtr, nBlocks)
		nonceLo = 0
		runtime.KeepAlive(&nonceLo)
		return
	}
	if HasAVX2 {
		siphashXORBlocksAvx2Asm(vInit, nonceLo, counter, dstPtr, srcPtr, nBlocks)
		nonceLo = 0
		runtime.KeepAlive(&nonceLo)
		return
	}
	scalarXORKeyStreamBlocksWithState(dst, src, vInit, nonceLo, counter)
	nonceLo = 0
	runtime.KeepAlive(&nonceLo)
}

// BatchPRFx4 evaluates 4 lanes of SipHash-2-4-128 under key (k0, k1), writing
// the 16-byte little-endian digest of in[lane] into dst[lane][:16].
func BatchPRFx4(dst, in *[4][]byte, k0, k1 uint64) {
	if len(dst[0]) < Size128 || len(dst[1]) < Size128 || len(dst[2]) < Size128 || len(dst[3]) < Size128 {
		panic("siphash24: dst buffer smaller than 16 bytes")
	}
	n := len(in[0])
	if len(in[1]) != n || len(in[2]) != n || len(in[3]) != n {
		scalarBatchPRFx4(dst, in, k0, k1)
		k0, k1 = 0, 0
		runtime.KeepAlive(&k0)
		runtime.KeepAlive(&k1)
		return
	}
	if HasAVX512 {
		siphashSum128x4Avx512Asm(dst, in, k0, k1, n)
		k0, k1 = 0, 0
		runtime.KeepAlive(&k0)
		runtime.KeepAlive(&k1)
		return
	}
	if HasAVX2 {
		siphashSum128x4Avx2Asm(dst, in, k0, k1, n)
		k0, k1 = 0, 0
		runtime.KeepAlive(&k0)
		runtime.KeepAlive(&k1)
		return
	}
	scalarBatchPRFx4(dst, in, k0, k1)
	k0, k1 = 0, 0
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
}
