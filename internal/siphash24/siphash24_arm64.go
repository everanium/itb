//go:build arm64 && !purego && !noitbasm

package siphash24

import (
	"runtime"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// HasNEON reports whether the ARM64 NEON SipHash-2-4-128 CTR and 4-lane batch
// PRF kernels are active on the running host.
var HasNEON = cpuid.ASIMD

func init() {
	applyHashTier()
}

func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		if cpuid.ASIMD {
			HasNEON = true
		}
	case "gpr", "scalar":
		HasNEON = false
	}
}

//go:noescape
func siphashXORBlocksNEONAsm(vInit *[4]uint64, nonceLo, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func siphashSum128x4NEONAsm(dst, in *[4][]byte, k0, k1 uint64, nBytes int)

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
	if HasNEON {
		siphashXORBlocksNEONAsm(vInit, nonceLo, counter, dstPtr, srcPtr, nBlocks)
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
	if HasNEON {
		siphashSum128x4NEONAsm(dst, in, k0, k1, n)
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
