//go:build arm64 && !purego && !noitbasm

package blake2sctr

import (
	"runtime"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// HasNEON reports whether the ARM64 NEON 4-lane BLAKE2s-256 CTR and
// batch-PRF kernels are active on the running host.
var HasNEON = cpuid.ASIMD

func init() {
	applyHashTier()
}

func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		if !cpuid.ASIMD {
			return
		}
		HasNEON = true
	case "gpr", "scalar":
		HasNEON = false
	}
}

//go:noescape
func blake2sXORBlocksNeonAsm(hKey *[8]uint32, nonce *[4]uint32, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake2sBatch24x4NeonAsm(hKey *[8]uint32, ptrs *[8]*byte)

//go:noescape
func blake2sCompress4xNeonAsm(hKey *[8]uint32, m *[16][4]uint32, t0 uint32, outPtrs *[4]*byte)

// BatchPRFx4 evaluates the RFC 7693 Keyed BLAKE2s-256 PRF across four
// independent inputs in[0..3] into dst[0..3]. When all four inputs share a
// common length in 1..64 bytes, a 4-lane NEON compression kernel is used.
func BatchPRFx4(dst, in *[4][]byte, hKey *[8]uint32, keyWords *[8]uint32) {
	if len(dst[0]) < BlockSize || len(dst[1]) < BlockSize || len(dst[2]) < BlockSize || len(dst[3]) < BlockSize {
		panic("blake2sctr: dst smaller than BlockSize")
	}
	commonLen := len(in[0])
	if commonLen >= 1 && commonLen <= 64 &&
		len(in[1]) == commonLen && len(in[2]) == commonLen && len(in[3]) == commonLen &&
		HasNEON {
		if commonLen == 24 {
			ptrs := [8]*byte{
				&in[0][0], &in[1][0], &in[2][0], &in[3][0],
				&dst[0][0], &dst[1][0], &dst[2][0], &dst[3][0],
			}
			blake2sBatch24x4NeonAsm(hKey, &ptrs)
			clear(ptrs[:])
			runtime.KeepAlive(&ptrs)
			return
		}
		var m [16][4]uint32
		transposeMsg4x(&m, in, commonLen)
		outPtrs := [4]*byte{&dst[0][0], &dst[1][0], &dst[2][0], &dst[3][0]}
		blake2sCompress4xNeonAsm(hKey, &m, uint32(64+commonLen), &outPtrs)
		clear(outPtrs[:])
		clear(m[:])
		runtime.KeepAlive(&outPtrs)
		runtime.KeepAlive(&m)
		return
	}
	scalarBatchPRFx4(dst, in, hKey, keyWords)
}

// XORKeyStreamBlocks XORs full 32-byte blocks of Keyed BLAKE2s-256 CTR
// keystream from src into dst starting at counter.
func XORKeyStreamBlocks(dst, src []byte, hKey *[8]uint32, nonce *[4]uint32, counter uint64) {
	nBlocks := len(src) / BlockSize
	if nBlocks <= 0 {
		return
	}
	nBytes := nBlocks * BlockSize
	if len(src) < nBytes || len(dst) < nBytes {
		panic("blake2sctr: buffer smaller than nBlocks")
	}
	if inexactOverlap(dst[:nBytes], src[:nBytes]) {
		panic("blake2sctr: invalid buffer overlap")
	}
	if HasNEON {
		blake2sXORBlocksNeonAsm(hKey, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	scalarXORKeyStreamBlocks(dst[:nBytes], src[:nBytes], hKey, nonce, counter)
}
