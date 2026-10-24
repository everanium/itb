//go:build amd64 && !purego && !noitbasm

package blake3ctr

import (
	"runtime"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

var (
	// HasAVX512 reports whether the AVX-512 (F + VL) BLAKE3 CTR and batch-PRF
	// kernels are active on the running host.
	HasAVX512 = cpuid.AVX512F && cpuid.AVX512VL
	// HasAVX2 reports whether the AVX2 BLAKE3 CTR and batch-PRF kernels are
	// active on the running host.
	HasAVX2 = cpuid.AVX2
)

func init() {
	applyHashTier()
}

func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "avx512":
		if !cpuid.AVX512F || !cpuid.AVX512VL {
			return
		}
		HasAVX512, HasAVX2 = true, false
	case "avx2", "vex":
		if !cpuid.AVX2 {
			return
		}
		HasAVX512, HasAVX2 = false, true
	case "aesni", "vaesavx2":
	case "neon", "sve2", "sve":
	case "gpr", "scalar":
		HasAVX512, HasAVX2 = false, false
	}
}

//go:noescape
func blake3XORBlocksAvx512Asm(keyWords *[8]uint32, nonce *[4]uint32, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake3XORBlocksAvx2Asm(keyWords *[8]uint32, nonce *[4]uint32, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake3Batch24x4Avx512Asm(keyWords *[8]uint32, ptrs *[8]*byte)

//go:noescape
func blake3Batch24x4Avx2Asm(keyWords *[8]uint32, ptrs *[8]*byte, scratch *[6][4]uint32)

//go:noescape
func blake3Compress4xAvx512Asm(keyWords *[8]uint32, m *[16][4]uint32, blockLen uint32, outPtrs *[4]*byte)

//go:noescape
func blake3Compress4xAvx2Asm(keyWords *[8]uint32, m *[16][4]uint32, blockLen uint32, outPtrs *[4]*byte)

// BatchPRFx4 evaluates the Keyed BLAKE3 PRF across four independent inputs
// in[0..3] into dst[0..3]. When all four inputs share a common length in
// 0..64 bytes, a 4-lane SIMD compression kernel is used.
func BatchPRFx4(dst, in *[4][]byte, keyWords *[8]uint32, keyBytes *[32]byte) {
	if len(dst[0]) < BlockSize || len(dst[1]) < BlockSize || len(dst[2]) < BlockSize || len(dst[3]) < BlockSize {
		panic("blake3ctr: dst smaller than BlockSize")
	}
	commonLen := len(in[0])
	if commonLen <= 64 &&
		len(in[1]) == commonLen && len(in[2]) == commonLen && len(in[3]) == commonLen &&
		(HasAVX512 || HasAVX2) {
		if commonLen == 24 {
			ptrs := [8]*byte{
				&in[0][0], &in[1][0], &in[2][0], &in[3][0],
				&dst[0][0], &dst[1][0], &dst[2][0], &dst[3][0],
			}
			if HasAVX512 {
				blake3Batch24x4Avx512Asm(keyWords, &ptrs)
				clear(ptrs[:])
				runtime.KeepAlive(&ptrs)
				return
			}
			var scratch [6][4]uint32
			blake3Batch24x4Avx2Asm(keyWords, &ptrs, &scratch)
			clear(ptrs[:])
			clear(scratch[:])
			runtime.KeepAlive(&ptrs)
			runtime.KeepAlive(&scratch)
			return
		}
		var m [16][4]uint32
		if commonLen > 0 {
			transposeMsg4x(&m, in, commonLen)
		}
		outPtrs := [4]*byte{&dst[0][0], &dst[1][0], &dst[2][0], &dst[3][0]}
		if HasAVX512 {
			blake3Compress4xAvx512Asm(keyWords, &m, uint32(commonLen), &outPtrs)
		} else {
			blake3Compress4xAvx2Asm(keyWords, &m, uint32(commonLen), &outPtrs)
		}
		clear(outPtrs[:])
		clear(m[:])
		runtime.KeepAlive(&outPtrs)
		runtime.KeepAlive(&m)
		return
	}
	scalarBatchPRFx4(dst, in, keyWords, keyBytes)
}

// XORKeyStreamBlocks XORs full 32-byte blocks of Keyed BLAKE3 CTR keystream
// from src into dst starting at counter.
func XORKeyStreamBlocks(dst, src []byte, keyWords *[8]uint32, nonce *[4]uint32, counter uint64) {
	nBlocks := len(src) / BlockSize
	if nBlocks <= 0 {
		return
	}
	nBytes := nBlocks * BlockSize
	if len(src) < nBytes || len(dst) < nBytes {
		panic("blake3ctr: buffer smaller than nBlocks")
	}
	if inexactOverlap(dst[:nBytes], src[:nBytes]) {
		panic("blake3ctr: invalid buffer overlap")
	}
	if HasAVX512 {
		blake3XORBlocksAvx512Asm(keyWords, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	if HasAVX2 {
		blake3XORBlocksAvx2Asm(keyWords, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	scalarXORKeyStreamBlocks(dst[:nBytes], src[:nBytes], keyWords, nonce, counter)
}
