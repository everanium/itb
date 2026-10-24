//go:build amd64 && !purego && !noitbasm

package blake2bctr

import (
	"encoding/binary"
	"runtime"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
	"github.com/everanium/itb/internal/wipe"
)

var (
	// HasAVX512 reports whether the AVX-512 (F + VL) BLAKE2b CTR and batch-PRF
	// kernels are active on the running host.
	HasAVX512 = cpuid.AVX512F && cpuid.AVX512VL
	// HasAVX2 reports whether the AVX2 BLAKE2b CTR and batch-PRF kernels are
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
		// BLAKE2b has no AES-based arm; keep auto-dispatch.
	case "neon", "sve2", "sve":
		// arm64-only tokens; keep auto-dispatch.
	case "gpr", "scalar":
		HasAVX512, HasAVX2 = false, false
	}
}

//go:noescape
func blake2bXORBlocks256Avx512Asm(hKey *[8]uint64, nonce *[2]uint64, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake2bXORBlocks512Avx512Asm(hKey *[8]uint64, nonce *[2]uint64, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake2bXORBlocks256Avx2Asm(hKey *[8]uint64, nonce *[2]uint64, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake2bXORBlocks512Avx2Asm(hKey *[8]uint64, nonce *[2]uint64, counter uint64, dst, src *byte, nBlocks int)

//go:noescape
func blake2bBatch24_256Avx512Asm(hKey *[8]uint64, m012 *[3][4]uint64, dstPtrs *[4]*byte)

//go:noescape
func blake2bBatch24_512Avx512Asm(hKey *[8]uint64, m012 *[3][4]uint64, dstPtrs *[4]*byte)

//go:noescape
func blake2bBatch24_256Avx2Asm(hKey *[8]uint64, m012 *[3][4]uint64, dstPtrs *[4]*byte)

//go:noescape
func blake2bBatch24_512Avx2Asm(hKey *[8]uint64, m012 *[3][4]uint64, dstPtrs *[4]*byte)

//go:noescape
func blake2bCompress4Avx512Asm(h *[8][4]uint64, m *[16][4]uint64, t0, f0 uint64)

//go:noescape
func blake2bCompress4Avx2Asm(h *[8][4]uint64, m *[16][4]uint64, t0, f0 uint64)

// XORKeyStreamBlocks256 XORs full 32-byte blocks of Keyed BLAKE2b-256 CTR
// keystream from src into dst starting at counter. len(src) must be a
// non-negative multiple of BlockSize256 (32).
func XORKeyStreamBlocks256(dst, src []byte, hKey *[8]uint64, nonce *[2]uint64, counter uint64) {
	nBlocks := len(src) / BlockSize256
	if nBlocks <= 0 {
		return
	}
	if len(src) < nBlocks*BlockSize256 || len(dst) < nBlocks*BlockSize256 {
		panic("blake2bctr: buffer smaller than nBlocks")
	}
	if HasAVX512 {
		blake2bXORBlocks256Avx512Asm(hKey, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	if HasAVX2 {
		blake2bXORBlocks256Avx2Asm(hKey, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	scalarXORKeyStreamBlocks256(dst[:nBlocks*BlockSize256], src[:nBlocks*BlockSize256], hKey, nonce, counter)
}

// XORKeyStreamBlocks512 XORs full 64-byte blocks of Keyed BLAKE2b-512 CTR
// keystream from src into dst starting at counter. len(src) must be a
// non-negative multiple of BlockSize512 (64).
func XORKeyStreamBlocks512(dst, src []byte, hKey *[8]uint64, nonce *[2]uint64, counter uint64) {
	nBlocks := len(src) / BlockSize512
	if nBlocks <= 0 {
		return
	}
	if len(src) < nBlocks*BlockSize512 || len(dst) < nBlocks*BlockSize512 {
		panic("blake2bctr: buffer smaller than nBlocks")
	}
	if HasAVX512 {
		blake2bXORBlocks512Avx512Asm(hKey, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	if HasAVX2 {
		blake2bXORBlocks512Avx2Asm(hKey, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	scalarXORKeyStreamBlocks512(dst[:nBlocks*BlockSize512], src[:nBlocks*BlockSize512], hKey, nonce, counter)
}

// BatchPRF256x4 evaluates Keyed BLAKE2b-256 across 4 lanes in parallel when
// all 4 inputs share a common length in 1..128, falling back to per-lane
// Eval256 otherwise.
func BatchPRF256x4(dst, in *[4][]byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < BlockSize256 {
			panic("blake2bctr: dst lane smaller than BlockSize256")
		}
	}
	commonLen := len(in[0])
	if commonLen < 1 || commonLen > 128 ||
		len(in[1]) != commonLen || len(in[2]) != commonLen || len(in[3]) != commonLen ||
		(!HasAVX512 && !HasAVX2) {
		scalarBatchPRF256x4(dst, in, hKey, keyBlock)
		return
	}
	if commonLen == 24 {
		batchPRF24Amd64(dst, in, hKey, false)
		return
	}
	batchPRF1BlockAmd64(dst, in, hKey, commonLen, 4)
}

// BatchPRF512x4 evaluates Keyed BLAKE2b-512 across 4 lanes in parallel when
// all 4 inputs share a common length in 1..128, falling back to per-lane
// Eval512 otherwise.
func BatchPRF512x4(dst, in *[4][]byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < BlockSize512 {
			panic("blake2bctr: dst lane smaller than BlockSize512")
		}
	}
	commonLen := len(in[0])
	if commonLen < 1 || commonLen > 128 ||
		len(in[1]) != commonLen || len(in[2]) != commonLen || len(in[3]) != commonLen ||
		(!HasAVX512 && !HasAVX2) {
		scalarBatchPRF512x4(dst, in, hKey, keyBlock)
		return
	}
	if commonLen == 24 {
		batchPRF24Amd64(dst, in, hKey, true)
		return
	}
	batchPRF1BlockAmd64(dst, in, hKey, commonLen, 8)
}

//go:noinline
func batchPRF24Amd64(dst, in *[4][]byte, hKey *[8]uint64, is512 bool) {
	var m012 [3][4]uint64
	for lane := 0; lane < 4; lane++ {
		inp := in[lane][:24:24]
		m012[0][lane] = binary.LittleEndian.Uint64(inp[0:8])
		m012[1][lane] = binary.LittleEndian.Uint64(inp[8:16])
		m012[2][lane] = binary.LittleEndian.Uint64(inp[16:24])
	}
	dstPtrs := [4]*byte{&dst[0][0], &dst[1][0], &dst[2][0], &dst[3][0]}
	if HasAVX512 {
		if is512 {
			blake2bBatch24_512Avx512Asm(hKey, &m012, &dstPtrs)
		} else {
			blake2bBatch24_256Avx512Asm(hKey, &m012, &dstPtrs)
		}
	} else {
		if is512 {
			blake2bBatch24_512Avx2Asm(hKey, &m012, &dstPtrs)
		} else {
			blake2bBatch24_256Avx2Asm(hKey, &m012, &dstPtrs)
		}
	}
	clear(m012[:])
	dstPtrs = [4]*byte{}
	runtime.KeepAlive(&m012)
	runtime.KeepAlive(&dstPtrs)
	wipe.ClobberRegs()
}

//go:noinline
func batchPRF1BlockAmd64(dst, in *[4][]byte, hKey *[8]uint64, commonLen, outWords int) {
	var hSoA [8][4]uint64
	var mSoA [16][4]uint64
	for i := 0; i < 8; i++ {
		w := hKey[i]
		hSoA[i] = [4]uint64{w, w, w, w}
	}
	fullWords := commonLen >> 3
	tail := commonLen & 7
	for lane := 0; lane < 4; lane++ {
		inp := in[lane][:commonLen:commonLen]
		for w := 0; w < fullWords; w++ {
			mSoA[w][lane] = binary.LittleEndian.Uint64(inp[w*8:])
		}
		if tail > 0 {
			var v uint64
			base := fullWords * 8
			for b := 0; b < tail; b++ {
				v |= uint64(inp[base+b]) << (8 * b)
			}
			mSoA[fullWords][lane] = v
		}
	}
	t0 := uint64(128 + commonLen)
	if HasAVX512 {
		blake2bCompress4Avx512Asm(&hSoA, &mSoA, t0, ^uint64(0))
	} else {
		blake2bCompress4Avx2Asm(&hSoA, &mSoA, t0, ^uint64(0))
	}
	for lane := 0; lane < 4; lane++ {
		d := dst[lane]
		for w := 0; w < outWords; w++ {
			binary.LittleEndian.PutUint64(d[w*8:], hSoA[w][lane])
		}
	}
	clear(hSoA[:])
	clear(mSoA[:])
	runtime.KeepAlive(&hSoA)
	runtime.KeepAlive(&mSoA)
	wipe.ClobberRegs()
}
