//go:build (!amd64 && !arm64) || purego || noitbasm

package blake2bctr

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
	scalarXORKeyStreamBlocks512(dst[:nBlocks*BlockSize512], src[:nBlocks*BlockSize512], hKey, nonce, counter)
}

// BatchPRF256x4 evaluates Keyed BLAKE2b-256 across 4 lanes.
func BatchPRF256x4(dst, in *[4][]byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < BlockSize256 {
			panic("blake2bctr: dst lane smaller than BlockSize256")
		}
	}
	scalarBatchPRF256x4(dst, in, hKey, keyBlock)
}

// BatchPRF512x4 evaluates Keyed BLAKE2b-512 across 4 lanes.
func BatchPRF512x4(dst, in *[4][]byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < BlockSize512 {
			panic("blake2bctr: dst lane smaller than BlockSize512")
		}
	}
	scalarBatchPRF512x4(dst, in, hKey, keyBlock)
}
