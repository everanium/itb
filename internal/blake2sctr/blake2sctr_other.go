//go:build (!amd64 && !arm64) || purego || noitbasm

package blake2sctr

// BatchPRFx4 evaluates the RFC 7693 Keyed BLAKE2s-256 PRF across four
// independent inputs in[0..3] into dst[0..3].
func BatchPRFx4(dst, in *[4][]byte, hKey *[8]uint32, keyWords *[8]uint32) {
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
	scalarXORKeyStreamBlocks(dst[:nBytes], src[:nBytes], hKey, nonce, counter)
}
