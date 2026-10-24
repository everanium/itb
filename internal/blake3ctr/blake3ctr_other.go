//go:build (!amd64 && !arm64) || purego || noitbasm

package blake3ctr

var (
	// HasAVX512 is always false on non-amd64 or pure-Go builds.
	HasAVX512 = false
	// HasAVX2 is always false on non-amd64 or pure-Go builds.
	HasAVX2 = false
	// HasNEON is always false on non-arm64 or pure-Go builds.
	HasNEON = false
)

func applyHashTier() {}

// BatchPRFx4 evaluates the Keyed BLAKE3 PRF across four independent inputs
// in[0..3] into dst[0..3].
func BatchPRFx4(dst, in *[4][]byte, keyWords *[8]uint32, keyBytes *[32]byte) {
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
	scalarXORKeyStreamBlocks(dst[:nBytes], src[:nBytes], keyWords, nonce, counter)
}
