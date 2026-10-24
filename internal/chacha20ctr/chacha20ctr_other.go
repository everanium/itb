//go:build (!amd64 && !arm64) || purego || noitbasm

package chacha20ctr

// XORKeyStreamBlocks XORs full 64-byte blocks of RFC 8439 ChaCha20 keystream
// from src into dst starting at counter. len(src) must be a non-negative
// multiple of BlockSize (64).
func XORKeyStreamBlocks(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter uint32) {
	nBlocks := len(src) / BlockSize
	if nBlocks <= 0 {
		return
	}
	if len(src) < nBlocks*BlockSize || len(dst) < nBlocks*BlockSize {
		panic("chacha20: buffer smaller than nBlocks")
	}
	if uint64(counter)+uint64(nBlocks) > 1<<32 {
		panic("chacha20: counter overflow")
	}
	scalarXORKeyStreamBlocks(dst[:nBlocks*BlockSize], src[:nBlocks*BlockSize], key, nonce, counter)
}
