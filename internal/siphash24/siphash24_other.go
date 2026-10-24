//go:build (!amd64 && !arm64) || purego || noitbasm

package siphash24

import "runtime"

// XORKeyStreamBlocksWithState XORs nBlocks = len(src) / 16 blocks of 16-byte
// SipHash-2-4-128 counter-mode keystream into dst starting from the
// precomputed post-nonceHi state vInit and block counter.
func XORKeyStreamBlocksWithState(dst, src []byte, vInit *[4]uint64, nonceLo, counter uint64) {
	scalarXORKeyStreamBlocksWithState(dst, src, vInit, nonceLo, counter)
	nonceLo = 0
	runtime.KeepAlive(&nonceLo)
}

// BatchPRFx4 evaluates 4 lanes of SipHash-2-4-128 under key (k0, k1), writing
// the 16-byte little-endian digest of in[lane] into dst[lane][:16].
func BatchPRFx4(dst, in *[4][]byte, k0, k1 uint64) {
	scalarBatchPRFx4(dst, in, k0, k1)
	k0, k1 = 0, 0
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
}
