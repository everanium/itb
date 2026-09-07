package itb

// Eight-pixel stride of the 128-bit pixel pipeline. Both processChunk128
// variants (process_cgo.go / process_generic.go) hash eight pixels per
// call through Seed128.blockHash128x8 ahead of their four-pixel loop when
// useBatch8Seeds reports both seeds carry the eight-lane fused hook; the
// per-pixel encoding is unchanged, so the wire is identical with and
// without the stride.

// useBatch8Seeds reports whether the eight-pixel stride applies: both
// seeds expose BatchHash (the four-lane stride's precondition, which the
// fallback of the eight-lane path relies on) and both carry the
// eight-lane fused hook.
func useBatch8Seeds(noiseSeed, dataSeed *Seed128) bool {
	return noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil &&
		noiseSeed.batchFusedChainX8 != nil && dataSeed.batchFusedChainX8 != nil
}

// acquireLaneBufs8 extends the four lane buffers of the four-pixel stride
// to eight: lanes 0..3 alias base, lanes 4..7 are drawn from the shared
// bufferPool at size bytes with nonce copied in at offset 4 (the
// pixel-index slot at offset 0 is written per call). release returns
// the four pooled buffers and must be deferred by the caller.
func acquireLaneBufs8(base *[4][]byte, nonce []byte, size int) (bufs [8][]byte, release func()) {
	var ptrs [4]*[]byte
	copy(bufs[0:4], base[:])
	for lane := 4; lane < 8; lane++ {
		ptrs[lane-4], bufs[lane] = acquireBuffer(size)
		copy(bufs[lane][4:], nonce)
	}
	release = func() {
		for lane := 4; lane < 8; lane++ {
			releaseBuffer(ptrs[lane-4], bufs[lane])
		}
	}
	return bufs, release
}
