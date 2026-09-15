package itb

// Eight-pixel stride of the 128-bit pixel pipeline. Both processChunk128
// variants (process_cgo.go / process_generic.go) hash eight pixels per
// call through Seed128.blockHash128x8 ahead of their four-pixel loop when
// useBatch8Seeds reports both seeds carry the eight-lane fused hook; the
// per-pixel encoding is unchanged, so the wire is identical with and
// without the stride. The eight lane buffers are the eight-lane views of
// the worker's laneScratch (lanescratch.go); lanes 0..3 alias the
// four-pixel stride's buffers.

// useBatch8Seeds reports whether the eight-pixel stride applies: both
// seeds expose BatchHash (the four-lane stride's precondition, which the
// fallback of the eight-lane path relies on) and both carry the
// eight-lane fused hook.
func useBatch8Seeds(noiseSeed, dataSeed *Seed128) bool {
	return noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil &&
		noiseSeed.batchFusedChainX8 != nil && dataSeed.batchFusedChainX8 != nil
}
