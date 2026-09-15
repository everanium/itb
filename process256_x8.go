package itb

// Eight-pixel stride of the 256-bit pixel pipeline. Both processChunk256
// variants (process_cgo.go / process_generic.go) hash eight pixels per
// call through Seed256.blockHash256x8 ahead of their four-pixel loop when
// useBatch8Seeds256 reports both seeds carry the eight-lane fused hook;
// the per-pixel encoding is unchanged, so the wire is identical with and
// without the stride. The eight lane buffers are the eight-lane views of
// the worker's laneScratch (lanescratch.go); lanes 0..3 alias the
// four-pixel stride's buffers.

// useBatch8Seeds256 reports whether the eight-pixel stride applies at
// width 256: both seeds expose BatchHash (the four-lane stride's
// precondition, which the fallback of the eight-lane path relies on)
// and both carry the eight-lane fused hook.
func useBatch8Seeds256(noiseSeed, dataSeed *Seed256) bool {
	return noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil &&
		noiseSeed.batchFusedChainX8 != nil && dataSeed.batchFusedChainX8 != nil
}
