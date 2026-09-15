package itb

// Eight-pixel stride of the pixel pipeline. Both processChunk variants
// (process_cgo.go / process_generic.go) hash eight pixels per call
// through Seed<W>.blockHash<W>x8 ahead of their four-pixel loop when the
// predicate below reports both seeds carry the eight-lane fused hook;
// the per-pixel encoding is unchanged, so the wire is identical with and
// without the stride. The eight lane buffers are the eight-lane views of
// the worker's laneScratch (lanescratch.go); lanes 0..3 alias the
// four-pixel stride's buffers.

// useBatch8Seeds reports whether the eight-pixel stride applies at width
// 128: both seeds expose BatchHash — the four-lane stride's precondition,
// which the eight-lane fallback relies on — and both carry the eight-lane
// fused hook.
func useBatch8Seeds(noiseSeed, dataSeed *Seed128) bool {
	return noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil &&
		noiseSeed.batchFusedChainX8 != nil && dataSeed.batchFusedChainX8 != nil
}

// useBatch8Seeds256 is the width-256 counterpart of useBatch8Seeds.
func useBatch8Seeds256(noiseSeed, dataSeed *Seed256) bool {
	return noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil &&
		noiseSeed.batchFusedChainX8 != nil && dataSeed.batchFusedChainX8 != nil
}

// useBatch8Seeds512 is the width-512 counterpart of useBatch8Seeds.
func useBatch8Seeds512(noiseSeed, dataSeed *Seed512) bool {
	return noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil &&
		noiseSeed.batchFusedChainX8 != nil && dataSeed.batchFusedChainX8 != nil
}
