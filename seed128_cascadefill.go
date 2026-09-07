package itb

// chainHash128With evaluates the ChainHash128 cascade over a
// caller-supplied component slice instead of s.Components — the
// prepended slice of the Interlocked Barrier cascade fill
// ([buildLockBatchPRF48_128Cascade]). Evaluation order matches
// [Seed128.ChainHash128]: the fused hook first, the sequential Hash loop
// when the hook is absent or declines. components must hold an even
// count of at least two words.
func (s *Seed128) chainHash128With(components []uint64, buf []byte) (uint64, uint64) {
	if s.FusedChain != nil {
		if lo, hi, ok := s.FusedChain(components, buf); ok {
			return lo, hi
		}
	}
	hLo, hHi := s.Hash(buf, components[0], components[1])
	for i := 2; i < len(components); i += 2 {
		hLo, hHi = s.Hash(buf, components[i]^hLo, components[i+1]^hHi)
	}
	return hLo, hHi
}

// batchChainHash128With is the four-lane counterpart of
// [Seed128.chainHash128With], mirroring [Seed128.BatchChainHash128] over
// the supplied slice: the batched fused hook first, the sequential
// BatchHash loop otherwise. Output [i] matches chainHash128With on
// buf[i]. Caller ensures s.BatchHash != nil.
func (s *Seed128) batchChainHash128With(components []uint64, buf *[4][]byte) [4][2]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(components, buf); ok {
			return out
		}
	}
	var seeds [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = components[0]
		seeds[lane][1] = components[1]
	}
	h := s.BatchHash(buf, seeds)
	for i := 2; i < len(components); i += 2 {
		c0, c1 := components[i], components[i+1]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}
