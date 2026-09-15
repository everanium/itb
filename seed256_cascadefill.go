package itb

// chainHash256With evaluates the ChainHash256 cascade over a
// caller-supplied component slice instead of s.Components — the
// prepended slice of the Interlocked Barrier cascade fill
// ([buildLockBatchPRF48_256]). Evaluation order matches
// [Seed256.ChainHash256]: the fused hook first, the sequential Hash
// loop when the hook is absent or declines. components must hold a
// multiple of four words, at least four.
func (s *Seed256) chainHash256With(components []uint64, buf []byte) [4]uint64 {
	if s.FusedChain != nil {
		if out, ok := s.FusedChain(components, buf); ok {
			return out
		}
	}
	var seed [4]uint64
	copy(seed[:], components[0:4])
	h := s.Hash(buf, seed)
	for i := 4; i < len(components); i += 4 {
		seed[0] = components[i] ^ h[0]
		seed[1] = components[i+1] ^ h[1]
		seed[2] = components[i+2] ^ h[2]
		seed[3] = components[i+3] ^ h[3]
		h = s.Hash(buf, seed)
	}
	return h
}

// batchChainHash256With is the four-lane counterpart of
// [Seed256.chainHash256With], mirroring [Seed256.BatchChainHash256]
// over the supplied slice: the batched fused hook first, the
// sequential BatchHash loop otherwise. Output [i] matches
// chainHash256With on buf[i]. Caller ensures s.BatchHash != nil.
func (s *Seed256) batchChainHash256With(components []uint64, buf *[4][]byte) [4][4]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(components, buf); ok {
			return out
		}
	}
	var seeds [4][4]uint64
	for lane := 0; lane < 4; lane++ {
		copy(seeds[lane][:], components[0:4])
	}
	h := s.BatchHash(buf, seeds)
	for i := 4; i < len(components); i += 4 {
		c0, c1, c2, c3 := components[i], components[i+1], components[i+2], components[i+3]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
			seeds[lane][2] = c2 ^ h[lane][2]
			seeds[lane][3] = c3 ^ h[lane][3]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}
