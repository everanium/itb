package itb

// chainHash512With evaluates the ChainHash512 cascade over a
// caller-supplied component slice instead of s.Components — the
// prepended slice of the Interlocked Barrier cascade fill
// ([buildLockBatchPRF48_512]). Evaluation order matches
// [Seed512.ChainHash512]: the fused hook first, the sequential Hash
// loop when the hook is absent or declines. components must hold a
// multiple of eight words, at least eight.
func (s *Seed512) chainHash512With(components []uint64, buf []byte) [8]uint64 {
	if s.FusedChain != nil {
		if out, ok := s.FusedChain(components, buf); ok {
			return out
		}
	}
	var seed [8]uint64
	copy(seed[:], components[0:8])
	h := s.Hash(buf, seed)
	for i := 8; i < len(components); i += 8 {
		for j := 0; j < 8; j++ {
			seed[j] = components[i+j] ^ h[j]
		}
		h = s.Hash(buf, seed)
	}
	return h
}

// batchChainHash512With is the four-lane counterpart of
// [Seed512.chainHash512With], mirroring [Seed512.BatchChainHash512]
// over the supplied slice: the batched fused hook first, the
// sequential BatchHash loop otherwise. Output [i] matches
// chainHash512With on buf[i]. Caller ensures s.BatchHash != nil.
func (s *Seed512) batchChainHash512With(components []uint64, buf *[4][]byte) [4][8]uint64 {
	if s.BatchFusedChain != nil {
		if out, ok := s.BatchFusedChain(components, buf); ok {
			return out
		}
	}
	var seeds [4][8]uint64
	for lane := 0; lane < 4; lane++ {
		copy(seeds[lane][:], components[0:8])
	}
	h := s.BatchHash(buf, seeds)
	for i := 8; i < len(components); i += 8 {
		for lane := 0; lane < 4; lane++ {
			for j := 0; j < 8; j++ {
				seeds[lane][j] = components[i+j] ^ h[lane][j]
			}
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}
