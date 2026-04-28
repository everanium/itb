package itb

import "encoding/binary"

// BatchHashFunc256 is the optional 4-way batched 256-bit hash interface.
// A primitive whose underlying SIMD implementation supports
// processing four independent (data, seed) tuples per call provides
// this alongside its single-call HashFunc256 (for example
// `AreionSoEM256x4` on x86_64 with VAES + AVX-512).
//
// Bit-exact parity invariant. For every i in {0,1,2,3} and arbitrary
// inputs:
//
//	BatchHashFunc256(data, seeds)[i] == HashFunc256(data[i], seeds[i])
//
// Implementations that violate this break ITB security claims under
// the batched dispatch path: the per-pixel ChainHash output would
// diverge from the serial reference, invalidating the underlying
// PRF assumption. The user-supplied wrapper is responsible for
// preserving this invariant; ITB's test suite (Areion-SoEM parity in
// `areion_test.go`) demonstrates the required structure.
type BatchHashFunc256 func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64

// BatchChainHash256 computes the four-way batched ChainHash256 on four
// pixel buffers in parallel using `s.BatchHash`. Each output position
// matches the serial `ChainHash256(data[i])` under the same seed
// components — the chain composition is identical, just executed four
// lanes at a time per round.
//
// Caller responsibility: `s.BatchHash` must be non-nil. The dispatch
// in `processChunk{256,512}` checks this before invoking; user-level
// callers should check explicitly.
func (s *Seed256) BatchChainHash256(buf *[4][]byte) [4][4]uint64 {
	var seeds [4][4]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = s.Components[0]
		seeds[lane][1] = s.Components[1]
		seeds[lane][2] = s.Components[2]
		seeds[lane][3] = s.Components[3]
	}
	h := s.BatchHash(buf, seeds)

	for i := 4; i < len(s.Components); i += 4 {
		c0, c1, c2, c3 := s.Components[i], s.Components[i+1], s.Components[i+2], s.Components[i+3]
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

// blockHash256x4 is the four-way batched counterpart of
// `blockHash256`. Mutates the first four bytes of each `buf[i]` to
// hold the corresponding `pixelIndices[i]` in little-endian, then
// invokes `BatchChainHash256`.
//
// Caller must ensure each `buf[i]` has at least 4 bytes of writable
// storage and that `s.BatchHash != nil`.
func (s *Seed256) blockHash256x4(buf *[4][]byte, pixelIndices [4]int) [4][4]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash256(buf)
}
