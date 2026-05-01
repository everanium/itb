package itb

import "encoding/binary"

// BatchHashFunc128 is the optional 4-way batched 128-bit hash interface.
// A primitive whose underlying SIMD implementation supports
// processing four independent (data, seed) tuples per call provides
// this alongside its single-call HashFunc128 (for example a
// ZMM-batched SipHash-2-4 or AES-CMAC kernel on x86_64 with
// AVX-512 / VAES).
//
// Bit-exact parity invariant. For every i in {0,1,2,3} and arbitrary
// inputs:
//
//	BatchHashFunc128(data, seeds)[i] == HashFunc128(data[i], seeds[i][0], seeds[i][1])
//
// (where the right-hand side's two return values are packed into the
// [2]uint64 row at output position i: out[i][0] = lo, out[i][1] = hi.)
//
// Implementations that violate this break ITB security claims under
// the batched dispatch path: the per-pixel ChainHash output would
// diverge from the serial reference, invalidating the underlying
// PRF assumption. The user-supplied wrapper is responsible for
// preserving this invariant; ITB's test suite (per-primitive parity
// in `hashes/<primitive>_test.go`) demonstrates the required
// structure.
type BatchHashFunc128 func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64

// BatchChainHash128 computes the four-way batched ChainHash128 on four
// pixel buffers in parallel using `s.BatchHash`. Each output position
// matches the serial `ChainHash128(data[i])` under the same seed
// components — the chain composition is identical, just executed four
// lanes at a time per round.
//
// Caller responsibility: `s.BatchHash` must be non-nil. The dispatch
// in `processChunk128` checks this before invoking; user-level
// callers should check explicitly.
func (s *Seed128) BatchChainHash128(buf *[4][]byte) [4][2]uint64 {
	var seeds [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = s.Components[0]
		seeds[lane][1] = s.Components[1]
	}
	h := s.BatchHash(buf, seeds)

	for i := 2; i < len(s.Components); i += 2 {
		c0, c1 := s.Components[i], s.Components[i+1]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}

// blockHash128x4 is the four-way batched counterpart of
// `blockHash128`. Mutates the first four bytes of each `buf[i]` to
// hold the corresponding `pixelIndices[i]` in little-endian, then
// invokes `BatchChainHash128`.
//
// Caller must ensure each `buf[i]` has at least 4 bytes of writable
// storage and that `s.BatchHash != nil`.
func (s *Seed128) blockHash128x4(buf *[4][]byte, pixelIndices [4]int) [4][2]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash128(buf)
}
