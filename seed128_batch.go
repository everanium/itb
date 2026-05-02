package itb

import "encoding/binary"

// BatchHashFunc128 is the 4-way batched 128-bit hash interface
// alongside [HashFunc128]. Primitives whose SIMD kernel processes
// four independent (data, seed) tuples per call expose this — e.g.
// the ZMM-batched SipHash-2-4 / AES-CMAC kernels on amd64 with
// AVX-512 + VAES.
//
// Bit-exact parity invariant: each lane output
// BatchHashFunc128(data, seeds)[i] matches the serial
// HashFunc128(data[i], seeds[i][0], seeds[i][1]) reference.
// Implementations violating this break the PRF assumption on the
// batched dispatch path.
type BatchHashFunc128 func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64

// BatchChainHash128 runs the four-way batched ChainHash128 via
// s.BatchHash. Output [i] matches serial ChainHash128(data[i])
// under the same Components. Caller ensures s.BatchHash != nil
// (processChunk128 checks this before invoking).
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

// blockHash128x4 is the four-way counterpart of blockHash128.
// Writes pixelIndices[i] as little-endian uint32 into buf[i]'s
// first four bytes, then runs the batched chain hash.
func (s *Seed128) blockHash128x4(buf *[4][]byte, pixelIndices [4]int) [4][2]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash128(buf)
}
