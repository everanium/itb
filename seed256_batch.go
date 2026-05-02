package itb

import "encoding/binary"

// BatchHashFunc256 is the 4-way batched 256-bit hash interface
// alongside [HashFunc256]. Primitives whose SIMD kernel processes
// four independent (data, seed) tuples per call expose this — e.g.
// the ZMM-batched Areion-SoEM-256 / BLAKE3 / BLAKE2s / ChaCha20
// kernels on amd64 with AVX-512 + VAES.
//
// Bit-exact parity invariant: each lane output
// BatchHashFunc256(data, seeds)[i] matches the serial
// HashFunc256(data[i], seeds[i]) reference. Implementations
// violating this break the PRF assumption on the batched dispatch
// path.
type BatchHashFunc256 func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64

// BatchChainHash256 runs the four-way batched ChainHash256 via
// s.BatchHash. Output [i] matches serial ChainHash256(data[i])
// under the same Components. Caller ensures s.BatchHash != nil
// (processChunk256 checks this before invoking).
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

// blockHash256x4 is the four-way counterpart of blockHash256.
// Writes pixelIndices[i] as little-endian uint32 into buf[i]'s
// first four bytes, then runs the batched chain hash.
func (s *Seed256) blockHash256x4(buf *[4][]byte, pixelIndices [4]int) [4][4]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash256(buf)
}
