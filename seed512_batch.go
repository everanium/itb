package itb

import "encoding/binary"

// BatchHashFunc512 is the 4-way batched 512-bit hash counterpart of
// BatchHashFunc256. See BatchHashFunc256 documentation for the
// security-critical bit-exact parity invariant; the same requirement
// applies here.
type BatchHashFunc512 func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64

// BatchChainHash512 computes the four-way batched ChainHash512 on four
// pixel buffers in parallel using `s.BatchHash`. Output position [i]
// matches serial `ChainHash512(data[i])` under the same seed
// components.
func (s *Seed512) BatchChainHash512(buf *[4][]byte) [4][8]uint64 {
	var seeds [4][8]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = s.Components[0]
		seeds[lane][1] = s.Components[1]
		seeds[lane][2] = s.Components[2]
		seeds[lane][3] = s.Components[3]
		seeds[lane][4] = s.Components[4]
		seeds[lane][5] = s.Components[5]
		seeds[lane][6] = s.Components[6]
		seeds[lane][7] = s.Components[7]
	}
	h := s.BatchHash(buf, seeds)

	for i := 8; i < len(s.Components); i += 8 {
		c0, c1, c2, c3 := s.Components[i], s.Components[i+1], s.Components[i+2], s.Components[i+3]
		c4, c5, c6, c7 := s.Components[i+4], s.Components[i+5], s.Components[i+6], s.Components[i+7]
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = c0 ^ h[lane][0]
			seeds[lane][1] = c1 ^ h[lane][1]
			seeds[lane][2] = c2 ^ h[lane][2]
			seeds[lane][3] = c3 ^ h[lane][3]
			seeds[lane][4] = c4 ^ h[lane][4]
			seeds[lane][5] = c5 ^ h[lane][5]
			seeds[lane][6] = c6 ^ h[lane][6]
			seeds[lane][7] = c7 ^ h[lane][7]
		}
		h = s.BatchHash(buf, seeds)
	}
	return h
}

// blockHash512x4 is the four-way batched counterpart of `blockHash512`.
// Mutates the first four bytes of each `buf[i]` with the corresponding
// `pixelIndices[i]` in little-endian, then runs the batched chain hash.
func (s *Seed512) blockHash512x4(buf *[4][]byte, pixelIndices [4]int) [4][8]uint64 {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.BatchChainHash512(buf)
}
