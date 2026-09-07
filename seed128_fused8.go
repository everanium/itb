package itb

import "encoding/binary"

// BatchFusedChainHashFunc128x8 is the eight-lane counterpart of
// [BatchFusedChainHashFunc128]: every lane runs the whole ChainHash128
// cascade over the shared components with its own data, and the result
// must be bit-exact with two [BatchFusedChainHashFunc128] evaluations
// over the lane halves (and hence with eight sequential cascades). ok
// reports whether the implementation handled data; when false the
// caller runs the four-lane path twice and out is meaningless.
// Implementations decide by input shape only.
//
// The hook is the pixel pipeline's eight-pixel stride: when both the
// noise and the data seed carry it, processChunk128 hashes eight pixels
// per call ahead of the four-pixel and single-pixel tails. Shipped
// primitives attach it only on hosts whose selected tier carries an
// eight-lane kernel (aesitb128 on VAES + AVX-512 silicon, through
// hashes.AttachFused128), so every other host keeps the four-lane stride
// unchanged.
type BatchFusedChainHashFunc128x8 func(components []uint64, data *[8][]byte) (out [8][2]uint64, ok bool)

// SetBatchFusedChain8 installs the eight-lane fused cascade hook. nil
// removes it; the pixel pipeline then keeps the four-lane stride. The
// hook is a performance path only: with or without it the seed produces
// the same wire.
func (s *Seed128) SetBatchFusedChain8(fn BatchFusedChainHashFunc128x8) {
	s.batchFusedChainX8 = fn
}

// BatchFusedChain8 returns the installed eight-lane fused cascade hook,
// nil when none is attached.
func (s *Seed128) BatchFusedChain8() BatchFusedChainHashFunc128x8 {
	return s.batchFusedChainX8
}

// batchChainHash128x8 runs the eight-lane batched ChainHash128: the
// eight-lane hook first, otherwise two [Seed128.BatchChainHash128] calls
// over the lane halves. Output [i] matches serial ChainHash128(buf[i])
// under the same Components. Caller ensures s.BatchHash != nil.
func (s *Seed128) batchChainHash128x8(buf *[8][]byte) [8][2]uint64 {
	if s.batchFusedChainX8 != nil {
		if out, ok := s.batchFusedChainX8(s.Components, buf); ok {
			return out
		}
	}
	var out [8][2]uint64
	lo := [4][]byte{buf[0], buf[1], buf[2], buf[3]}
	hi := [4][]byte{buf[4], buf[5], buf[6], buf[7]}
	h := s.BatchChainHash128(&lo)
	copy(out[0:4], h[:])
	h = s.BatchChainHash128(&hi)
	copy(out[4:8], h[:])
	return out
}

// blockHash128x8 is the eight-way counterpart of blockHash128x4. Writes
// pixelIndices[i] as little-endian uint32 into buf[i]'s first four
// bytes, then runs the eight-lane batched chain hash.
func (s *Seed128) blockHash128x8(buf *[8][]byte, pixelIndices [8]int) [8][2]uint64 {
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buf[i], uint32(pixelIndices[i]))
	}
	return s.batchChainHash128x8(buf)
}
