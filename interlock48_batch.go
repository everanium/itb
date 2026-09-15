package itb

import "github.com/everanium/itb/internal/interlock"

// chunk48lockBatch applies [chunk48lock] to the n consecutive chunks
// k .. k+n-1 (clamped to the chunk count M) through the batched
// [interlock.Chunk48LockBatch] kernel, writing the little-endian lane
// values at p_i[2k : 2(k+n)]. Returns false — and performs no work —
// when the batched kernel is not selected on this host or when the
// source window is not wholly inside src.body (the chunk straddling
// the head / body boundary, or the zero-padded tail chunk), so the
// caller runs its per-chunk loop instead. Bit-exact with that loop.
func chunk48lockBatch(src framedSrc48, M, k, n int, masks [][3]uint64, p0, p1, p2 []byte) bool {
	if !interlock.HasChunk48Batch {
		return false
	}
	if M-k < n {
		n = M - k
	}
	if n <= 0 {
		return false
	}
	base := 6*k - len(src.head)
	if base < 0 || base+6*n > len(src.body) {
		return false
	}
	interlock.Chunk48LockBatch(src.body[base:base+6*n], masks[:n], p0[2*k:], p1[2*k:], p2[2*k:])
	return true
}

// unchunk48lockBatch applies [unchunk48lock] to the n consecutive
// chunks k .. k+n-1 (clamped to M) through the batched
// [interlock.Unchunk48LockBatch] kernel, reading the little-endian lane
// values at p_i[2k : 2(k+n)] and writing the recovered chunk bytes at
// result[6k : 6(k+n)]. Returns false — and performs no work — when the
// batched kernel is not selected on this host, so the caller runs its
// per-chunk loop instead. Bit-exact with that loop.
func unchunk48lockBatch(result []byte, M, k, n int, masks [][3]uint64, p0, p1, p2 []byte) bool {
	if !interlock.HasChunk48Batch {
		return false
	}
	if M-k < n {
		n = M - k
	}
	if n <= 0 {
		return false
	}
	interlock.Unchunk48LockBatch(p0[2*k:], p1[2*k:], p2[2*k:], masks[:n], result[6*k:])
	return true
}
