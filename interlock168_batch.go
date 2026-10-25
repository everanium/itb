package itb

import "github.com/everanium/itb/internal/interlock"

// chunk168lockBatch applies [chunk168lock] to the n consecutive chunks
// k .. k+n-1 (clamped to the chunk count M) through the batched
// [interlock.Chunk168LockBatch] kernel, writing the 7-byte little-endian
// lane values at p_i[7k : 7(k+n)]. Returns false — and performs no work —
// when the batched kernel is not selected on this host or when the
// source window is not wholly inside src.body (the chunk straddling
// the head / body boundary, or the zero-padded tail chunk), so the
// caller runs its per-chunk loop instead. Bit-exact with that loop.
func chunk168lockBatch(src framedSrc168, M, k, n int, masks [][3][3]uint64, p0, p1, p2 []byte) bool {
	if !interlock.HasChunk168Batch {
		return false
	}
	if M-k < n {
		n = M - k
	}
	if n <= 0 {
		return false
	}
	base := 21*k - len(src.head)
	if base < 0 || base+21*n > len(src.body) {
		return false
	}
	interlock.Chunk168LockBatch(src.body[base:base+21*n], masks[:n], p0[7*k:], p1[7*k:], p2[7*k:])
	return true
}

// unchunk168lockBatch applies [unchunk168lock] to the n consecutive
// chunks k .. k+n-1 (clamped to M) through the batched
// [interlock.Unchunk168LockBatch] kernel, reading the 7-byte little-endian
// lane values at p_i[7k : 7(k+n)] and writing the recovered 21-byte chunk
// values at result[21k : 21(k+n)]. Returns false — and performs no work —
// when the batched kernel is not selected on this host, so the caller runs
// its per-chunk loop instead. Bit-exact with that loop.
func unchunk168lockBatch(result []byte, M, k, n int, masks [][3][3]uint64, p0, p1, p2 []byte) bool {
	if !interlock.HasChunk168Batch {
		return false
	}
	if M-k < n {
		n = M - k
	}
	if n <= 0 {
		return false
	}
	interlock.Unchunk168LockBatch(p0[7*k:], p1[7*k:], p2[7*k:], masks[:n], result[21*k:])
	return true
}
