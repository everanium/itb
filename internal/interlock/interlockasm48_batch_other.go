//go:build !amd64 || purego || noitbasm

package interlock

// HasChunk48Batch is always false on non-amd64 / purego / noitbasm.
const HasChunk48Batch = false

// Chunk48LockBatch should never be called when HasChunk48Batch is
// false — the parent package's dispatch runs the per-chunk path. Kept
// as a callable stub so the import resolves cleanly.
func Chunk48LockBatch(src []byte, masks [][3]uint64, p0, p1, p2 []byte) {
	panic("interlock: Chunk48LockBatch unavailable on this build")
}

// Unchunk48LockBatch — same stubbed behaviour as Chunk48LockBatch.
func Unchunk48LockBatch(p0, p1, p2 []byte, masks [][3]uint64, dst []byte) {
	panic("interlock: Unchunk48LockBatch unavailable on this build")
}
