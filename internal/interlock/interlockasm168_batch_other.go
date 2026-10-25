//go:build (!amd64 && !arm64) || purego || noitbasm

package interlock

// HasChunk168Batch is always false on non-amd64 / non-arm64 / purego /
// noitbasm.
var HasChunk168Batch = false

// Chunk168LockBatch should never be called when HasChunk168Batch is
// false — the parent package's dispatch runs the per-chunk path. Kept
// as a callable stub so the import resolves cleanly.
func Chunk168LockBatch(src []byte, masks [][3][3]uint64, p0, p1, p2 []byte) {
	panic("interlock: Chunk168LockBatch unavailable on this build")
}

// Unchunk168LockBatch — same stubbed behaviour as Chunk168LockBatch.
func Unchunk168LockBatch(p0, p1, p2 []byte, masks [][3][3]uint64, dst []byte) {
	panic("interlock: Unchunk168LockBatch unavailable on this build")
}
