// Package poolstats carries process-wide hit / miss counters for the
// sync.Pool sites of the Low-Level encrypt / decrypt pipeline. The
// counters are measurement scaffolding: the itb package increments
// them at every pool checkout, and tools/loop reads them into its
// final summary so a long-run harness can tell whether a pool keeps
// its items warm between calls or evicts them across GC cycles.
//
// Every counter is a monotonically increasing atomic; readers snapshot
// two points in time and difference them.
package poolstats

import "sync/atomic"

// MaxHashTiers bounds the per-tier hash-array counters; the shipped
// starter ladder has two tiers and the env override rarely exceeds a
// handful.
const MaxHashTiers = 8

// Hash-array pool (process_cgo.go hashPools), per starter tier.
var (
	// HashStarter records the starter width (uint64 elements per array)
	// of tier i; zero for tiers the ladder does not use.
	HashStarter [MaxHashTiers]atomic.Int64
	// HashGet counts checkouts from tier i.
	HashGet [MaxHashTiers]atomic.Int64
	// HashNew counts pool misses on tier i — checkouts that ran the
	// pool's New constructor (a fresh starter-width allocation).
	HashNew [MaxHashTiers]atomic.Int64
	// HashRegrow counts checkouts whose pooled item was narrower than
	// the requested width and was replaced by a fresh allocation.
	HashRegrow [MaxHashTiers]atomic.Int64
	// HashNewBytes accumulates the bytes allocated by HashNew and
	// HashRegrow events on tier i.
	HashNewBytes [MaxHashTiers]atomic.Int64
)

// Scratch byte pool (bytepool.go bufferPool).
var (
	// BufGet counts acquireBuffer calls.
	BufGet atomic.Int64
	// BufNew counts pool misses — acquires that ran the New constructor.
	BufNew atomic.Int64
	// BufRegrow counts acquires whose pooled buffer was too small and
	// was replaced by a fresh allocation.
	BufRegrow atomic.Int64
	// BufRegrowBytes accumulates the bytes allocated by BufRegrow.
	BufRegrowBytes atomic.Int64
)

// Parallax stream chunk pool (parallax/stream.go streamChunkPool).
var (
	// ChunkGet counts acquireChunkBuffer calls.
	ChunkGet atomic.Int64
	// ChunkNew counts pool misses — acquires that ran the New constructor.
	ChunkNew atomic.Int64
	// ChunkRegrow counts acquires whose pooled buffer was too small and
	// was replaced by a fresh allocation.
	ChunkRegrow atomic.Int64
	// ChunkRegrowBytes accumulates the bytes allocated by ChunkRegrow.
	ChunkRegrowBytes atomic.Int64
)

// Snapshot is a point-in-time copy of every counter.
type Snapshot struct {
	HashStarter                                       [MaxHashTiers]int64
	HashGet, HashNew, HashRegrow, HashNewBytes        [MaxHashTiers]int64
	BufGet, BufNew, BufRegrow, BufRegrowBytes         int64
	ChunkGet, ChunkNew, ChunkRegrow, ChunkRegrowBytes int64
}

// Take returns the current counter values.
func Take() Snapshot {
	var s Snapshot
	for i := 0; i < MaxHashTiers; i++ {
		s.HashStarter[i] = HashStarter[i].Load()
		s.HashGet[i] = HashGet[i].Load()
		s.HashNew[i] = HashNew[i].Load()
		s.HashRegrow[i] = HashRegrow[i].Load()
		s.HashNewBytes[i] = HashNewBytes[i].Load()
	}
	s.BufGet = BufGet.Load()
	s.BufNew = BufNew.Load()
	s.BufRegrow = BufRegrow.Load()
	s.BufRegrowBytes = BufRegrowBytes.Load()
	s.ChunkGet = ChunkGet.Load()
	s.ChunkNew = ChunkNew.Load()
	s.ChunkRegrow = ChunkRegrow.Load()
	s.ChunkRegrowBytes = ChunkRegrowBytes.Load()
	return s
}

// Sub returns s minus base, field by field.
func (s Snapshot) Sub(base Snapshot) Snapshot {
	var d Snapshot
	for i := 0; i < MaxHashTiers; i++ {
		d.HashStarter[i] = s.HashStarter[i]
		d.HashGet[i] = s.HashGet[i] - base.HashGet[i]
		d.HashNew[i] = s.HashNew[i] - base.HashNew[i]
		d.HashRegrow[i] = s.HashRegrow[i] - base.HashRegrow[i]
		d.HashNewBytes[i] = s.HashNewBytes[i] - base.HashNewBytes[i]
	}
	d.BufGet = s.BufGet - base.BufGet
	d.BufNew = s.BufNew - base.BufNew
	d.BufRegrow = s.BufRegrow - base.BufRegrow
	d.BufRegrowBytes = s.BufRegrowBytes - base.BufRegrowBytes
	d.ChunkGet = s.ChunkGet - base.ChunkGet
	d.ChunkNew = s.ChunkNew - base.ChunkNew
	d.ChunkRegrow = s.ChunkRegrow - base.ChunkRegrow
	d.ChunkRegrowBytes = s.ChunkRegrowBytes - base.ChunkRegrowBytes
	return d
}
