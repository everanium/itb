package itb

import (
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"

	"github.com/everanium/itb/internal/poolstats"
	_ "github.com/everanium/itb/internal/runtimecfg"
)

// SetMemoryLimit configures the Go runtime's heap-size soft limit
// (bytes). Pass -1 (or any negative value) to query the current limit
// without changing it; the previous limit is returned. Setter calls
// override any ITB_GOMEMLIMIT env var set at libitb3 load time.
func SetMemoryLimit(limit int64) int64 {
	return debug.SetMemoryLimit(limit)
}

// SetGCPercent configures the Go runtime's GC trigger percentage. The
// default is 100 (GC fires at +100% heap growth); lower values trigger
// GC more aggressively. Pass -1 (or any negative value) to query the
// current value without changing it; the previous value is returned.
// Setter calls override any ITB_GOGC env var set at libitb3 load time.
func SetGCPercent(pct int) int {
	if pct < 0 {
		// Query mode — round-trip set-then-restore to retrieve current
		// without long-term change. debug.SetGCPercent has no native
		// query path; every call sets. Use 100 as the sentinel pass
		// since it is the documented default and a benign target.
		curr := debug.SetGCPercent(100)
		debug.SetGCPercent(curr)
		return curr
	}
	return debug.SetGCPercent(pct)
}

// SetGOMAXPROCS configures the Go runtime's GOMAXPROCS — the number of
// OS threads executing Go code simultaneously. Pass 0 (or any negative
// value) to query the current value without changing it; the previous
// value is returned, matching runtime.GOMAXPROCS. Setter calls override
// any ITB_GOMAXPROCS env var set at load time.
func SetGOMAXPROCS(n int) int {
	if n <= 0 {
		return runtime.GOMAXPROCS(0)
	}
	return runtime.GOMAXPROCS(n)
}

// errHeapProfilePath is returned by WriteHeapProfile for an empty path.
var errHeapProfilePath = errors.New("itb: heap profile path is empty")

// WriteHeapProfile writes the Go runtime's heap profile (pprof format,
// readable with `go tool pprof`) to path. One garbage collection runs
// first so the in-use figures describe the live heap at the call
// rather than the heap as of the last collection the runtime happened
// to schedule; the alloc_space / alloc_objects samples are cumulative
// since process start either way. An empty path is rejected;
// file-system failures are returned as the os error.
func WriteHeapProfile(path string) error {
	if path == "" {
		return errHeapProfilePath
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	runtime.GC()
	werr := pprof.Lookup("heap").WriteTo(f, 0)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// Pool-counter slot layout shared by PoolStatsLen and PoolStats. The
// same vector crosses the C ABI unchanged (ITB_PoolStatsLen /
// ITB_PoolStats), so the layout is one contract for Go callers and
// for every binding:
//
//	slot 0                      number of hash-array pool tiers (T)
//	slot 1 + 5*i + 0            tier i starter width (uint64 elements); 0 for an unused tier
//	slot 1 + 5*i + 1            tier i checkouts
//	slot 1 + 5*i + 2            tier i constructor misses
//	slot 1 + 5*i + 3            tier i regrow replacements
//	slot 1 + 5*i + 4            tier i bytes allocated by misses + regrows
//	slot 1 + 5*T + 0 .. 3       scratch byte pool: get, new, regrow, regrow bytes
//	slot 1 + 5*T + 4 .. 7       parallax chunk pool: get, new, regrow, regrow bytes
const (
	poolStatsHeadSlots = 1
	poolStatsPerTier   = 5
	poolStatsTailSlots = 8
)

// PoolStatsLen returns the number of int64 slots PoolStats fills.
// Callers size their buffer from this value rather than a constant:
// the count grows if a pool is added.
func PoolStatsLen() int {
	return poolStatsHeadSlots + poolStatsPerTier*poolstats.MaxHashTiers + poolStatsTailSlots
}

// PoolStats copies the library's pool hit / miss counters into dst
// under the slot layout documented above and returns the slot count
// written. When dst is shorter than PoolStatsLen (a nil dst included)
// nothing is written and the required count is returned. Every counter
// is a monotonically increasing total since process start; a consumer
// differences two snapshots to describe an interval.
func PoolStats(dst []int64) int {
	need := PoolStatsLen()
	if len(dst) < need {
		return need
	}
	s := poolstats.Take()
	dst[0] = poolstats.MaxHashTiers
	for i := 0; i < poolstats.MaxHashTiers; i++ {
		base := poolStatsHeadSlots + poolStatsPerTier*i
		dst[base+0] = s.HashStarter[i]
		dst[base+1] = s.HashGet[i]
		dst[base+2] = s.HashNew[i]
		dst[base+3] = s.HashRegrow[i]
		dst[base+4] = s.HashNewBytes[i]
	}
	tail := poolStatsHeadSlots + poolStatsPerTier*poolstats.MaxHashTiers
	dst[tail+0] = s.BufGet
	dst[tail+1] = s.BufNew
	dst[tail+2] = s.BufRegrow
	dst[tail+3] = s.BufRegrowBytes
	dst[tail+4] = s.ChunkGet
	dst[tail+5] = s.ChunkNew
	dst[tail+6] = s.ChunkRegrow
	dst[tail+7] = s.ChunkRegrowBytes
	return need
}
