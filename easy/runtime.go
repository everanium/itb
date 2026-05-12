package easy

import (
	"runtime/debug"

	_ "github.com/everanium/itb/internal/runtimecfg"
)

// SetMemoryLimit configures the Go runtime's heap-size soft limit
// (bytes). Pass -1 (or any negative value) to query the current limit
// without changing it; the previous limit is returned. Setter calls
// override any ITB_GOMEMLIMIT env var set at libitb load time.
func SetMemoryLimit(limit int64) int64 {
	return debug.SetMemoryLimit(limit)
}

// SetGCPercent configures the Go runtime's GC trigger percentage. The
// default is 100 (GC fires at +100% heap growth); lower values trigger
// GC more aggressively. Pass -1 (or any negative value) to query the
// current value without changing it; the previous value is returned.
// Setter calls override any ITB_GOGC env var set at libitb load time.
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
