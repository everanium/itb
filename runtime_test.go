package itb

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/everanium/itb/internal/poolstats"
)

// TestSetMemoryLimitGetSet verifies that SetMemoryLimit installs a
// new heap soft-limit and returns the previous value. The test
// captures the limit on entry and restores it via t.Cleanup so the
// post-test process state matches the pre-test state.
func TestSetMemoryLimitGetSet(t *testing.T) {
	// Capture the initial limit via the same setter (the negative
	// argument returns the current value without mutating it).
	initial := SetMemoryLimit(-1)
	t.Cleanup(func() {
		SetMemoryLimit(initial)
	})

	const target = int64(256 << 20) // 256 MiB
	prev := SetMemoryLimit(target)
	if prev != initial {
		t.Fatalf("SetMemoryLimit(%d): returned previous=%d, want %d", target, prev, initial)
	}
	if got := SetMemoryLimit(-1); got != target {
		t.Fatalf("SetMemoryLimit query: got %d, want %d", got, target)
	}
}

// TestSetMemoryLimitQuery confirms that a negative argument returns
// the current limit without changing it. The probe sets a known
// target first, queries via -1, then verifies the query did not
// alter the live limit.
func TestSetMemoryLimitQuery(t *testing.T) {
	initial := SetMemoryLimit(-1)
	t.Cleanup(func() {
		SetMemoryLimit(initial)
	})

	const target = int64(128 << 20) // 128 MiB
	SetMemoryLimit(target)

	queried := SetMemoryLimit(-1)
	if queried != target {
		t.Fatalf("SetMemoryLimit(-1): got %d, want %d (query must not mutate)", queried, target)
	}
	if got := SetMemoryLimit(-1); got != target {
		t.Fatalf("SetMemoryLimit second query: got %d, want %d", got, target)
	}
}

// TestSetGCPercentGetSet verifies that SetGCPercent installs a new
// GC trigger percentage and returns the previous value. The test
// captures the percentage on entry via the protected query path and
// restores it via t.Cleanup.
func TestSetGCPercentGetSet(t *testing.T) {
	initial := SetGCPercent(-1)
	t.Cleanup(func() {
		SetGCPercent(initial)
	})

	const target = 50
	prev := SetGCPercent(target)
	if prev != initial {
		t.Fatalf("SetGCPercent(%d): returned previous=%d, want %d", target, prev, initial)
	}
	if got := SetGCPercent(-1); got != target {
		t.Fatalf("SetGCPercent query: got %d, want %d", got, target)
	}
}

// TestSetGCPercentQuery confirms that a negative argument returns
// the current GC percentage without mutating it. Critically, the
// wrapper's protected query path must NOT disable GC despite passing
// -1 — the round-trip set-then-restore inside SetGCPercent preserves
// whatever percentage was previously live.
func TestSetGCPercentQuery(t *testing.T) {
	initial := SetGCPercent(-1)
	t.Cleanup(func() {
		SetGCPercent(initial)
	})

	const target = 75
	SetGCPercent(target)

	// Invoke the protected query path twice; both must return the
	// installed target and neither must disable GC.
	queried := SetGCPercent(-1)
	if queried != target {
		t.Fatalf("SetGCPercent(-1) #1: got %d, want %d (query must not mutate)", queried, target)
	}
	queried2 := SetGCPercent(-1)
	if queried2 != target {
		t.Fatalf("SetGCPercent(-1) #2: got %d, want %d (query must not mutate)", queried2, target)
	}

	// Cross-check via runtime/debug.SetGCPercent: passing -1 to
	// debug.SetGCPercent returns the live percentage AND disables
	// GC, so this assertion both confirms the live percentage is
	// the target value and re-enables GC at the same percentage
	// for the rest of the test process. The wrapper's protected
	// query did NOT leave GC disabled; only this direct probe
	// briefly does so before restoring.
	directQuery := debug.SetGCPercent(-1)
	if directQuery != target {
		t.Fatalf("debug.SetGCPercent(-1) live probe: got %d, want %d (wrapper query mutated state)", directQuery, target)
	}
	// Restore — debug.SetGCPercent(-1) above disabled GC; reinstate
	// the target percentage before t.Cleanup fires.
	debug.SetGCPercent(target)
}

// TestSetGOMAXPROCSGetSet pins the query / set / restore contract: a
// non-positive argument reports the current value without changing
// it, a positive argument installs the new value and returns the
// previous one.
func TestSetGOMAXPROCSGetSet(t *testing.T) {
	initial := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(initial)
	})

	if got := SetGOMAXPROCS(0); got != initial {
		t.Fatalf("SetGOMAXPROCS(0) = %d, want current %d", got, initial)
	}
	if got := SetGOMAXPROCS(-3); got != initial {
		t.Fatalf("SetGOMAXPROCS(-3) = %d, want current %d", got, initial)
	}
	if got := runtime.GOMAXPROCS(0); got != initial {
		t.Fatalf("query changed GOMAXPROCS to %d, want %d untouched", got, initial)
	}
	next := initial + 1
	if prev := SetGOMAXPROCS(next); prev != initial {
		t.Fatalf("SetGOMAXPROCS(%d) returned %d, want previous %d", next, prev, initial)
	}
	if got := runtime.GOMAXPROCS(0); got != next {
		t.Fatalf("GOMAXPROCS after set = %d, want %d", got, next)
	}
}

// TestWriteHeapProfile writes a profile to a temp path and checks a
// non-empty file appears; an empty path and an unwritable directory
// are rejected with an error.
func TestWriteHeapProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heap.prof")
	if err := WriteHeapProfile(path); err != nil {
		t.Fatalf("WriteHeapProfile(%q): %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("profile at %q: stat err=%v, want a non-empty file", path, err)
	}
	if err := WriteHeapProfile(""); err == nil {
		t.Fatalf("WriteHeapProfile(\"\") = nil, want an error")
	}
	bad := filepath.Join(dir, "missing-dir", "heap.prof")
	if err := WriteHeapProfile(bad); err == nil {
		t.Fatalf("WriteHeapProfile(%q) = nil, want an error", bad)
	}
}

// TestPoolStatsLayout checks the slot-count formula, the too-short
// forms, and that a filled buffer agrees slot for slot with a
// poolstats.Take snapshot bracketing the call.
func TestPoolStatsLayout(t *testing.T) {
	want := 1 + 5*poolstats.MaxHashTiers + 8
	if got := PoolStatsLen(); got != want {
		t.Fatalf("PoolStatsLen() = %d, want %d", got, want)
	}
	if n := PoolStats(nil); n != want {
		t.Fatalf("PoolStats(nil) = %d, want %d", n, want)
	}
	short := make([]int64, want-1)
	if n := PoolStats(short); n != want {
		t.Fatalf("PoolStats(short) = %d, want %d", n, want)
	}
	for i, v := range short {
		if v != 0 {
			t.Fatalf("PoolStats(short) wrote slot %d", i)
		}
	}

	before := poolstats.Take()
	dst := make([]int64, want+3)
	n := PoolStats(dst)
	after := poolstats.Take()
	if n != want {
		t.Fatalf("PoolStats(dst) = %d, want %d", n, want)
	}
	if dst[0] != poolstats.MaxHashTiers {
		t.Fatalf("slot 0 = %d, want tier count %d", dst[0], poolstats.MaxHashTiers)
	}
	within := func(name string, slot int, lo, hi int64) {
		if dst[slot] < lo || dst[slot] > hi {
			t.Errorf("%s (slot %d) = %d, want within [%d, %d]", name, slot, dst[slot], lo, hi)
		}
	}
	for i := 0; i < poolstats.MaxHashTiers; i++ {
		base := 1 + 5*i
		if dst[base] != before.HashStarter[i] || dst[base] != after.HashStarter[i] {
			t.Errorf("tier %d starter = %d, want %d", i, dst[base], before.HashStarter[i])
		}
		within("hash get", base+1, before.HashGet[i], after.HashGet[i])
		within("hash new", base+2, before.HashNew[i], after.HashNew[i])
		within("hash regrow", base+3, before.HashRegrow[i], after.HashRegrow[i])
		within("hash new bytes", base+4, before.HashNewBytes[i], after.HashNewBytes[i])
	}
	tail := 1 + 5*poolstats.MaxHashTiers
	within("buf get", tail+0, before.BufGet, after.BufGet)
	within("buf new", tail+1, before.BufNew, after.BufNew)
	within("buf regrow", tail+2, before.BufRegrow, after.BufRegrow)
	within("buf regrow bytes", tail+3, before.BufRegrowBytes, after.BufRegrowBytes)
	within("chunk get", tail+4, before.ChunkGet, after.ChunkGet)
	within("chunk new", tail+5, before.ChunkNew, after.ChunkNew)
	within("chunk regrow", tail+6, before.ChunkRegrow, after.ChunkRegrow)
	within("chunk regrow bytes", tail+7, before.ChunkRegrowBytes, after.ChunkRegrowBytes)
	for i := want; i < len(dst); i++ {
		if dst[i] != 0 {
			t.Errorf("slot %d beyond the layout was written (%d)", i, dst[i])
		}
	}
}
