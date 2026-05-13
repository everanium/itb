package itb

import (
	"runtime/debug"
	"testing"
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
