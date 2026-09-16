package capi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/everanium/itb/internal/poolstats"
)

// TestSetGOMAXPROCS pins the query / set / restore contract: a
// non-positive argument reports the current value without changing
// it, a positive argument installs the new value and returns the
// previous one.
func TestSetGOMAXPROCS(t *testing.T) {
	orig := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(orig)

	if got := SetGOMAXPROCS(0); got != orig {
		t.Fatalf("SetGOMAXPROCS(0) = %d, want current %d", got, orig)
	}
	if got := SetGOMAXPROCS(-7); got != orig {
		t.Fatalf("SetGOMAXPROCS(-7) = %d, want current %d", got, orig)
	}
	if got := runtime.GOMAXPROCS(0); got != orig {
		t.Fatalf("query changed GOMAXPROCS to %d, want %d untouched", got, orig)
	}

	next := orig + 1
	if prev := SetGOMAXPROCS(next); prev != orig {
		t.Fatalf("SetGOMAXPROCS(%d) returned %d, want previous %d", next, prev, orig)
	}
	if got := runtime.GOMAXPROCS(0); got != next {
		t.Fatalf("GOMAXPROCS after set = %d, want %d", got, next)
	}
	if prev := SetGOMAXPROCS(orig); prev != next {
		t.Fatalf("restore returned %d, want %d", prev, next)
	}
}

// TestWriteHeapProfile writes a profile to a temp path and checks a
// non-empty file appears; then exercises the empty-path fallback both
// with and without ITB_MEMPROFILE, and an unwritable directory.
func TestWriteHeapProfile(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "explicit.prof")
	if st := WriteHeapProfile(path); st != StatusOK {
		t.Fatalf("WriteHeapProfile(%q) = %v (%s), want OK", path, st, LastError())
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("profile at %q: stat err=%v size=%d, want a non-empty file", path, err, sizeOf(fi))
	}

	t.Setenv(memProfileEnv, "")
	if st := WriteHeapProfile(""); st != StatusBadInput {
		t.Fatalf("WriteHeapProfile(\"\") with env unset = %v, want BadInput", st)
	}
	if LastError() == "" {
		t.Fatalf("empty-path rejection left no diagnostic in LastError")
	}

	envPath := filepath.Join(dir, "from-env.prof")
	t.Setenv(memProfileEnv, envPath)
	if st := WriteHeapProfile(""); st != StatusOK {
		t.Fatalf("WriteHeapProfile(\"\") with env set = %v (%s), want OK", st, LastError())
	}
	if fi, err := os.Stat(envPath); err != nil || fi.Size() == 0 {
		t.Fatalf("profile at env path %q: stat err=%v size=%d", envPath, err, sizeOf(fi))
	}

	bad := filepath.Join(dir, "missing-dir", "x.prof")
	if st := WriteHeapProfile(bad); st != StatusBadInput {
		t.Fatalf("WriteHeapProfile(%q) = %v, want BadInput", bad, st)
	}
}

func sizeOf(fi os.FileInfo) int64 {
	if fi == nil {
		return -1
	}
	return fi.Size()
}

// TestPoolStatsLayout checks the slot count formula, the probe form,
// the too-small form, and that a filled buffer agrees slot for slot
// with a poolstats.Take snapshot bracketing the call.
func TestPoolStatsLayout(t *testing.T) {
	want := 1 + 5*poolstats.MaxHashTiers + 8
	if got := PoolStatsLen(); got != want {
		t.Fatalf("PoolStatsLen() = %d, want %d", got, want)
	}

	if n, st := PoolStats(nil); st != StatusBufferTooSmall || n != want {
		t.Fatalf("PoolStats(nil) = (%d, %v), want (%d, BufferTooSmall)", n, st, want)
	}
	short := make([]int64, want-1)
	if n, st := PoolStats(short); st != StatusBufferTooSmall || n != want {
		t.Fatalf("PoolStats(short) = (%d, %v), want (%d, BufferTooSmall)", n, st, want)
	}

	before := poolstats.Take()
	dst := make([]int64, want+3)
	n, st := PoolStats(dst)
	after := poolstats.Take()
	if st != StatusOK || n != want {
		t.Fatalf("PoolStats(dst) = (%d, %v), want (%d, OK)", n, st, want)
	}
	if dst[0] != poolstats.MaxHashTiers {
		t.Fatalf("slot 0 = %d, want tier count %d", dst[0], poolstats.MaxHashTiers)
	}
	// Counters only grow; every slot must sit between the two
	// bracketing snapshots.
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
