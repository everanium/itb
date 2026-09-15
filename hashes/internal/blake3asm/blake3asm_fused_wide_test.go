package blake3asm

import (
	"crypto/rand"
	"testing"
)

// blake3asm_fused_wide_test.go — parity scaffolding of the eight-lane
// per-pixel dispatchers shared by every architecture.

type x8fn256 func(*[32]byte, []uint64, *[8]*byte, *[8][4]uint64)

func laneData8(n int) ([8][]byte, [8]*byte) {
	var bufs [8][]byte
	var ptrs [8]*byte
	for l := range bufs {
		bufs[l] = make([]byte, n)
		rand.Read(bufs[l])
		ptrs[l] = &bufs[l][0]
	}
	return bufs, ptrs
}

// checkX8_256 pins an eight-lane evaluator to the reference on random
// inputs at every group count.
func checkX8_256(t *testing.T, label string, n int, f x8fn256) {
	t.Helper()
	for _, g := range groupCounts {
		key := randomKey256()
		comps := randomWords(4 * g)
		bufs, ptrs := laneData8(n)
		var got [8][4]uint64
		f(key, comps, &ptrs, &got)
		for l := range bufs {
			if want := ScalarFusedChain256(key, comps, bufs[l]); got[l] != want {
				t.Fatalf("%s shape %d groups=%d lane %d: got %x want %x", label, n, g, l, got[l], want)
			}
		}
	}
}

func dispatchers256x8() map[int]x8fn256 {
	return map[int]x8fn256{20: Fused256Chain20x8, 36: Fused256Chain36x8, 68: Fused256Chain68x8}
}

// checkWideDispatchers pins the eight-lane dispatchers to the reference
// under the current flag state.
func checkWideDispatchers(t *testing.T, label string) {
	t.Helper()
	for _, n := range []int{20, 36, 68} {
		checkX8_256(t, label+"-256x8", n, dispatchers256x8()[n])
	}
}

// TestFusedWideDispatchersAuto pins the wide dispatchers under the
// build's auto-selected dispatch state.
func TestFusedWideDispatchersAuto(t *testing.T) {
	checkWideDispatchers(t, "auto")
}

// TestFusedWideReference pins the wide reference to the narrow one: an
// eight-lane evaluation is two four-lane evaluations.
func TestFusedWideReference(t *testing.T) {
	key256 := randomKey256()
	c256 := randomWords(8)
	for _, n := range []int{20, 36, 68} {
		_, ptrs := laneData8(n)
		var o256 [8][4]uint64
		scalarFused256X8(key256, c256, &ptrs, n, &o256)
		for h := 0; h < 2; h++ {
			var h256 [4][4]uint64
			scalarFused256X4(key256, c256, ptrs8Half(&ptrs, h), n, &h256)
			if *out8x256Half(&o256, h) != h256 {
				t.Fatalf("shape %d half %d: eight-lane reference diverges from the four-lane reference", n, h)
			}
		}
	}
}

// checkWideZeroAlloc pins that the wide dispatchers allocate nothing
// under the current flag state; not applicable where the pure-Go cascade
// is the arm (see checkZeroAlloc).
func checkWideZeroAlloc(t *testing.T, label string) {
	t.Helper()
	if !FusedAvailable() {
		t.Logf("%s: pure-Go cascade; allocation guard not applicable", label)
		return
	}
	k256 := randomKey256()
	c256 := randomWords(8)
	_, ptrs := laneData8(68)
	var o256 [8][4]uint64
	check := func(name string, fn func()) {
		if a := testing.AllocsPerRun(20, fn); a != 0 {
			t.Fatalf("%s %s: %v allocs per call", label, name, a)
		}
	}
	for n, f := range dispatchers256x8() {
		check(shapeName(n)+"-256x8", func() { f(k256, c256, &ptrs, &o256) })
	}
}

// TestFusedWideDispatchersZeroAlloc runs the allocation guard under the
// auto-selected dispatch state.
func TestFusedWideDispatchersZeroAlloc(t *testing.T) {
	checkWideZeroAlloc(t, "auto")
}
