package blake2basm

import (
	"crypto/rand"
	"testing"
)

// areionasm_fused_wide_test.go — parity scaffolding of the eight-lane
// per-pixel dispatchers and the batch-32 fill hooks shared by every
// architecture.

type x8fn256 func(*[32]byte, []uint64, *[8]*byte, *[8][4]uint64)
type x8fn512 func(*[64]byte, []uint64, *[8]*byte, *[8][8]uint64)
type fill8fn512 func(*[64]byte, []uint64, uint64, *[8][8]uint64)

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

// checkX8_256 pins an eight-lane width-256 evaluator to the reference on
// random inputs at every group count.
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

func checkX8_512(t *testing.T, label string, n int, f x8fn512) {
	t.Helper()
	for _, g := range groupCounts {
		key := randomKey512()
		comps := randomWords(8 * g)
		bufs, ptrs := laneData8(n)
		var got [8][8]uint64
		f(key, comps, &ptrs, &got)
		for l := range bufs {
			if want := ScalarFusedChain512(key, comps, bufs[l]); got[l] != want {
				t.Fatalf("%s shape %d groups=%d lane %d: got %x want %x", label, n, g, l, got[l], want)
			}
		}
	}
}

// checkFill512X8 pins the width-512 batch-32 fill hook to the reference
// at group index bases that carry through every byte of the index.
func checkFill512X8(t *testing.T, label string, f fill8fn512) {
	t.Helper()
	for _, g := range groupCounts {
		for _, base := range fillBases {
			key := randomKey512()
			comps := randomWords(8 * g)
			var got, want [8][8]uint64
			f(key, comps, base, &got)
			scalarFill512X8(key, comps, base, &want)
			if got != want {
				t.Fatalf("%s groups=%d base=%#x: got %x want %x", label, g, base, got, want)
			}
		}
	}
}

func dispatchers256x8() map[int]x8fn256 {
	return map[int]x8fn256{20: Fused256Chain20x8, 36: Fused256Chain36x8, 68: Fused256Chain68x8}
}
func dispatchers512x8() map[int]x8fn512 {
	return map[int]x8fn512{20: Fused512Chain20x8, 36: Fused512Chain36x8, 68: Fused512Chain68x8}
}

// checkWideDispatchers pins the eight-lane dispatchers and the width-512
// batch-32 fill hook to the reference under the current flag state.
func checkWideDispatchers(t *testing.T, label string) {
	t.Helper()
	for _, n := range []int{20, 36, 68} {
		checkX8_256(t, label+"-256x8", n, dispatchers256x8()[n])
		checkX8_512(t, label+"-512x8", n, dispatchers512x8()[n])
	}
	checkFill512X8(t, label+"-fill512x8", Fused512Fill13x8)
}

// TestFusedWideDispatchersAuto pins the wide dispatchers under the
// build's auto-selected dispatch state.
func TestFusedWideDispatchersAuto(t *testing.T) {
	checkWideDispatchers(t, "auto")
}

// TestFusedWideReference pins the wide references to the narrow ones:
// an eight-lane evaluation is two four-lane evaluations, an eight-group
// fill two four-group fills.
func TestFusedWideReference(t *testing.T) {
	key256, key512 := randomKey256(), randomKey512()
	c256, c512 := randomWords(8), randomWords(16)
	for _, n := range []int{20, 36, 68} {
		_, ptrs := laneData8(n)
		var o256 [8][4]uint64
		var o512 [8][8]uint64
		scalarFused256X8(key256, c256, &ptrs, n, &o256)
		scalarFused512X8(key512, c512, &ptrs, n, &o512)
		for h := 0; h < 2; h++ {
			var h256 [4][4]uint64
			var h512 [4][8]uint64
			scalarFused256X4(key256, c256, ptrs8Half(&ptrs, h), n, &h256)
			scalarFused512X4(key512, c512, ptrs8Half(&ptrs, h), n, &h512)
			if *out8x256Half(&o256, h) != h256 || *out8x512Half(&o512, h) != h512 {
				t.Fatalf("shape %d half %d: eight-lane reference diverges from the four-lane reference", n, h)
			}
		}
	}
	const base = uint64(0x00FFFFFFFFFFFFF8)
	var f8 [8][8]uint64
	scalarFill512X8(key512, c512, base, &f8)
	for h := 0; h < 2; h++ {
		var f4 [4][8]uint64
		scalarFill512X4(key512, c512, base+uint64(4*h), &f4)
		if *out8x512Half(&f8, h) != f4 {
			t.Fatalf("fill512 half %d: eight-group reference diverges from the four-group reference", h)
		}
	}
}

// checkWideZeroAlloc pins that the wide dispatchers allocate nothing
// under the current flag state.
func checkWideZeroAlloc(t *testing.T, label string) {
	t.Helper()
	k256, k512 := randomKey256(), randomKey512()
	c256, c512 := randomWords(8), randomWords(16)
	_, ptrs := laneData8(68)
	var o256 [8][4]uint64
	var o512 [8][8]uint64
	var f8 [8][8]uint64
	check := func(name string, fn func()) {
		if a := testing.AllocsPerRun(20, fn); a != 0 {
			t.Fatalf("%s %s: %v allocs per call", label, name, a)
		}
	}
	for n, f := range dispatchers256x8() {
		check(shapeName(n)+"-256x8", func() { f(k256, c256, &ptrs, &o256) })
	}
	for n, f := range dispatchers512x8() {
		check(shapeName(n)+"-512x8", func() { f(k512, c512, &ptrs, &o512) })
	}
	check("Fused512Fill13x8", func() { Fused512Fill13x8(k512, c512, 0x00FFFFFFFFFFFFF8, &f8) })
}

// TestFusedWideDispatchersZeroAlloc runs the allocation guard under the
// auto-selected dispatch state.
func TestFusedWideDispatchersZeroAlloc(t *testing.T) {
	checkWideZeroAlloc(t, "auto")
}
