package siphashasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

var pairCounts = []int{1, 2, 4, 8}

type fusedX4Fn func([]uint64, *[4]*byte, *[4][2]uint64)
type fusedX1Fn func([]uint64, *byte, *[2]uint64)

func randomComponents(pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	raw := make([]byte, 8*len(comps))
	rand.Read(raw)
	for i := range comps {
		comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return comps
}

// runFusedX4Parity checks a four-lane fused kernel against the pure-Go
// cascade on every fixed lane case and a random sweep, for every
// component-pair count.
func runFusedX4Parity(t *testing.T, name string, n int, kernel fusedX4Fn) {
	t.Helper()
	for _, pairs := range pairCounts {
		for _, tc := range laneCases {
			bufs, ptrs := makeLaneData(n)
			comps := make([]uint64, 2*pairs)
			for i := range comps {
				comps[i] = tc.seeds[i%4][i%2] ^ uint64(i)*0x9E3779B97F4A7C15
			}
			var want, got [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(comps, bufs[lane])
			}
			kernel(comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d case %q: got %x want %x", name, n, pairs, tc.name, got, want)
			}
		}
		for iter := 0; iter < 64; iter++ {
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			for lane := 0; lane < 4; lane++ {
				rand.Read(bufs[lane])
			}
			var want, got [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(comps, bufs[lane])
			}
			kernel(comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d random iter %d: got %x want %x", name, n, pairs, iter, got, want)
			}
		}
	}
}

// runFusedX1Parity checks a single-lane fused kernel the same way.
func runFusedX1Parity(t *testing.T, name string, n int, kernel fusedX1Fn) {
	t.Helper()
	for _, pairs := range pairCounts {
		for iter := 0; iter < 96; iter++ {
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			rand.Read(bufs[0])
			wantLo, wantHi := ScalarFusedChain(comps, bufs[0])
			var got [2]uint64
			kernel(comps, ptrs[0], &got)
			if got[0] != wantLo || got[1] != wantHi {
				t.Fatalf("%s n=%d pairs=%d iter %d: got %x want (%x,%x)", name, n, pairs, iter, got, wantLo, wantHi)
			}
		}
	}
}

// TestScalarFusedChainMatchesSequential pins the fused reference to the
// literal sequential composition of ChainAbsorb.
func TestScalarFusedChainMatchesSequential(t *testing.T) {
	for _, n := range append([]int{0, 1, 17, 33, 65}, shapes...) {
		for _, pairs := range pairCounts {
			comps := randomComponents(pairs)
			data := make([]byte, n)
			rand.Read(data)
			lo, hi := ChainAbsorb(data, comps[0], comps[1])
			for i := 2; i < len(comps); i += 2 {
				lo, hi = ChainAbsorb(data, comps[i]^lo, comps[i+1]^hi)
			}
			gLo, gHi := ScalarFusedChain(comps, data)
			if gLo != lo || gHi != hi {
				t.Fatalf("n=%d pairs=%d: fused reference diverges", n, pairs)
			}
		}
	}
}

// TestFusedDispatchParity runs the public fused dispatchers (auto tier).
func TestFusedDispatchParity(t *testing.T) {
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	x1 := map[int]fusedX1Fn{13: FusedChain13x1, 20: FusedChain20x1, 36: FusedChain36x1, 68: FusedChain68x1}
	for _, n := range shapes {
		t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "dispatch-x4", n, x4[n]) })
		t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "dispatch-x1", n, x1[n]) })
	}
}

// TestFusedRejectsShortComponents pins the guard path: fewer than two or
// an odd number of components routes to the scalar cascade without
// touching the kernels.
func TestFusedRejectsShortComponents(t *testing.T) {
	bufs, ptrs := makeLaneData(20)
	var out [4][2]uint64
	comps := []uint64{1, 2, 3}
	FusedChain20x4(comps, &ptrs, &out)
	var want [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		want[lane][0], want[lane][1] = ScalarFusedChain(comps, bufs[lane])
	}
	if out != want {
		t.Fatal("odd component count did not route to the scalar cascade")
	}
	var one [2]uint64
	FusedChain20x1(comps, ptrs[0], &one)
	if one != want[0] {
		t.Fatal("odd component count did not route the single lane to the scalar cascade")
	}
}

// checkDispatchersZeroAlloc asserts that every fused dispatcher — the
// single- and four-lane arms at the four shapes, the eight-lane arm at
// the nonce-buf shapes and the batch-16 fill — runs without a heap
// allocation under the current dispatch state. The dispatchers sit on
// the per-pixel and per-group hot paths of the itb pipeline, where one
// allocation per call is a measurable throughput regression.
func checkDispatchersZeroAlloc(t *testing.T, label string) {
	t.Helper()
	comps := randomComponents(4)
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s: %s allocates %.0f objects per call", label, what, n)
		}
	}
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	x1 := map[int]fusedX1Fn{13: FusedChain13x1, 20: FusedChain20x1, 36: FusedChain36x1, 68: FusedChain68x1}
	for _, n := range shapes {
		bufs, ptrs := makeLaneData(n)
		var out4 [4][2]uint64
		var out1 [2]uint64
		check("FusedChain"+shapeName(n)+"x4", func() { x4[n](comps, &ptrs, &out4) })
		check("FusedChain"+shapeName(n)+"x1", func() { x1[n](comps, &bufs[0][0], &out1) })
	}
	x8 := map[int]fusedX8Fn{20: FusedChain20x8, 36: FusedChain36x8, 68: FusedChain68x8}
	for _, n := range []int{20, 36, 68} {
		_, ptrs8 := makeLaneData8(n)
		var out8 [8][2]uint64
		check("FusedChain"+shapeName(n)+"x8", func() { x8[n](comps, &ptrs8, &out8) })
	}
	var out16 [16][2]uint64
	check("FusedChain13x16", func() { FusedChain13x16(comps, 0x00FFFFFFFFFFFFF8, &out16) })
}

// TestFusedDispatchersZeroAlloc runs the allocation check under the
// build's auto-selected dispatch state.
func TestFusedDispatchersZeroAlloc(t *testing.T) {
	checkDispatchersZeroAlloc(t, "auto")
}
