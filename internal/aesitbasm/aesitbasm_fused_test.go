package aesitbasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

var pairCounts = []int{1, 2, 4, 8}

type fusedX4Fn func(*[16]byte, []uint64, *[4]*byte, *[4][2]uint64)
type fusedX1Fn func(*[16]byte, []uint64, *byte, *[2]uint64)

func randomComponents(pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	var raw [16 * 8]byte
	rand.Read(raw[:])
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
			key := tc.key
			var want, got [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(&key, comps, bufs[lane])
			}
			kernel(&key, comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d case %q: got %x want %x", name, n, pairs, tc.name, got, want)
			}
		}
		for iter := 0; iter < 64; iter++ {
			var key [16]byte
			rand.Read(key[:])
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			for lane := 0; lane < 4; lane++ {
				rand.Read(bufs[lane])
			}
			var want, got [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(&key, comps, bufs[lane])
			}
			kernel(&key, comps, &ptrs, &got)
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
			var key [16]byte
			rand.Read(key[:])
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			rand.Read(bufs[0])
			wantLo, wantHi := ScalarFusedChain(&key, comps, bufs[0])
			var got [2]uint64
			kernel(&key, comps, ptrs[0], &got)
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
			var key [16]byte
			rand.Read(key[:])
			comps := randomComponents(pairs)
			data := make([]byte, n)
			rand.Read(data)
			lo, hi := ChainAbsorb(&key, data, comps[0], comps[1])
			for i := 2; i < len(comps); i += 2 {
				lo, hi = ChainAbsorb(&key, data, comps[i]^lo, comps[i+1]^hi)
			}
			gLo, gHi := ScalarFusedChain(&key, comps, data)
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
	var key [16]byte
	bufs, ptrs := makeLaneData(20)
	var out [4][2]uint64
	comps := []uint64{1, 2, 3}
	FusedChain20x4(&key, comps, &ptrs, &out)
	var want [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		want[lane][0], want[lane][1] = ScalarFusedChain(&key, comps, bufs[lane])
	}
	if out != want {
		t.Fatal("odd component count did not route to the scalar cascade")
	}
}
