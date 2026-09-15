package aescmacasm

import (
	"crypto/rand"
	"testing"
)

// x8Shapes lists the per-lane input lengths the eight-lane dispatchers
// cover: the 128 / 256 / 512-bit nonce-buf shapes.
var x8Shapes = []int{20, 36, 68}

// x8PairCounts covers the pixel-path cascades of the 512 / 1024 /
// 2048-bit keys (4 / 8 / 16 pairs), the prepended-pair fill cascades
// (5 / 9 / 17) and the one- and two-pair floor.
var x8PairCounts = []int{1, 2, 4, 5, 8, 9, 16, 17}

type fusedX8Fn func(*Schedule, []uint64, *[8]*byte, *[8][2]uint64)

// makeLaneData8 returns eight distinct per-lane inputs of exactly n
// bytes, carved out of longer backings whose bytes past n are non-zero
// (see makeLaneData).
func makeLaneData8(n int) ([8][]byte, [8]*byte) {
	var bufs [8][]byte
	var ptrs [8]*byte
	for lane := 0; lane < 8; lane++ {
		backing := make([]byte, n+32)
		for i := range backing {
			backing[i] = byte(i + 0xA0 + lane*0x20)
		}
		for i := n; i < len(backing); i++ {
			backing[i] = 0xEE
		}
		bufs[lane] = backing[:n:n]
		ptrs[lane] = &bufs[lane][0]
	}
	return bufs, ptrs
}

// randomComponentsN returns 2*pairs random component words for any pair
// count (randomComponents caps at eight pairs).
func randomComponentsN(pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	for i := range comps {
		var raw [8]byte
		rand.Read(raw[:])
		comps[i] = uint64(raw[0]) | uint64(raw[1])<<8 | uint64(raw[2])<<16 | uint64(raw[3])<<24 |
			uint64(raw[4])<<32 | uint64(raw[5])<<40 | uint64(raw[6])<<48 | uint64(raw[7])<<56
	}
	return comps
}

// runFusedX8Parity checks an eight-lane fused kernel against the pure-Go
// cascade on the fixed lane cases and a random sweep, for every pair
// count in x8PairCounts.
func runFusedX8Parity(t *testing.T, name string, n int, kernel fusedX8Fn) {
	t.Helper()
	for _, pairs := range x8PairCounts {
		for _, tc := range laneCases {
			bufs, ptrs := makeLaneData8(n)
			comps := make([]uint64, 2*pairs)
			for i := range comps {
				comps[i] = tc.seeds[i%4][i%2] ^ uint64(i)*0x9E3779B97F4A7C15
			}
			s := NewSchedule(tc.key)
			var want, got [8][2]uint64
			for lane := 0; lane < 8; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(s, comps, bufs[lane])
			}
			kernel(s, comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d case %q: got %x want %x", name, n, pairs, tc.name, got, want)
			}
		}
		for iter := 0; iter < 64; iter++ {
			var key [16]byte
			rand.Read(key[:])
			s := NewSchedule(key)
			comps := randomComponentsN(pairs)
			bufs, ptrs := makeLaneData8(n)
			for lane := 0; lane < 8; lane++ {
				rand.Read(bufs[lane])
			}
			var want, got [8][2]uint64
			for lane := 0; lane < 8; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(s, comps, bufs[lane])
			}
			kernel(s, comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d random iter %d: got %x want %x", name, n, pairs, iter, got, want)
			}
		}
	}
}

// TestFusedX8DispatchParity runs the public eight-lane dispatchers
// (whatever arm the host selects) against the pure-Go cascade, then
// again with the eight-lane arm disarmed so the two-four-lane fallback
// is pinned on every build.
func TestFusedX8DispatchParity(t *testing.T) {
	x8 := map[int]fusedX8Fn{20: FusedChain20x8, 36: FusedChain36x8, 68: FusedChain68x8}
	for _, n := range x8Shapes {
		t.Run("auto/"+shapeName(n), func(t *testing.T) { runFusedX8Parity(t, "dispatch-x8", n, x8[n]) })
	}
	saved := FusedHasVAESAVX512X8
	FusedHasVAESAVX512X8 = false
	t.Cleanup(func() { FusedHasVAESAVX512X8 = saved })
	if FusedX8Active() {
		t.Fatal("FusedX8Active with the x8 flag cleared")
	}
	for _, n := range x8Shapes {
		t.Run("viax4/"+shapeName(n), func(t *testing.T) { runFusedX8Parity(t, "dispatch-x8-via-x4", n, x8[n]) })
	}
}

// TestFusedX8RejectsShortComponents pins the guard path: an odd
// component count routes the eight lanes to the scalar cascade.
func TestFusedX8RejectsShortComponents(t *testing.T) {
	s := NewSchedule(ascendingKey())
	bufs, ptrs := makeLaneData8(68)
	var out [8][2]uint64
	comps := []uint64{1, 2, 3}
	FusedChain68x8(s, comps, &ptrs, &out)
	var want [8][2]uint64
	for lane := 0; lane < 8; lane++ {
		want[lane][0], want[lane][1] = ScalarFusedChain(s, comps, bufs[lane])
	}
	if out != want {
		t.Fatal("odd component count did not route to the scalar cascade")
	}
}
