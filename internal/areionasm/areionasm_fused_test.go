package areionasm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
)

// areionasm_fused_test.go — parity scaffolding of the fused cascade shared
// by every architecture: random inputs, the dispatcher-level parity
// checks against ScalarFusedChain256 / ScalarFusedChain512, and the
// zero-allocation guard.

var groupCounts = []int{1, 2, 4, 8}

func shapeName(n int) string { return fmt.Sprintf("shape%d", n) }

func randomWords(k int) []uint64 {
	raw := make([]byte, 8*k)
	rand.Read(raw)
	w := make([]uint64, k)
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return w
}

func randomKey256() *[32]byte {
	var k [32]byte
	rand.Read(k[:])
	return &k
}

func randomKey512() *[64]byte {
	var k [64]byte
	rand.Read(k[:])
	return &k
}

func laneData(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for l := range bufs {
		bufs[l] = make([]byte, n)
		rand.Read(bufs[l])
		ptrs[l] = &bufs[l][0]
	}
	return bufs, ptrs
}

type x4fn256 func(*[32]byte, []uint64, *[4]*byte, *[4][4]uint64)
type x1fn256 func(*[32]byte, []uint64, *byte, *[4]uint64)
type x4fn512 func(*[64]byte, []uint64, *[4]*byte, *[4][8]uint64)
type x1fn512 func(*[64]byte, []uint64, *byte, *[8]uint64)

// checkX4_256 pins a four-lane width-256 kernel to the reference on
// random inputs at every group count.
func checkX4_256(t *testing.T, label string, n int, f x4fn256) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey256()
			comps := randomWords(4 * g)
			bufs, ptrs := laneData(n)
			var got [4][4]uint64
			f(key, comps, &ptrs, &got)
			for l := 0; l < 4; l++ {
				if want := ScalarFusedChain256(key, comps, bufs[l]); got[l] != want {
					t.Fatalf("%s n=%d groups=%d iter=%d lane %d: got %x want %x", label, n, g, iter, l, got[l], want)
				}
			}
		}
	}
}

func checkX1_256(t *testing.T, label string, n int, f x1fn256) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey256()
			comps := randomWords(4 * g)
			buf := make([]byte, n)
			rand.Read(buf)
			var got [4]uint64
			f(key, comps, &buf[0], &got)
			if want := ScalarFusedChain256(key, comps, buf); got != want {
				t.Fatalf("%s n=%d groups=%d iter=%d: got %x want %x", label, n, g, iter, got, want)
			}
		}
	}
}

func checkX4_512(t *testing.T, label string, n int, f x4fn512) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey512()
			comps := randomWords(8 * g)
			bufs, ptrs := laneData(n)
			var got [4][8]uint64
			f(key, comps, &ptrs, &got)
			for l := 0; l < 4; l++ {
				if want := ScalarFusedChain512(key, comps, bufs[l]); got[l] != want {
					t.Fatalf("%s n=%d groups=%d iter=%d lane %d: got %x want %x", label, n, g, iter, l, got[l], want)
				}
			}
		}
	}
}

func checkX1_512(t *testing.T, label string, n int, f x1fn512) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey512()
			comps := randomWords(8 * g)
			buf := make([]byte, n)
			rand.Read(buf)
			var got [8]uint64
			f(key, comps, &buf[0], &got)
			if want := ScalarFusedChain512(key, comps, buf); got != want {
				t.Fatalf("%s n=%d groups=%d iter=%d: got %x want %x", label, n, g, iter, got, want)
			}
		}
	}
}

var fillBases = []uint64{0, 1, 0xFF, 0x00FFFFFFFFFFFFF8, 0xFFFFFFFFFFFFFFFC, 0x0123456789ABCDEF}

// checkFill256 pins the width-256 batch-16 fill hook to the reference at
// group index bases that carry through every byte of the index.
func checkFill256(t *testing.T, label string, f func(*[32]byte, []uint64, uint64, *[8][4]uint64)) {
	t.Helper()
	for _, g := range groupCounts {
		for _, base := range fillBases {
			key := randomKey256()
			comps := randomWords(4 * g)
			var got, want [8][4]uint64
			f(key, comps, base, &got)
			scalarFill256X8(key, comps, base, &want)
			if got != want {
				t.Fatalf("%s groups=%d base=%#x: got %x want %x", label, g, base, got, want)
			}
		}
	}
}

func checkFill512(t *testing.T, label string, f func(*[64]byte, []uint64, uint64, *[4][8]uint64)) {
	t.Helper()
	for _, g := range groupCounts {
		for _, base := range fillBases {
			key := randomKey512()
			comps := randomWords(8 * g)
			var got, want [4][8]uint64
			f(key, comps, base, &got)
			scalarFill512X4(key, comps, base, &want)
			if got != want {
				t.Fatalf("%s groups=%d base=%#x: got %x want %x", label, g, base, got, want)
			}
		}
	}
}

func dispatchers256x4() map[int]x4fn256 {
	return map[int]x4fn256{13: Fused256Chain13x4, 20: Fused256Chain20x4, 36: Fused256Chain36x4, 68: Fused256Chain68x4}
}
func dispatchers256x1() map[int]x1fn256 {
	return map[int]x1fn256{13: Fused256Chain13x1, 20: Fused256Chain20x1, 36: Fused256Chain36x1, 68: Fused256Chain68x1}
}
func dispatchers512x4() map[int]x4fn512 {
	return map[int]x4fn512{13: Fused512Chain13x4, 20: Fused512Chain20x4, 36: Fused512Chain36x4, 68: Fused512Chain68x4}
}
func dispatchers512x1() map[int]x1fn512 {
	return map[int]x1fn512{13: Fused512Chain13x1, 20: Fused512Chain20x1, 36: Fused512Chain36x1, 68: Fused512Chain68x1}
}

// checkDispatchers pins every dispatcher to the reference under the
// current flag state.
func checkDispatchers(t *testing.T, label string) {
	t.Helper()
	for _, n := range Shapes {
		checkX4_256(t, label+"-256x4", n, dispatchers256x4()[n])
		checkX1_256(t, label+"-256x1", n, dispatchers256x1()[n])
		checkX4_512(t, label+"-512x4", n, dispatchers512x4()[n])
		checkX1_512(t, label+"-512x1", n, dispatchers512x1()[n])
	}
	checkFill256(t, label+"-fill256", Fused256Fill13x8)
	checkFill512(t, label+"-fill512", Fused512Fill13x4)
}

// TestFusedDispatchersAuto pins the dispatchers under the build's
// auto-selected dispatch state.
func TestFusedDispatchersAuto(t *testing.T) {
	checkDispatchers(t, "auto")
}

// TestFusedReferenceCascade pins the pure-Go reference's cascade
// structure: one group is the plain chain absorb under
// fixedKey ‖ components, and each further group re-keys with the
// previous output XOR the group.
func TestFusedReferenceCascade(t *testing.T) {
	key := randomKey256()
	comps := randomWords(8)
	data := make([]byte, 36)
	rand.Read(data)
	var k [64]byte
	copy(k[:32], key[:])
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(k[32+8*i:], comps[i])
	}
	h := soem256Absorb(&k, data)
	if got := ScalarFusedChain256(key, comps[:4], data); got != h {
		t.Fatalf("one group: got %x want %x", got, h)
	}
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(k[32+8*i:], comps[4+i]^h[i])
	}
	h = soem256Absorb(&k, data)
	if got := ScalarFusedChain256(key, comps, data); got != h {
		t.Fatalf("two groups: got %x want %x", got, h)
	}
}

// checkZeroAlloc asserts that every dispatcher runs without a heap
// allocation under the current dispatch state.
func checkZeroAlloc(t *testing.T, label string) {
	t.Helper()
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s: %s allocates %.0f objects per call", label, what, n)
		}
	}
	k256, k512 := randomKey256(), randomKey512()
	c256, c512 := randomWords(8), randomWords(16)
	for _, n := range Shapes {
		bufs, ptrs := laneData(n)
		var o4 [4][4]uint64
		var o1 [4]uint64
		var p4 [4][8]uint64
		var p1 [8]uint64
		f4, f1 := dispatchers256x4()[n], dispatchers256x1()[n]
		g4, g1 := dispatchers512x4()[n], dispatchers512x1()[n]
		check("Fused256Chain"+shapeName(n)+"x4", func() { f4(k256, c256, &ptrs, &o4) })
		check("Fused256Chain"+shapeName(n)+"x1", func() { f1(k256, c256, &bufs[0][0], &o1) })
		check("Fused512Chain"+shapeName(n)+"x4", func() { g4(k512, c512, &ptrs, &p4) })
		check("Fused512Chain"+shapeName(n)+"x1", func() { g1(k512, c512, &bufs[0][0], &p1) })
	}
	var f8 [8][4]uint64
	var f4 [4][8]uint64
	check("Fused256Fill13x8", func() { Fused256Fill13x8(k256, c256, 0x00FFFFFFFFFFFFF8, &f8) })
	check("Fused512Fill13x4", func() { Fused512Fill13x4(k512, c512, 0x00FFFFFFFFFFFFF8, &f4) })
}

func TestFusedDispatchersZeroAlloc(t *testing.T) {
	checkZeroAlloc(t, "auto")
}
