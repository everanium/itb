package siphashasm

import (
	"fmt"
	"testing"

	"github.com/dchest/siphash"
)

// shapes are the four per-lane input lengths every kernel family covers.
var shapes = []int{13, 20, 36, 68}

func shapeName(n int) string { return fmt.Sprintf("shape%d", n) }

// laneCase fixes the four per-lane seed pairs of a parity scenario.
// SipHash has no fixed key — the seed pair is the entire key.
type laneCase struct {
	name  string
	seeds [4][2]uint64
}

var laneCases = []laneCase{
	{"zero seeds", [4][2]uint64{}},
	{"ascending distinct lane seeds", [4][2]uint64{{1, 2}, {3, 4}, {5, 6}, {7, 8}}},
	{"high-bit-set seeds", [4][2]uint64{
		{0x8000000000000001, 0x8000000000000002}, {0x8000000000000003, 0x8000000000000004},
		{0x8000000000000005, 0x8000000000000006}, {0x8000000000000007, 0x8000000000000008}}},
	{"all-ones seeds", [4][2]uint64{
		{0xffffffffffffffff, 0xffffffffffffffff}, {0xffffffffffffffff, 0xffffffffffffffff},
		{0xffffffffffffffff, 0xffffffffffffffff}, {0xffffffffffffffff, 0xffffffffffffffff}}},
}

// makeLaneData returns four distinct per-lane inputs of exactly n bytes,
// carved out of longer backings whose bytes past n are non-zero, so a
// kernel that reads past its shape is caught by the parity checks.
func makeLaneData(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		backing := make([]byte, n+32)
		for i := range backing {
			backing[i] = byte(i + 0x10 + lane*0x40)
		}
		for i := n; i < len(backing); i++ {
			backing[i] = 0xEE
		}
		bufs[lane] = backing[:n:n]
		ptrs[lane] = &bufs[lane][0]
	}
	return bufs, ptrs
}

// TestChainAbsorbMatchesDchest pins the reference round to the upstream
// SipHash-128 implementation the public hashes.SipHash24 closure calls.
func TestChainAbsorbMatchesDchest(t *testing.T) {
	for _, n := range append([]int{0, 1, 7, 8, 9, 15, 16, 17}, shapes...) {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*13 + n)
		}
		for _, tc := range laneCases {
			for lane := 0; lane < 4; lane++ {
				lo, hi := ChainAbsorb(data, tc.seeds[lane][0], tc.seeds[lane][1])
				wLo, wHi := siphash.Hash128(tc.seeds[lane][0], tc.seeds[lane][1], data)
				if lo != wLo || hi != wHi {
					t.Fatalf("n=%d case %q lane %d: ChainAbsorb diverges from siphash.Hash128", n, tc.name, lane)
				}
			}
		}
	}
}

// TestSipConstsSpec verifies the SipHash init constants match the
// Aumasson & Bernstein 2012 reference values.
func TestSipConstsSpec(t *testing.T) {
	if SipConst0 != 0x736f6d6570736575 || SipConst1 != 0x646f72616e646f6d ||
		SipConst2 != 0x6c7967656e657261 || SipConst3 != 0x7465646279746573 ||
		SipConst1XorEE != 0x646f72616e646f83 {
		t.Fatal("SipHash constants diverge from the reference values")
	}
}

// TestLaneTables pins the batch-16 kernel's index tables.
func TestLaneTables(t *testing.T) {
	for i, v := range laneIdx16 {
		if v != uint64(i) {
			t.Fatalf("laneIdx16[%d] = %d", i, v)
		}
	}
	for i, v := range interleaveIdx16 {
		lane := i / 2
		want := uint64(lane)
		if i%2 == 1 {
			want += 8
		}
		if v != want {
			t.Fatalf("interleaveIdx16[%d] = %d, want %d", i, v, want)
		}
	}
}
