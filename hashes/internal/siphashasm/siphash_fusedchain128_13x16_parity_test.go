package siphashasm

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// scalarBatchX16 evaluates the 13-byte shape on 16 lanes via the
// per-round Go reference: lane i (0..15) runs ChainAbsorb over the
// explicit fill block [0x03 | LE64(groupIdxBase+i) | LE32(v)] under the
// single seed pair. It is the one-pair reference of the batch-16 fused
// kernels, built independently of fillBlocks16 / scalarFusedX16.
func scalarBatchX16(groupIdxBase uint64, v uint32, seed0, seed1 uint64, out *[16][2]uint64) {
	for i := 0; i < 16; i++ {
		var buf [13]byte
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], groupIdxBase+uint64(i))
		binary.LittleEndian.PutUint32(buf[9:13], v)
		out[i][0], out[i][1] = ChainAbsorb(buf[:], seed0, seed1)
	}
}

// fusedX16PairCounts are the cascade lengths the batch-16 fill kernels
// are checked at: one pair (the plain chain-absorb of the 13-byte shape)
// and 5 / 9 / 17 pairs — the Interlocked Barrier cascade over the
// derived pair plus the 512 / 1024 / 2048-bit lockSeed components.
var fusedX16PairCounts = []int{1, 5, 9, 17}

// fusedX16Fn is the batch-16 fused kernel shape shared by the
// dispatcher and the per-tier wrappers.
type fusedX16Fn func(comps []uint64, groupIdxBase uint64, v uint32, out *[16][2]uint64)

// fusedX16FixedCases are the fixed (first pair, bases, folds) vectors
// every batch-16 kernel is checked on. The bases include the byte-6 →
// byte-7 carry of the in-register groupIdx synthesis (0x7FFF…, 0xFEFE…)
// and the uint64 wrap across the 16-lane batch (0xFFFF…); the folds
// include the all-zero and all-one words and a word with the top and
// bottom bits set, so a kernel that narrows, shifts or drops the fold
// misses at least one vector.
var fusedX16FixedCases = []struct {
	name         string
	seed0, seed1 uint64
	bases        []uint64
	folds        []uint32
}{
	{"zero_seeds", 0, 0, []uint64{0, 1, 0x100, 0x7FFFFFFFFFFFFFFF}, []uint32{0, 0xFFFFFFFF, 0x80000001}},
	{"distinct_seeds", 0x0102030405060708, 0x090a0b0c0d0e0f00, []uint64{0, 1, 0x100, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, []uint32{0, 0x01020304, 0xDEADBEEF, 0xFFFFFFFF}},
	{"all_ones_seeds", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, []uint64{0, 1, 0xFEFEFEFEFEFEFEFE, 0x00FFFFFFFFFFFFF8}, []uint32{0, 0xFFFFFFFF, 0x7F000080}},
}

// fusedX16Components expands a first pair into a deterministic
// component slice of the requested pair count.
func fusedX16Components(seed0, seed1 uint64, pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	comps[0], comps[1] = seed0, seed1
	for i := 2; i < len(comps); i++ {
		comps[i] = comps[i-2]*0x9E3779B97F4A7C15 + uint64(i)*0xD1B54A32D192ED03
	}
	return comps
}

// fusedX16RandomComponents draws a component slice from rng.
func fusedX16RandomComponents(rng *rand.Rand, pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	for i := range comps {
		comps[i] = rng.Uint64()
	}
	return comps
}

// checkFusedX16Parity pins one batch-16 kernel to the pure-Go reference
// (scalarFusedX16) at every pair count: the fixed cases over every
// (base, fold) pair, 32 fixed-seed random iterations with the base
// pinned to a multiple of 16 and a random fold, and 8 fixed-seed random
// iterations with a fully random base so the byte carries and the uint64
// wrap fall inside a batch at random lane positions (the worker loops
// hand the kernel arbitrary bases, so both alignments matter). At one
// pair the kernel is additionally pinned to scalarBatchX16, the
// chain-absorb reference over the explicit 13-byte block. Every check
// also flips one bit of the fold and requires every lane to move, so a
// kernel that leaves bytes 9..12 at zero cannot pass by agreeing with a
// reference that happens to use a zero fold.
func checkFusedX16Parity(t *testing.T, label string, kernel fusedX16Fn) {
	t.Helper()
	check := func(what string, comps []uint64, base uint64, v uint32) {
		var got, want [16][2]uint64
		kernel(comps, base, v, &got)
		scalarFusedX16(comps, base, v, &want)
		for i := 0; i < 16; i++ {
			if got[i] != want[i] {
				t.Errorf("%s %s pairs=%d base=%#x v=%#x lane %d: %v != scalar %v", label, what, len(comps)/2, base, v, i, got[i], want[i])
			}
		}
		if len(comps) == 2 {
			scalarBatchX16(base, v, comps[0], comps[1], &want)
			for i := 0; i < 16; i++ {
				if got[i] != want[i] {
					t.Errorf("%s %s pairs=1 base=%#x v=%#x lane %d: %v != chain-absorb %v", label, what, base, v, i, got[i], want[i])
				}
			}
		}
		var flipped [16][2]uint64
		bit := uint32(1) << (uint(base) & 31)
		kernel(comps, base, v^bit, &flipped)
		for i := 0; i < 16; i++ {
			if flipped[i] == got[i] {
				t.Errorf("%s %s pairs=%d base=%#x v=%#x lane %d: flipping fold bit %#x leaves the lane unchanged", label, what, len(comps)/2, base, v, i, bit)
			}
		}
	}
	for _, pairs := range fusedX16PairCounts {
		for _, tc := range fusedX16FixedCases {
			comps := fusedX16Components(tc.seed0, tc.seed1, pairs)
			for _, base := range tc.bases {
				for _, v := range tc.folds {
					check(tc.name, comps, base, v)
				}
			}
		}
		rng := rand.New(rand.NewSource(int64(pairs)))
		for iter := 0; iter < 32; iter++ {
			comps := fusedX16RandomComponents(rng, pairs)
			base := (rng.Uint64() &^ 0xF) | (1 << 56) // a multiple of 16 in [2^56, 2^64)
			check("random-aligned", comps, base, rng.Uint32())
		}
		for iter := 0; iter < 8; iter++ {
			comps := fusedX16RandomComponents(rng, pairs)
			check("random-unaligned", comps, rng.Uint64(), rng.Uint32())
		}
	}
}

// TestScalarFusedX16MatchesSequential pins the batch-16 reference to
// the literal per-lane composition: lane i is the sequential ChainAbsorb
// cascade over the fill block [0x03 | LE64(base+i) | LE32(v)], and at
// one pair it is scalarBatchX16.
func TestScalarFusedX16MatchesSequential(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, pairs := range fusedX16PairCounts {
		for iter := 0; iter < 16; iter++ {
			comps := fusedX16RandomComponents(rng, pairs)
			base := rng.Uint64()
			v := rng.Uint32()
			var got [16][2]uint64
			scalarFusedX16(comps, base, v, &got)
			for i := 0; i < 16; i++ {
				var buf [13]byte
				buf[0] = 0x03
				binary.LittleEndian.PutUint64(buf[1:9], base+uint64(i))
				binary.LittleEndian.PutUint32(buf[9:13], v)
				lo, hi := ChainAbsorb(buf[:], comps[0], comps[1])
				for k := 2; k < len(comps); k += 2 {
					lo, hi = ChainAbsorb(buf[:], comps[k]^lo, comps[k+1]^hi)
				}
				if got[i][0] != lo || got[i][1] != hi {
					t.Fatalf("pairs=%d base=%#x lane %d: reference diverges from the sequential cascade", pairs, base, i)
				}
			}
			if pairs == 1 {
				var want [16][2]uint64
				scalarBatchX16(base, v, comps[0], comps[1], &want)
				if got != want {
					t.Fatalf("base=%#x v=%#x: one-pair reference diverges from scalarBatchX16", base, v)
				}
			}
		}
	}
}

// TestFusedChain13x16DispatchParity runs the public batch-16 dispatcher
// under the auto-selected tier against the reference.
func TestFusedChain13x16DispatchParity(t *testing.T) {
	checkFusedX16Parity(t, "dispatch", FusedChain13x16)
}

// TestFusedChain13x16BatchingInvariant pins the batch-16 dispatcher to
// sixteen single-lane FusedChain13x1 calls on the same fill blocks,
// built explicitly in memory with the fold at bytes 9..12 — the two
// kernel families the Interlocked Barrier fill closures run must agree
// on every lane at every cascade length, and the memory-reading kernel
// absorbs whatever the buffer carries, so a synthesising kernel that
// ignored the fold would diverge here.
func TestFusedChain13x16BatchingInvariant(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for _, pairs := range fusedX16PairCounts {
		for _, tc := range fusedX16FixedCases {
			comps := fusedX16Components(tc.seed0, tc.seed1, pairs)
			for _, base := range append([]uint64{rng.Uint64()}, tc.bases...) {
				v := rng.Uint32()
				var got [16][2]uint64
				FusedChain13x16(comps, base, v, &got)
				for i := 0; i < 16; i++ {
					var buf [13]byte
					buf[0] = 0x03
					binary.LittleEndian.PutUint64(buf[1:9], base+uint64(i))
					binary.LittleEndian.PutUint32(buf[9:13], v)
					var one [2]uint64
					FusedChain13x1(comps, &buf[0], &one)
					if got[i] != one {
						t.Fatalf("%s pairs=%d base=%#x v=%#x lane %d: x16 %v != x1 %v", tc.name, pairs, base, v, i, got[i], one)
					}
				}
			}
		}
	}
}

// TestFusedChain13x16RejectsShortComponents pins the guard path: an odd
// component count routes to the scalar cascade without touching the
// kernels.
func TestFusedChain13x16RejectsShortComponents(t *testing.T) {
	comps := []uint64{1, 2, 3}
	var got, want [16][2]uint64
	FusedChain13x16(comps, 5, 7, &got)
	scalarFusedX16(comps, 5, 7, &want)
	if got != want {
		t.Fatal("odd component count did not route to the scalar cascade")
	}
}
