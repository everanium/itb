//go:build arm64 && !purego && !noitbasm

package siphashasm

import (
	"math/rand"
	"testing"
)

// The eight-lane fill kernel of the NEON tier by direct call: each
// half of a batch-16 call must equal the pure-Go reference and the
// four-lane NEON kernels run over the Go-synthesised blocks of the
// same lanes.

// fillX16ViaX8Neon is the batch-16 fill as two eight-lane NEON kernel
// calls with in-register block synthesis.
func fillX16ViaX8Neon(comps []uint64, base uint64, v uint32, out *[16][2]uint64) {
	sipHash24FusedChain13x8NeonAsm(&comps[0], len(comps)/2, base, x16Half(out, 0), v)
	sipHash24FusedChain13x8NeonAsm(&comps[0], len(comps)/2, base+8, x16Half(out, 1), v)
}

// TestFusedChain13x8NeonKernelParity pins the eight-lane NEON fill kernel
// to the pure-Go reference by direct call, independent of the dispatch
// flag.
func TestFusedChain13x8NeonKernelParity(t *testing.T) {
	checkFusedX16Parity(t, "neon-x8", fillX16ViaX8Neon)
}

// TestFusedChain13x8NeonMatchesX4 pins the eight-lane NEON fill kernel
// lane for lane to the four-lane NEON kernels at every pair count, probe
// base and fold (the fixed folds and a random one); the four-lane kernel
// reads the fold from the block in memory (fillBlocks16), so a
// synthesising kernel that dropped or misplaced it would diverge here.
func TestFusedChain13x8NeonMatchesX4(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	for _, pairs := range fusedX16PairCounts {
		for _, tc := range fusedX16FixedCases {
			comps := fusedX16Components(tc.seed0, tc.seed1, pairs)
			for _, base := range append(tc.bases, 0xFFFFFFFFFFFFFFF8, 0x00000000FFFFFFFC) {
				for _, v := range append(tc.folds, rng.Uint32()) {
					var viaX4, viaX8 [16][2]uint64
					blocks := fillBlocks16(base, v)
					for q := 0; q < 4; q++ {
						ptrs := x16Quarter(&blocks, q)
						sipHash24FusedChain13x4NeonAsm(&comps[0], len(comps)/2, &ptrs, x16Out(&viaX4, q))
					}
					fillX16ViaX8Neon(comps, base, v, &viaX8)
					if viaX4 != viaX8 {
						t.Fatalf("%s pairs=%d base=%#x v=%#x: eight-lane kernel %v != four-lane kernels %v", tc.name, pairs, base, v, viaX8, viaX4)
					}
				}
			}
		}
	}
}
