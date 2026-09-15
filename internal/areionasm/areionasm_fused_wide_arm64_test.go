//go:build arm64 && !purego && !noitbasm

package areionasm

import "testing"

func neonFill256x8(k *[32]byte, c []uint64, base uint64, o *[8][4]uint64) {
	areion256FusedChain13x8NeonAsm(k, &c[0], len(c)/4, base, o)
}
func neonFill512x8(k *[64]byte, c []uint64, base uint64, o *[8][8]uint64) {
	areion512FusedChain13x8NeonAsm(k, &c[0], len(c)/8, base, o)
}

// TestFusedWideKernelParityArm64 pins the eight-lane NEON fill kernels
// to the pure-Go cascade by direct call, independent of the dispatch
// flag, and to the four-lane NEON kernels over the same groups.
func TestFusedWideKernelParityArm64(t *testing.T) {
	if !FusedHasARMAES {
		t.Skip("ARM crypto extension not available")
	}
	t.Run("fill256x8", func(t *testing.T) { checkFill256(t, "neon-x8", neonFill256x8) })
	t.Run("fill512x8", func(t *testing.T) { checkFill512X8(t, "neon-x8", neonFill512x8) })
	t.Run("fill256x8-vs-x4", func(t *testing.T) {
		for _, g := range groupCounts {
			for _, base := range fillBases {
				key := randomKey256()
				comps := randomWords(4 * g)
				var got, want [8][4]uint64
				neonFill256x8(key, comps, base, &got)
				var blocks [4][13]byte
				for h := 0; h < 2; h++ {
					ptrs := fillPtrs4(&blocks, base+uint64(4*h))
					areion256FusedChain13x4NeonAsm(key, &comps[0], g, &ptrs, out8x256Half(&want, h))
				}
				if got != want {
					t.Fatalf("groups=%d base=%#x: eight-lane kernel diverges from the four-lane kernel", g, base)
				}
			}
		}
	})
}

// TestFusedWideDispatcherTiersArm64 installs the NEON and the scalar
// dispatch state in turn and pins the wide dispatchers and the
// allocation guard under each.
func TestFusedWideDispatcherTiersArm64(t *testing.T) {
	a, x := FusedHasARMAES, HasARMAESX16
	t.Cleanup(func() { FusedHasARMAES, HasARMAESX16 = a, x })
	if a {
		FusedHasARMAES, HasARMAESX16 = true, true
		checkWideDispatchers(t, "neon")
		checkWideZeroAlloc(t, "neon")
	}
	FusedHasARMAES, HasARMAESX16 = false, false
	checkWideDispatchers(t, "scalar")
	checkWideZeroAlloc(t, "scalar")
}
