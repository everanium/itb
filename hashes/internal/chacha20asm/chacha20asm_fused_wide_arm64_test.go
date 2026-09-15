//go:build arm64 && !purego && !noitbasm

package chacha20asm

import "testing"

func wrap1_256(f func(*[32]byte, *uint64, int, *byte, *[4]uint64)) x1fn256 {
	return func(k *[32]byte, c []uint64, d *byte, o *[4]uint64) { f(k, &c[0], len(c)/4, d, o) }
}

var kernels256x1 = map[int]x1fn256{13: wrap1_256(chacha20FusedChain13x1GprAsm), 20: wrap1_256(chacha20FusedChain20x1GprAsm), 36: wrap1_256(chacha20FusedChain36x1GprAsm), 68: wrap1_256(chacha20FusedChain68x1GprAsm)}

// TestFusedGprKernelParityArm64 pins the single-lane general-purpose-
// register kernels to the pure-Go cascade by direct call.
func TestFusedGprKernelParityArm64(t *testing.T) {
	for _, n := range Shapes {
		t.Run("256x1/"+shapeName(n), func(t *testing.T) { checkX1_256(t, "gpr", n, kernels256x1[n]) })
	}
}

// TestFusedWideDispatcherTiersArm64 pins the eight-lane dispatchers (two
// four-lane NEON calls) under the NEON state and the scalar state.
func TestFusedWideDispatcherTiersArm64(t *testing.T) {
	a, b := FusedHasNEON, HasNEONX16
	t.Cleanup(func() { FusedHasNEON, HasNEONX16 = a, b })
	t.Run("neon", func(t *testing.T) {
		if !a {
			t.Skip("requires Advanced SIMD")
		}
		FusedHasNEON, HasNEONX16 = true, true
		checkWideDispatchers(t, "neon")
		checkWideZeroAlloc(t, "neon")
	})
	t.Run("scalar", func(t *testing.T) {
		FusedHasNEON, HasNEONX16 = false, false
		checkWideDispatchers(t, "scalar")
		checkWideZeroAlloc(t, "scalar")
	})
}
