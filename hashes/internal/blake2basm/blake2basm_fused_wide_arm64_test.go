//go:build arm64 && !purego && !noitbasm

package blake2basm

import "testing"

func wrap1_256(f func(*[32]byte, *uint64, int, *byte, *[4]uint64)) x1fn256 {
	return func(k *[32]byte, c []uint64, d *byte, o *[4]uint64) { f(k, &c[0], len(c)/4, d, o) }
}
func wrap1_512(f func(*[64]byte, *uint64, int, *byte, *[8]uint64)) x1fn512 {
	return func(k *[64]byte, c []uint64, d *byte, o *[8]uint64) { f(k, &c[0], len(c)/8, d, o) }
}

var kernels256x1 = map[int]x1fn256{13: wrap1_256(blake2b256FusedChain13x1GprAsm), 20: wrap1_256(blake2b256FusedChain20x1GprAsm), 36: wrap1_256(blake2b256FusedChain36x1GprAsm), 68: wrap1_256(blake2b256FusedChain68x1GprAsm)}
var kernels512x1 = map[int]x1fn512{13: wrap1_512(blake2b512FusedChain13x1GprAsm), 20: wrap1_512(blake2b512FusedChain20x1GprAsm), 36: wrap1_512(blake2b512FusedChain36x1GprAsm), 68: wrap1_512(blake2b512FusedChain68x1GprAsm)}

// TestFusedGprKernelParityArm64 pins the single-lane general-purpose-
// register kernels to the pure-Go cascade by direct call.
func TestFusedGprKernelParityArm64(t *testing.T) {
	for _, n := range Shapes {
		t.Run("256x1/"+shapeName(n), func(t *testing.T) { checkX1_256(t, "gpr", n, kernels256x1[n]) })
		t.Run("512x1/"+shapeName(n), func(t *testing.T) { checkX1_512(t, "gpr", n, kernels512x1[n]) })
	}
}

// TestFusedWideDispatcherTiersArm64 installs the NEON and the scalar
// dispatch state in turn and pins the wide dispatchers and the
// allocation guard under each.
func TestFusedWideDispatcherTiersArm64(t *testing.T) {
	a, x := FusedHasNEON, HasNEONX16
	t.Cleanup(func() { FusedHasNEON, HasNEONX16 = a, x })
	FusedHasNEON, HasNEONX16 = true, true
	checkWideDispatchers(t, "neon")
	checkWideZeroAlloc(t, "neon")
	FusedHasNEON, HasNEONX16 = false, false
	checkWideDispatchers(t, "scalar")
	checkWideZeroAlloc(t, "scalar")
}
