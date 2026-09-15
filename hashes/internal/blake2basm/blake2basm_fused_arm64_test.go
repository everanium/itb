//go:build arm64 && !purego && !noitbasm

package blake2basm

import "testing"

// blake2basm_fused_arm64_test.go — the four-lane NEON kernels by direct
// call and the four-lane dispatchers under the NEON and scalar dispatch
// states.

func wrap4_256(f func(*[32]byte, *uint64, int, *[4]*byte, *[4][4]uint64)) x4fn256 {
	return func(k *[32]byte, c []uint64, p *[4]*byte, o *[4][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}
func wrap4_512(f func(*[64]byte, *uint64, int, *[4]*byte, *[4][8]uint64)) x4fn512 {
	return func(k *[64]byte, c []uint64, p *[4]*byte, o *[4][8]uint64) { f(k, &c[0], len(c)/8, p, o) }
}

var neon256x4 = map[int]x4fn256{13: wrap4_256(blake2b256FusedChain13x4NeonAsm), 20: wrap4_256(blake2b256FusedChain20x4NeonAsm), 36: wrap4_256(blake2b256FusedChain36x4NeonAsm), 68: wrap4_256(blake2b256FusedChain68x4NeonAsm)}
var neon512x4 = map[int]x4fn512{13: wrap4_512(blake2b512FusedChain13x4NeonAsm), 20: wrap4_512(blake2b512FusedChain20x4NeonAsm), 36: wrap4_512(blake2b512FusedChain36x4NeonAsm), 68: wrap4_512(blake2b512FusedChain68x4NeonAsm)}

// TestFusedKernelParityArm64 pins every four-lane NEON kernel to the
// pure-Go cascade by direct call, independent of the dispatch flag.
func TestFusedKernelParityArm64(t *testing.T) {
	if !FusedHasNEON {
		t.Skip("NEON not available")
	}
	for _, n := range Shapes {
		t.Run("256x4/"+shapeName(n), func(t *testing.T) { checkX4_256(t, "neon", n, neon256x4[n]) })
		t.Run("512x4/"+shapeName(n), func(t *testing.T) { checkX4_512(t, "neon", n, neon512x4[n]) })
	}
}

// TestFusedDispatcherTiersArm64 installs the NEON and the scalar dispatch
// state in turn and pins the dispatchers and the allocation guard under
// each.
func TestFusedDispatcherTiersArm64(t *testing.T) {
	a, x := FusedHasNEON, HasNEONX16
	g, gx := FusedHasGPR, HasGPRX16
	t.Cleanup(func() { FusedHasNEON, HasNEONX16 = a, x; FusedHasGPR, HasGPRX16 = g, gx })
	if a {
		FusedHasNEON, HasNEONX16 = true, true
		checkDispatchers(t, "neon")
		checkZeroAlloc(t, "neon")
	}
	FusedHasNEON, HasNEONX16 = false, false
	FusedHasGPR, HasGPRX16 = false, false
	checkDispatchers(t, "scalar")
	checkZeroAlloc(t, "scalar")
}
