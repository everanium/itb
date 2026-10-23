//go:build arm64 && !purego && !noitbasm

package blake2sasm

import "testing"

func wrap4_256(f func(*[32]byte, *uint64, int, *[4]*byte, *[4][4]uint64)) x4fn256 {
	return func(k *[32]byte, c []uint64, p *[4]*byte, o *[4][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}

var neon256x4 = map[int]x4fn256{13: wrap4_256(blake2sFusedChain13x4NeonAsm), 20: wrap4_256(blake2sFusedChain20x4NeonAsm), 36: wrap4_256(blake2sFusedChain36x4NeonAsm), 68: wrap4_256(blake2sFusedChain68x4NeonAsm)}

// TestFusedKernelParityArm64 pins every NEON kernel to the pure-Go
// cascade by direct call, independent of the dispatch flags.
func TestFusedKernelParityArm64(t *testing.T) {
	if !FusedHasNEON {
		t.Skip("requires Advanced SIMD")
	}
	for _, n := range Shapes {
		t.Run("256x4/"+shapeName(n), func(t *testing.T) { checkX4_256(t, "neon", n, neon256x4[n]) })
	}
}

// TestFusedDispatcherTiersArm64 pins the dispatchers and the allocation
// guard under the NEON state and the scalar state.
func TestFusedDispatcherTiersArm64(t *testing.T) {
	a, b := FusedHasNEON, HasNEONX16
	g, gx := FusedHasGPR, HasGPRX16
	t.Cleanup(func() { FusedHasNEON, HasNEONX16 = a, b; FusedHasGPR, HasGPRX16 = g, gx })
	t.Run("neon", func(t *testing.T) {
		if !a {
			t.Skip("requires Advanced SIMD")
		}
		FusedHasNEON, HasNEONX16 = true, true
		checkDispatchers(t, "neon")
		checkZeroAlloc(t, "neon")
	})
	t.Run("scalar", func(t *testing.T) {
		FusedHasNEON, HasNEONX16 = false, false
		FusedHasGPR, HasGPRX16 = false, false
		checkDispatchers(t, "scalar")
		checkZeroAlloc(t, "scalar")
	})
}

// TestFusedKernelsLeaveNoSecretInFrameArm64 runs the NEON four-lane and
// the general-purpose-register single-lane kernels under the
// stack-residue probe: no key dword and no seed-injected dword may be
// left in the stack once a kernel has returned.
func TestFusedKernelsLeaveNoSecretInFrameArm64(t *testing.T) {
	checkResidueNegativeControls(t)
	if FusedHasNEON {
		checkBlake2sResidue(t, "neon", neon256x4, nil, nil)
	}
	checkBlake2sResidue(t, "gpr", nil, kernels256x1, nil)
}

func dumpSIMDRegs(dst *[88]uint64, avx512 bool)
func dirtySIMDRegForTest(masked uint64)

func init() {
	dumpSIMDRegsHook = func(dst *[88]uint64) {
		dumpSIMDRegs(dst, false)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}
