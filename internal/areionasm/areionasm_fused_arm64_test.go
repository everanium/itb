//go:build arm64 && !purego && !noitbasm

package areionasm

import "testing"

func wrap4_256(f func(*[32]byte, *uint64, int, *[4]*byte, *[4][4]uint64)) x4fn256 {
	return func(k *[32]byte, c []uint64, p *[4]*byte, o *[4][4]uint64) { f(k, &c[0], len(c)/4, p, o) }
}
func wrap1_256(f func(*[32]byte, *uint64, int, *byte, *[4]uint64)) x1fn256 {
	return func(k *[32]byte, c []uint64, d *byte, o *[4]uint64) { f(k, &c[0], len(c)/4, d, o) }
}
func wrap4_512(f func(*[64]byte, *uint64, int, *[4]*byte, *[4][8]uint64)) x4fn512 {
	return func(k *[64]byte, c []uint64, p *[4]*byte, o *[4][8]uint64) { f(k, &c[0], len(c)/8, p, o) }
}
func wrap1_512(f func(*[64]byte, *uint64, int, *byte, *[8]uint64)) x1fn512 {
	return func(k *[64]byte, c []uint64, d *byte, o *[8]uint64) { f(k, &c[0], len(c)/8, d, o) }
}

var neon256x4 = map[int]x4fn256{13: wrap4_256(areion256FusedChain13x4NeonAsm), 20: wrap4_256(areion256FusedChain20x4NeonAsm), 36: wrap4_256(areion256FusedChain36x4NeonAsm), 68: wrap4_256(areion256FusedChain68x4NeonAsm)}
var neon256x1 = map[int]x1fn256{13: wrap1_256(areion256FusedChain13x1NeonAsm), 20: wrap1_256(areion256FusedChain20x1NeonAsm), 36: wrap1_256(areion256FusedChain36x1NeonAsm), 68: wrap1_256(areion256FusedChain68x1NeonAsm)}
var neon512x4 = map[int]x4fn512{13: wrap4_512(areion512FusedChain13x4NeonAsm), 20: wrap4_512(areion512FusedChain20x4NeonAsm), 36: wrap4_512(areion512FusedChain36x4NeonAsm), 68: wrap4_512(areion512FusedChain68x4NeonAsm)}
var neon512x1 = map[int]x1fn512{13: wrap1_512(areion512FusedChain13x1NeonAsm), 20: wrap1_512(areion512FusedChain20x1NeonAsm), 36: wrap1_512(areion512FusedChain36x1NeonAsm), 68: wrap1_512(areion512FusedChain68x1NeonAsm)}

// TestFusedKernelParityArm64 pins every NEON kernel to the pure-Go
// cascade by direct call, independent of the dispatch flag.
func TestFusedKernelParityArm64(t *testing.T) {
	if !FusedHasARMAES {
		t.Skip("ARM crypto extension not available")
	}
	for _, n := range Shapes {
		t.Run("256x4/"+shapeName(n), func(t *testing.T) { checkX4_256(t, "neon", n, neon256x4[n]) })
		t.Run("256x1/"+shapeName(n), func(t *testing.T) { checkX1_256(t, "neon", n, neon256x1[n]) })
		t.Run("512x4/"+shapeName(n), func(t *testing.T) { checkX4_512(t, "neon", n, neon512x4[n]) })
		t.Run("512x1/"+shapeName(n), func(t *testing.T) { checkX1_512(t, "neon", n, neon512x1[n]) })
	}
}

// TestFusedDispatcherTiersArm64 installs the NEON and the scalar dispatch
// state in turn and pins the dispatchers and the allocation guard under
// each.
func TestFusedDispatcherTiersArm64(t *testing.T) {
	a, x := FusedHasARMAES, HasARMAESX16
	t.Cleanup(func() { FusedHasARMAES, HasARMAESX16 = a, x })
	if a {
		FusedHasARMAES, HasARMAESX16 = true, true
		checkDispatchers(t, "neon")
		checkZeroAlloc(t, "neon")
	}
	FusedHasARMAES, HasARMAESX16 = false, false
	checkDispatchers(t, "scalar")
	checkZeroAlloc(t, "scalar")
}

// TestFusedKernelsLeaveNoSecretInFrameArm64 runs the four-, eight-, and
// single-lane NEON kernels, the eight-lane NEON fill kernels, and the
// standalone NEON permutation / SoEM kernels under the stack- and
// register-residue probe: no fixed-key word, no k2 word, no K1 ^ k2
// word, and no state word may be left in the stack or NEON registers once
// a kernel has returned.
func TestFusedKernelsLeaveNoSecretInFrameArm64(t *testing.T) {
	checkResidueNegativeControls(t)
	if !FusedHasARMAES {
		t.Skip("ARM crypto extension not available")
	}
	checkAreionResidue(t, "neon", neon256x4, neon512x4, neon256x1, neon512x1)
	checkAreionWideResidue(t, "neon-disp", dispatchers256x8(), dispatchers512x8())
	checkAreionFillResidue(t, "neon", neonFill256x8, Fused512Fill13x4, neonFill512x8)
	checkAreionPermute256Residue(t, "Areion256Permutex4", Areion256Permutex4)
	checkAreionPermute256Residue(t, "Areion256Permute2x4", Areion256Permute2x4)
	checkAreionPermute512Residue(t, "Areion512Permutex4", Areion512Permutex4)
	checkAreionPermute512Residue(t, "Areion512Permute2x4", Areion512Permute2x4)
	checkAreionSoEM256Residue(t, "Areion256SoEMPermutex4NEON", Areion256SoEMPermutex4NEON)
	checkAreionSoEM512Residue(t, "Areion512SoEMPermutex4NEON", Areion512SoEMPermutex4NEON)
}

func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	TestFusedKernelsLeaveNoSecretInFrameArm64(t)
}

func dumpSIMDRegs(dst *[88]uint64, avx512 bool)
func dirtySIMDRegForTest(masked uint64)

func init() {
	dumpSIMDRegsHook = func(dst *[88]uint64) {
		dumpSIMDRegs(dst, false)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}
