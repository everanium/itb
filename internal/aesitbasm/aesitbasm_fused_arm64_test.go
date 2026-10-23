//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	"github.com/everanium/itb/internal/cpuid"
)

type fusedAsmX4Neon func(*[16]byte, *uint64, int, *[4]*byte, *[4][2]uint64)
type fusedAsmX1Neon func(*[16]byte, *uint64, int, *byte, *[2]uint64)

func wrapX4Neon(f fusedAsmX4Neon) fusedX4Fn {
	return func(key *[16]byte, comps []uint64, ptrs *[4]*byte, out *[4][2]uint64) {
		f(key, &comps[0], len(comps)/2, ptrs, out)
	}
}

func wrapX1Neon(f fusedAsmX1Neon) fusedX1Fn {
	return func(key *[16]byte, comps []uint64, data *byte, out *[2]uint64) {
		f(key, &comps[0], len(comps)/2, data, out)
	}
}

func neonFusedX4() map[int]fusedX4Fn {
	return map[int]fusedX4Fn{
		13: wrapX4Neon(aesITB128FusedChain13x4NeonAsm), 20: wrapX4Neon(aesITB128FusedChain20x4NeonAsm),
		36: wrapX4Neon(aesITB128FusedChain36x4NeonAsm), 68: wrapX4Neon(aesITB128FusedChain68x4NeonAsm),
	}
}

func neonFusedX1() map[int]fusedX1Fn {
	return map[int]fusedX1Fn{
		13: wrapX1Neon(aesITB128FusedChain13x1NeonAsm), 20: wrapX1Neon(aesITB128FusedChain20x1NeonAsm),
		36: wrapX1Neon(aesITB128FusedChain36x1NeonAsm), 68: wrapX1Neon(aesITB128FusedChain68x1NeonAsm),
	}
}

// TestFusedKernelParityNeon pins every NEON fused cascade kernel — four
// lanes and one lane, every shape — to the pure-Go cascade by direct
// call, independent of the dispatch flag, on the fixed lane cases and a
// random sweep at every component-pair count.
func TestFusedKernelParityNeon(t *testing.T) {
	if !cpuid.ARMAES {
		t.Skip("requires the ARM crypto extension")
	}
	x4, x1 := neonFusedX4(), neonFusedX1()
	for _, n := range shapes {
		t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "neon-x4", n, x4[n]) })
		t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "neon-x1", n, x1[n]) })
	}
}

// TestFusedKernelsLeaveNoSecretInFrameArm64 runs the NEON x1, x4 and
// batch-16 AES-ITB-128 kernels under the stack-residue probe after the
// probe's negative control: no key, no component pair, no key-folded
// block and no lane output may be left in the stack once a kernel has
// returned.
func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	TestFusedKernelsLeaveNoSecretInFrameArm64(t)
}

func TestFusedKernelsLeaveNoSecretInFrameArm64(t *testing.T) {
	checkResidueNegativeControls(t)
	checkResidueProbeSeesKeyFold(t)
	if !cpuid.ARMAES {
		t.Skip("requires the ARM crypto extension")
	}
	x16 := func(key *[16]byte, comps []uint64, base uint64, v uint32, out *[16][2]uint64) {
		aesITB128FusedChain13x16NeonAsm(key, &comps[0], len(comps)/2, base, out, v)
	}
	checkAESITBResidue(t, "neon", neonFusedX4(), neonFusedX1(), nil, x16)
	checkNoiseFillResidue(t, "neon", 8, noiseFillX8NeonAsm)
}

func dumpSIMDRegs(dst *[88]uint64, avx512 bool)
func dirtySIMDRegForTest(masked uint64)

func init() {
	dumpSIMDRegsHook = func(dst *[88]uint64) {
		dumpSIMDRegs(dst, false)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}
