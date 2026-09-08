//go:build arm64 && !purego && !noitbasm

package siphashasm

import "testing"

type fusedAsmX4Neon func(*uint64, int, *[4]*byte, *[4][2]uint64)
type fusedAsmX1Gpr func(*uint64, int, *byte, *[2]uint64)

func wrapX4Neon(f fusedAsmX4Neon) fusedX4Fn {
	return func(comps []uint64, ptrs *[4]*byte, out *[4][2]uint64) {
		f(&comps[0], len(comps)/2, ptrs, out)
	}
}

func wrapX1Gpr(f fusedAsmX1Gpr) fusedX1Fn {
	return func(comps []uint64, data *byte, out *[2]uint64) {
		f(&comps[0], len(comps)/2, data, out)
	}
}

func neonFusedX4() map[int]fusedX4Fn {
	return map[int]fusedX4Fn{
		13: wrapX4Neon(sipHash24FusedChain13x4NeonAsm), 20: wrapX4Neon(sipHash24FusedChain20x4NeonAsm),
		36: wrapX4Neon(sipHash24FusedChain36x4NeonAsm), 68: wrapX4Neon(sipHash24FusedChain68x4NeonAsm),
	}
}

func gprFusedX1() map[int]fusedX1Fn {
	return map[int]fusedX1Fn{
		13: wrapX1Gpr(sipHash24FusedChain13x1GprAsm), 20: wrapX1Gpr(sipHash24FusedChain20x1GprAsm),
		36: wrapX1Gpr(sipHash24FusedChain36x1GprAsm), 68: wrapX1Gpr(sipHash24FusedChain68x1GprAsm),
	}
}

// TestFusedKernelParityArm64 pins every NEON four-lane kernel and every
// GPR single-lane kernel to the pure-Go cascade by direct call,
// independent of the dispatch flag, on the fixed lane cases and a random
// sweep at every component-pair count.
func TestFusedKernelParityArm64(t *testing.T) {
	x4, x1 := neonFusedX4(), gprFusedX1()
	for _, n := range shapes {
		t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "neon-x4", n, x4[n]) })
		t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "gpr-x1", n, x1[n]) })
	}
}

// TestFusedDispatcherTiersArm64 installs the NEON and the scalar
// dispatch state in turn and pins the dispatchers' output to the
// reference under each.
func TestFusedDispatcherTiersArm64(t *testing.T) {
	saved := FusedHasNEON
	t.Cleanup(func() { FusedHasNEON = saved })
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	x1 := map[int]fusedX1Fn{13: FusedChain13x1, 20: FusedChain20x1, 36: FusedChain36x1, 68: FusedChain68x1}
	for _, state := range []struct {
		name string
		neon bool
	}{{"neon", true}, {"scalar", false}} {
		t.Run(state.name, func(t *testing.T) {
			FusedHasNEON = state.neon
			for _, n := range shapes {
				t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "dispatch-"+state.name+"-x4", n, x4[n]) })
				t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "dispatch-"+state.name+"-x1", n, x1[n]) })
			}
		})
	}
}

// TestFusedChain13x16DispatcherArm64 installs the NEON and the scalar
// batch-16 state in turn and pins the dispatcher's output to the
// reference under each.
func TestFusedChain13x16DispatcherArm64(t *testing.T) {
	saved := HasNEONX16
	t.Cleanup(func() { HasNEONX16 = saved })
	HasNEONX16 = true
	checkFusedX16Parity(t, "dispatch-neon", FusedChain13x16)
	HasNEONX16 = false
	checkFusedX16Parity(t, "dispatch-scalar", FusedChain13x16)
}
