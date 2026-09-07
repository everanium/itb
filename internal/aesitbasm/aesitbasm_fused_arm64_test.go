//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"
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
	if !aes.CPU.HasARMCrypto {
		t.Skip("requires the ARM crypto extension")
	}
	x4, x1 := neonFusedX4(), neonFusedX1()
	for _, n := range shapes {
		t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "neon-x4", n, x4[n]) })
		t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "neon-x1", n, x1[n]) })
	}
}
