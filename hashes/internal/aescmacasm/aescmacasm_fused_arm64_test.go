//go:build arm64 && !purego && !noitbasm

package aescmacasm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/everanium/itb/internal/cpuid"
)

type fusedAsmX4Neon func(*[176]byte, *uint64, int, *[4]*byte, *[4][2]uint64)
type fusedAsmX1Neon func(*[176]byte, *uint64, int, *byte, *[2]uint64)

func wrapX4Neon(f fusedAsmX4Neon) fusedX4Fn {
	return func(s *Schedule, comps []uint64, ptrs *[4]*byte, out *[4][2]uint64) {
		f(&s.roundKeys, &comps[0], len(comps)/2, ptrs, out)
	}
}

func wrapX1Neon(f fusedAsmX1Neon) fusedX1Fn {
	return func(s *Schedule, comps []uint64, data *byte, out *[2]uint64) {
		f(&s.roundKeys, &comps[0], len(comps)/2, data, out)
	}
}

func neonFusedX4() map[int]fusedX4Fn {
	return map[int]fusedX4Fn{
		13: wrapX4Neon(aesCMAC128FusedChain13x4NeonAsm), 20: wrapX4Neon(aesCMAC128FusedChain20x4NeonAsm),
		36: wrapX4Neon(aesCMAC128FusedChain36x4NeonAsm), 68: wrapX4Neon(aesCMAC128FusedChain68x4NeonAsm),
	}
}

func neonFusedX1() map[int]fusedX1Fn {
	return map[int]fusedX1Fn{
		13: wrapX1Neon(aesCMAC128FusedChain13x1NeonAsm), 20: wrapX1Neon(aesCMAC128FusedChain20x1NeonAsm),
		36: wrapX1Neon(aesCMAC128FusedChain36x1NeonAsm), 68: wrapX1Neon(aesCMAC128FusedChain68x1NeonAsm),
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

func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	TestFusedKernelsLeaveNoKeyInFrame(t)
}

func TestFusedKernelsLeaveNoKeyInFrame(t *testing.T) {
	checkResidueNegativeControls(t)
	if !cpuid.ARMAES {
		t.Skip("requires the ARM crypto extension")
	}
	var key [16]byte
	rand.Read(key[:])
	s := NewSchedule(key)
	comps := randomComponents(2)
	run := func(name string, n int, lanes [][]byte, call func()) {
		res := stackResidue(call)
		assertNoSecretResidue(t, name, res, secretWords(cmacSecrets(s, n, lanes)), nil)
	}
	x4, x1 := neonFusedX4(), neonFusedX1()
	for _, n := range shapes {
		if k, ok := x4[n]; ok {
			bufs, ptrs := makeLaneData(n)
			for i := range bufs {
				rand.Read(bufs[i])
			}
			var out [4][2]uint64
			run(fmt.Sprintf("neon x4 n=%d", n), n, bufs[:], func() { k(s, comps, &ptrs, &out) })
		}
		if k, ok := x1[n]; ok {
			bufs, ptrs := makeLaneData(n)
			rand.Read(bufs[0])
			var out [2]uint64
			run(fmt.Sprintf("neon x1 n=%d", n), n, bufs[:1], func() { k(s, comps, ptrs[0], &out) })
		}
	}
	base := uint64(0x0123456789ABCDEF)
	v := uint32(0xA5C33C5A)
	lanes := make([][]byte, 16)
	for i := range lanes {
		lanes[i] = make([]byte, 13)
		lanes[i][0] = 0x03
		binary.LittleEndian.PutUint64(lanes[i][1:], base+uint64(i))
		binary.LittleEndian.PutUint32(lanes[i][9:], v)
	}
	var out [16][2]uint64
	run("neon x16", 13, lanes, func() {
		aesCMAC128FusedChain13x16NeonAsm(&s.roundKeys, &comps[0], len(comps)/2, base, &out, v)
	})
}

func dumpSIMDRegs(dst *[88]uint64, avx512 bool)
func dirtySIMDRegForTest(masked uint64)

func init() {
	dumpSIMDRegsHook = func(dst *[88]uint64) {
		dumpSIMDRegs(dst, false)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}
