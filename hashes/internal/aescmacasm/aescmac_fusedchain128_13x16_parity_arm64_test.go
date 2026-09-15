//go:build arm64 && !purego && !noitbasm

package aescmacasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// TestFusedChain13x16KernelParityNeon pins the NEON batch-16 kernel to
// the reference by direct call, independent of the dispatch flag.
func TestFusedChain13x16KernelParityNeon(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("requires the ARM crypto extension")
	}
	checkFusedX16Parity(t, "neon", func(s *Schedule, comps []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		aesCMAC128FusedChain13x16NeonAsm(&s.roundKeys, &comps[0], len(comps)/2, groupIdxBase, out)
	})
}

// TestFusedChain13x16DispatcherNeon installs the NEON and the scalar
// dispatch state in turn and pins the dispatcher's output to the
// reference under each.
func TestFusedChain13x16DispatcherNeon(t *testing.T) {
	saved := HasARMAESX16
	t.Cleanup(func() { HasARMAESX16 = saved })
	if aes.CPU.HasARMCrypto {
		HasARMAESX16 = true
		checkFusedX16Parity(t, "dispatch-neon", FusedChain13x16)
	}
	HasARMAESX16 = false
	checkFusedX16Parity(t, "dispatch-scalar", FusedChain13x16)
}
