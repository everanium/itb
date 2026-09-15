//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// TestFusedChain13x16NeonParity pins the NEON batch-16 kernel to the
// reference by direct call at every cascade length, independent of the
// dispatch flag.
func TestFusedChain13x16NeonParity(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("ARM crypto extension not available")
	}
	checkFusedX16Parity(t, "neon", func(key *[16]byte, comps []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		aesITB128FusedChain13x16NeonAsm(key, &comps[0], len(comps)/2, groupIdxBase, out)
	})
}

// TestFusedChain13x16DispatcherTiers installs the NEON and the scalar
// dispatch states in turn and pins the dispatcher's output to the
// reference under each.
func TestFusedChain13x16DispatcherTiers(t *testing.T) {
	saved := HasARMAESX16
	t.Cleanup(func() { HasARMAESX16 = saved })
	for _, tier := range []struct {
		name string
		ok   bool
		arm  bool
	}{
		{"neon", aes.CPU.HasARMCrypto, true},
		{"scalar", true, false},
	} {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skipf("%s tier not executable on this host", tier.name)
			}
			HasARMAESX16 = tier.arm
			checkFusedX16Parity(t, "dispatch-"+tier.name, FusedChain13x16)
		})
	}
}
