//go:build arm64 && !purego && !noitbasm

package aescmacasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// aescmacasm_entropy_arm64_test.go — the input-entropy differential
// audit of every NEON kernel by direct call, independent of the dispatch
// flag.

// TestInputEntropyKernelsArm64 audits the four-lane and single-lane NEON
// kernels of every shape and the NEON batch-16 fill kernel.
func TestInputEntropyKernelsArm64(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("ARM crypto extension not available")
	}
	x4, x1 := neonFusedX4(), neonFusedX1()
	for _, n := range shapes {
		auditX4(t, "neon", n, x4[n])
		auditX1(t, "neon", n, x1[n])
	}
	auditX16(t, "neon", func(s *Schedule, comps []uint64, base uint64, out *[16][2]uint64) {
		aesCMAC128FusedChain13x16NeonAsm(&s.roundKeys, &comps[0], len(comps)/2, base, out)
	})
}
