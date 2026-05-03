//go:build amd64 && !purego && !noitbasm

package blake3asm

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestHasAVX512Fused_DerivationConsistency verifies the runtime flag
// derivation matches the upstream golang.org/x/sys/cpu CPUID
// detection. Mirrors the equivalent guard in blake2{b,s}asm — a
// regression in the derivation expression would silently misroute
// dispatch toward the slower upstream blake3 path on capable hosts.
func TestHasAVX512Fused_DerivationConsistency(t *testing.T) {
	want := cpu.X86.HasAVX512F
	if HasAVX512Fused != want {
		t.Fatalf("HasAVX512Fused = %v; derived expectation = %v", HasAVX512Fused, want)
	}
}
