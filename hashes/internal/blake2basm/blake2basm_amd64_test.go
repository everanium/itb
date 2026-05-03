//go:build amd64 && !purego && !noitbasm

package blake2basm

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestHasAVX512Fused_DerivationConsistency verifies the runtime flag
// derivation matches the upstream golang.org/x/sys/cpu CPUID detection
// — a regression in the derivation expression (e.g. swapping in a
// wrong capability bit, accidentally adding an unrelated AND clause)
// would otherwise silently misroute dispatch in the parent hashes/
// package toward the slower upstream golang.org/x/crypto/blake2b path
// on capable hosts (or in the opposite direction toward an
// unsupported ASM call on incapable hosts). Mirrors the spirit of
// TestVAESFlags_MutualExclusion in the internal/areionasm package: a
// fail-fast guard on the dispatch flag before any per-pixel hash call
// reaches the assembly entry points.
func TestHasAVX512Fused_DerivationConsistency(t *testing.T) {
	want := cpu.X86.HasAVX512F
	if HasAVX512Fused != want {
		t.Fatalf("HasAVX512Fused = %v; derived expectation = %v", HasAVX512Fused, want)
	}
}
