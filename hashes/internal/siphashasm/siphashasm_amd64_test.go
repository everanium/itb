//go:build amd64 && !purego

package siphashasm

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestHasAVX512Fused_DerivationConsistency verifies the runtime flag
// derivation matches the upstream golang.org/x/sys/cpu CPUID
// detection. Mirrors the equivalent guard in blake2{b,s}asm /
// blake3asm / chacha20asm — a regression in the derivation
// expression would silently misroute dispatch toward the slower
// dchest/siphash path on capable hosts.
func TestHasAVX512Fused_DerivationConsistency(t *testing.T) {
	want := cpu.X86.HasAVX512F
	if HasAVX512Fused != want {
		t.Fatalf("HasAVX512Fused = %v; derived expectation = %v", HasAVX512Fused, want)
	}
}

// TestSipConsts_Spec verifies the SipHash init constants match the
// Aumasson & Bernstein 2012 reference values byte-by-byte. A
// regression here (e.g. byte-order swap) would observably change
// every single digest the kernel produces.
func TestSipConsts_Spec(t *testing.T) {
	if SipConst0 != 0x736f6d6570736575 {
		t.Errorf("SipConst0 = %#x; want 0x736f6d6570736575", SipConst0)
	}
	if SipConst1 != 0x646f72616e646f6d {
		t.Errorf("SipConst1 = %#x; want 0x646f72616e646f6d", SipConst1)
	}
	if SipConst2 != 0x6c7967656e657261 {
		t.Errorf("SipConst2 = %#x; want 0x6c7967656e657261", SipConst2)
	}
	if SipConst3 != 0x7465646279746573 {
		t.Errorf("SipConst3 = %#x; want 0x7465646279746573", SipConst3)
	}
	if SipConst1XorEE != 0x646f72616e646f83 {
		t.Errorf("SipConst1XorEE = %#x; want 0x646f72616e646f83", SipConst1XorEE)
	}
}
