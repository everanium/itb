//go:build amd64 && !purego

package chacha20asm

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// TestHasAVX512Fused_DerivationConsistency verifies the runtime flag
// derivation matches the upstream golang.org/x/sys/cpu CPUID
// detection. Mirrors the equivalent guard in blake2{b,s}asm /
// blake3asm — a regression in the derivation expression would
// silently misroute dispatch toward the slower upstream chacha20
// path on capable hosts.
func TestHasAVX512Fused_DerivationConsistency(t *testing.T) {
	want := cpu.X86.HasAVX512F
	if HasAVX512Fused != want {
		t.Fatalf("HasAVX512Fused = %v; derived expectation = %v", HasAVX512Fused, want)
	}
}

// TestChaCha20Sigma_RFC7539 verifies the sigma constant table matches
// the ChaCha20 RFC 7539 §2.3 ASCII-encoded "expand 32-byte k"
// little-endian uint32 representation. A regression here would
// silently corrupt every per-call key derivation downstream.
func TestChaCha20Sigma_RFC7539(t *testing.T) {
	want := [4]uint32{
		0x61707865, // "expa"
		0x3320646e, // "nd 3"
		0x79622d32, // "2-by"
		0x6b206574, // "te k"
	}
	if ChaCha20Sigma != want {
		t.Fatalf("ChaCha20Sigma deviates from RFC 7539:\n  got  = %x\n  want = %x", ChaCha20Sigma, want)
	}
}
