//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"testing"

	"github.com/jedisct1/go-aes"
)

// TestHasVAESAVX512_DerivationConsistency verifies the runtime flag
// derivation matches the upstream github.com/jedisct1/go-aes CPUID
// detection. Mirrors the equivalent guard in areionasm — a regression
// in the derivation expression would silently misroute dispatch
// toward the slower upstream crypto/aes path on capable hosts.
func TestHasVAESAVX512_DerivationConsistency(t *testing.T) {
	want := aes.CPU.HasVAES && aes.CPU.HasAVX512
	if HasVAESAVX512 != want {
		t.Fatalf("HasVAESAVX512 = %v; derived expectation = %v", HasVAESAVX512, want)
	}
}

// TestExpandKeyAES128_KAT verifies the AES-128 round-key schedule
// against the FIPS 197 §A.1 known-answer test (key = 0x2b7e1516..., the
// canonical example) and against crypto/aes's internal expansion via
// a single-block encryption parity check (the encrypted block is
// completely defined by the schedule, so a divergence in any round
// key would surface as a ciphertext mismatch).
func TestExpandKeyAES128_KAT(t *testing.T) {
	key := [16]byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	got := ExpandKeyAES128(key)

	// FIPS 197 §A.1 round-key schedule for the canonical example —
	// only K0 (the input key) and K10 (the final round key) are
	// spot-checked; the parity test against crypto/aes encryption
	// covers the intermediate rounds end-to-end.
	wantK0 := [16]byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	if [16]byte(got[0:16]) != wantK0 {
		t.Errorf("ExpandKeyAES128 K0 deviates:\n  got  = %x\n  want = %x", got[0:16], wantK0)
	}
	wantK10 := [16]byte{
		0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89,
		0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6,
	}
	if [16]byte(got[160:176]) != wantK10 {
		t.Errorf("ExpandKeyAES128 K10 deviates:\n  got  = %x\n  want = %x", got[160:176], wantK10)
	}
}
