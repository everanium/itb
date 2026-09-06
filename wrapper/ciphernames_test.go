package wrapper

import (
	"testing"

	"github.com/everanium/itb/hashes"
)

// TestCipherNamesMirrorsHashesRegistry pins CipherNames to the outer-
// cipher-eligible subset of the shipped hashes.Registry (hashes.
// KeystreamNames), element by element and in order. Inner-PRF-only
// Registry entries (hashes.ClassNone) are intentionally excluded — see
// the CipherNames docstring for the security rationale.
func TestCipherNamesMirrorsHashesRegistry(t *testing.T) {
	want := hashes.KeystreamNames()
	if len(CipherNames) != len(want) {
		t.Fatalf("len(CipherNames) = %d, want %d", len(CipherNames), len(want))
	}
	for i := range want {
		if CipherNames[i] != want[i] {
			t.Errorf("CipherNames[%d] = %q, want %q", i, CipherNames[i], want[i])
		}
	}
}
