package wrapper

import (
	"testing"

	"github.com/everanium/itb/hashes"
)

// TestCipherNamesMirrorsHashesRegistry pins CipherNames to the shipped
// hashes.Registry name list, element by element and in order.
func TestCipherNamesMirrorsHashesRegistry(t *testing.T) {
	want := hashes.Names()
	if len(CipherNames) != len(want) {
		t.Fatalf("len(CipherNames) = %d, want %d", len(CipherNames), len(want))
	}
	for i := range want {
		if CipherNames[i] != want[i] {
			t.Errorf("CipherNames[%d] = %q, want %q", i, CipherNames[i], want[i])
		}
	}
}
