package capi

import "testing"

// TestHeaderSize confirms the capi HeaderSize helper computes the
// correct chunk header prefix for every valid nonce-byte value and
// rejects out-of-range inputs with StatusBadInput.
//
// This test is the drift guard for the intentional 2*nonceBytes+4
// formula duplication between itb.headerSizeCfg and
// [capi.HeaderSize] (whose FFI-adapter C-ABI stability contract is
// decoupled from itb-internal helpers). The literal expected sizes
// 36 / 68 / 132 pin the formula; any refactor of HeaderSize that
// changes those values must be an intentional wire break.
func TestHeaderSize(t *testing.T) {
	cases := []struct {
		nonceBytes int
		want       int
		wantStatus Status
	}{
		{16, 36, StatusOK},
		{32, 68, StatusOK},
		{64, 132, StatusOK},
		{0, 0, StatusBadInput},
		{20, 0, StatusBadInput},
		{128, 0, StatusBadInput},
	}
	for _, c := range cases {
		got, st := HeaderSize(c.nonceBytes)
		if st != c.wantStatus {
			t.Errorf("HeaderSize(%d) status = %v, want %v", c.nonceBytes, st, c.wantStatus)
		}
		if got != c.want {
			t.Errorf("HeaderSize(%d) = %d, want %d", c.nonceBytes, got, c.want)
		}
	}
}

// TestReadOnlyConstants verifies build-time constants are reachable.
func TestReadOnlyConstants(t *testing.T) {
	if MaxKeyBits() != 2048 {
		t.Errorf("MaxKeyBits = %d, want 2048", MaxKeyBits())
	}
	if Channels() != 8 {
		t.Errorf("Channels = %d, want 8", Channels())
	}
}

// TestDefaultNonceBits confirms the exported compile-in default nonce
// width matches the itb DefaultNonceBits constant (used by bindings
// that need a sentinel for streaming without threading a Config).
func TestDefaultNonceBits(t *testing.T) {
	if got := DefaultNonceBits(); got != 512 {
		t.Errorf("DefaultNonceBits() = %d, want 512", got)
	}
}
