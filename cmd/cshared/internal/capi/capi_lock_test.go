package capi

import "testing"

// Scope: defensive-status-branch coverage for the shared Status
// enum's default (unknown-value) label path.

// ───────────────────────────────────────────────────────────────────
// Status.String — defensive default branch
// ───────────────────────────────────────────────────────────────────

// TestStatusStringUnknownValue covers the default "unknown status"
// branch in Status.String() by constructing a Status value outside
// the defined constants.
func TestStatusStringUnknownValue(t *testing.T) {
	s := Status(12345)
	if got := s.String(); got != "unknown status" {
		t.Errorf("Status(12345).String() = %q, want %q", got, "unknown status")
	}
}
