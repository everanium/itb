package forcetier

import "testing"

// TestInterlockPRFFillNarrow pins the parse of
// ITB_FORCE_INTERLOCK_PRF_FILL_NARROW: unset and unknown values leave
// the batch-32 rung armed, the true spellings disarm it, and the
// variable is re-read on every query.
func TestInterlockPRFFillNarrow(t *testing.T) {
	for _, v := range []string{"", "0", "no", "false", "narrow"} {
		t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_NARROW", v)
		if InterlockPRFFillNarrow() {
			t.Fatalf("value %q reported narrow", v)
		}
	}
	for _, v := range []string{"1", "true", "yes", " TRUE ", "Yes"} {
		t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_NARROW", v)
		if !InterlockPRFFillNarrow() {
			t.Fatalf("value %q did not report narrow", v)
		}
	}
}
