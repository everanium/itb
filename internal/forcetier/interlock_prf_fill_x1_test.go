package forcetier

import "testing"

// TestInterlockPRFFillX1 pins the parse of
// ITB_FORCE_INTERLOCK_PRF_FILL_X1: unset and unknown values leave
// the wider rungs armed, the true spellings disarm them, and the
// variable is re-read on every query.
func TestInterlockPRFFillX1(t *testing.T) {
	for _, v := range []string{"", "0", "no", "false", "narrow"} {
		t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_X1", v)
		if InterlockPRFFillX1() {
			t.Fatalf("value %q reported narrow", v)
		}
	}
	for _, v := range []string{"1", "true", "yes", " TRUE ", "Yes"} {
		t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_X1", v)
		if !InterlockPRFFillX1() {
			t.Fatalf("value %q did not report narrow", v)
		}
	}
}
