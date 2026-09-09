package forcetier

import "testing"

// TestInterlockPRFFillX4 pins the parse of
// ITB_FORCE_INTERLOCK_PRF_FILL_X4: unset and unknown values leave
// the wider rungs armed, the true spellings disarm them, and the
// variable is re-read on every query.
func TestInterlockPRFFillX4(t *testing.T) {
	for _, v := range []string{"", "0", "no", "false", "narrow"} {
		t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_X4", v)
		if InterlockPRFFillX4() {
			t.Fatalf("value %q reported narrow", v)
		}
	}
	for _, v := range []string{"1", "true", "yes", " TRUE ", "Yes"} {
		t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_X4", v)
		if !InterlockPRFFillX4() {
			t.Fatalf("value %q did not report narrow", v)
		}
	}
}
