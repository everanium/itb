package itb

import "github.com/everanium/itb/internal/forcetier"

// interlock48_fill_knobs_test.go — the fill-ladder knobs as the tests
// see them: a test that exercises a rung skips when a knob disarms it.

// fillBatch16Disarmed reports whether a knob leaves the batch-16 fill
// rung off: ITB_FORCE_INTERLOCK_PRF_FILL_SEQ, _X1 or _X4.
func fillBatch16Disarmed() bool {
	return forcetier.InterlockPRFFillSeq() || forcetier.InterlockPRFFillX1() || forcetier.InterlockPRFFillX4()
}

// fillBatch32Disarmed reports whether a knob leaves the batch-32 fill
// rung off: any knob of fillBatch16Disarmed or _X16.
func fillBatch32Disarmed() bool {
	return fillBatch16Disarmed() || forcetier.InterlockPRFFillX16()
}

// clearFillKnobs unsets every fill-ladder knob for the test's duration.
func clearFillKnobs(t interface{ Setenv(string, string) }) {
	for _, k := range []string{"ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "ITB_FORCE_INTERLOCK_PRF_FILL_X1", "ITB_FORCE_INTERLOCK_PRF_FILL_X4", "ITB_FORCE_INTERLOCK_PRF_FILL_X16"} {
		t.Setenv(k, "")
	}
}
