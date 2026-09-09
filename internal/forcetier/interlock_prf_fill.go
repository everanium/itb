package forcetier

import (
	"os"
	"strings"
)

// InterlockPRFFillSeq reports whether ITB_FORCE_INTERLOCK_PRF_FILL_SEQ is
// set to a true value ("1", "true", "yes"). When set, the lockSeed
// builders leave every batched fill rung disarmed — the batch-32 and
// batch-16 hooks and the four-lane fillRanksX4 arm — so the interlock
// hot loop fills one group per call through the single-lane fillRanks
// arm. This is a KAT parity knob for the parity harness, not a
// production setting; ITB_FORCE_INTERLOCK_PRF_FILL_X1 / _X4 / _X16 pin
// the narrower rungs one at a time. The variable is read on every query
// so a harness can toggle it between pipeline constructions within one
// process.
func InterlockPRFFillSeq() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
