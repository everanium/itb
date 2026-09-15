package forcetier

import (
	"os"
	"strings"
)

// InterlockPRFFillX1 reports whether ITB_FORCE_INTERLOCK_PRF_FILL_X1 is
// set to a true value ("1", "true", "yes"). When set, the lockSeed
// builders leave every batched fill rung disarmed — the batch-32 and
// batch-16 hooks and the four-lane fillRanksX4 arm — so the interlock
// hot loop fills one group per call through the single-lane fillRanks
// arm: the parity / benchmark knob that pins the single-lane rung as the
// top of the fill ladder. Not a production setting. The variable is read
// on every query so a harness can toggle it between pipeline
// constructions within one process.
func InterlockPRFFillX1() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_INTERLOCK_PRF_FILL_X1"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
