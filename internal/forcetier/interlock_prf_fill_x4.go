package forcetier

import (
	"os"
	"strings"
)

// InterlockPRFFillX4 reports whether ITB_FORCE_INTERLOCK_PRF_FILL_X4 is
// set to a true value ("1", "true", "yes"). When set, the lockSeed
// builders leave the batch-16 and batch-32 fill hooks disarmed, so the
// interlock hot loop runs the four-lane fillRanksX4 rung (or the
// single-lane arm below it) — the parity / benchmark knob that pins the
// four-lane rung as the top of the fill ladder.
// ITB_FORCE_INTERLOCK_PRF_FILL_X1 disarms that rung as well, and
// ITB_FORCE_INTERLOCK_PRF_FILL_SEQ every batched rung. Not a production
// setting. The variable is read on every query so a harness can toggle
// it between pipeline constructions within one process.
func InterlockPRFFillX4() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_INTERLOCK_PRF_FILL_X4"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
