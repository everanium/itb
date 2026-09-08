package forcetier

import (
	"os"
	"strings"
)

// InterlockPRFFillX16 reports whether ITB_FORCE_INTERLOCK_PRF_FILL_X16
// is set to a true value ("1", "true", "yes"). When set, the width-256 /
// width-512 lockSeed builders leave the optional batch-32 fillRanksSuper32
// hook disarmed, so the interlock hot loop runs the batch-16
// fillRanksSuper rung (or the four-lane / single-lane arms below it) —
// the parity / benchmark knob that isolates the batch-32 rung on a host
// that would otherwise select it. ITB_FORCE_INTERLOCK_PRF_FILL_SEQ
// disarms both rungs. Not a production setting. The variable is read on
// every query so a harness can toggle it between pipeline constructions
// within one process.
func InterlockPRFFillX16() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_INTERLOCK_PRF_FILL_X16"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
