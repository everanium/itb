package forcetier

import (
	"os"
	"strings"
)

// InterlockPRFFillSeq reports whether ITB_FORCE_INTERLOCK_PRF_FILL_SEQ is
// set to a true value ("1", "true", "yes"). When set, the interlock hot
// loop falls back to four sequential fillRanksX4 calls per super-block
// instead of using the optional batch-16 fillRanksSuper hook. This is a
// KAT parity knob for the aesitbasm parity harness, not a production
// setting. The variable is read on every query so a harness can toggle
// it between pipeline constructions within one process.
func InterlockPRFFillSeq() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
