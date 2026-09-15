package forcetier

import (
	"os"
	"strings"
)

// ChainHashSeq reports whether ITB_FORCE_CHAINHASH_SEQ is set to a true
// value ("1", "true", "yes"). When set, primitives that offer a fused
// ChainHash cascade leave the Seed128 fused hooks unpopulated so the
// sequential per-round loop runs — a benchmark / parity knob, not a
// production setting. The variable is read on every query so a harness
// can flip it between pipeline constructions within one process.
func ChainHashSeq() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_CHAINHASH_SEQ"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
