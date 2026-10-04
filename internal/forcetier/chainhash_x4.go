package forcetier

import (
	"os"
	"strings"
)

// ChainHashX4 reports whether ITB_FORCE_CHAINHASH_X4 is set to a true
// value ("1", "true", "yes"). When set, package inits leave the
// eight-lane ZMM fused ChainHash cascade arm disarmed
// (e.g. FusedHasVAESAVX512X8 false), so an AVX-512 host runs the
// four-lane fused kernels of the selected hash tier and the pixel
// pipeline keeps its four-lane stride — the parity / benchmark knob that
// isolates the eight-lane arm on the silicon that would otherwise select
// it. Not a production setting. The variable is consumed once at package
// init by aesitbasm, areionasm, and the hashes/internal/*asm packages.
func ChainHashX4() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_FORCE_CHAINHASH_X4"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
