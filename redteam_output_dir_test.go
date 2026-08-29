//go:build redteam

package itb

import (
	"os"
	"path/filepath"
	"strings"
)

// redteamOutputDir returns the scratch directory into which red-team
// probes emit their JSON records. Default: `$HOME/scratch/redteam/<name>/`
// per the working-tree layout (scratch outputs live outside the
// repository tree). Override via `REDTEAM_<UPPER_NAME>_OUTPUT_DIR`
// (e.g. `REDTEAM_NONCE_REUSE_OUTPUT_DIR`). The env variable takes the
// full path verbatim, no substitution.
//
// The helper mirrors the Python-side pattern
// (`ITB_KL_OUTPUT_DIR` / `SAT_HARNESS_4ROUND_OUTPUT_DIR` /
// `GD_CHAINHASH_AES2R_OUTPUT_DIR`): default under `~/scratch/redteam/`,
// override via one env variable per probe. Test code is
// location-independent — the caller supplies `filepath.Join(dir, name)`
// per emit.
func redteamOutputDir(name string) string {
	envKey := "REDTEAM_" + strings.ToUpper(strings.ReplaceAll(name, "/", "_")) + "_OUTPUT_DIR"
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, "scratch", "redteam", name)
}
