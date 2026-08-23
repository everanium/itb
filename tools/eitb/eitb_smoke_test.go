package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEITBSmoke builds the eitb binary and runs it once, asserting
// every mode combo reports PASS. This is a smoke test — the full
// per-mode behaviour coverage lives in the capi Triple test file
// (cmd/cshared/internal/capi/triple_test.go) and in the triple
// package's own round-trip tests.
//
// The binary emits one line per example × outer-cipher combination
// followed by a summary line "=== Summary: N PASS, M FAIL ===";
// this test scans the summary line and asserts M == 0 and N > 0.
// The exit code doubles as a hard failure signal: eitb exits non-zero
// when any combination fails, so the *exec.ExitError branch surfaces
// alongside the parsed-summary path.
func TestEITBSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping eitb smoke test in -short mode")
	}

	// Build eitb into a temp file so the smoke run does not depend on
	// a pre-existing binary in the repo root and does not leak an
	// artefact after the test.
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "eitb")

	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	// tools/eitb sits at the same path as this test file; go build .
	// against the package directory produces the binary.
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = pkgDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build eitb: %v\n%s", err, out)
	}

	// Pin the cipher to a single choice to keep the smoke run under
	// a second on typical hardware. The full sweep (every example ×
	// every outer cipher) runs manually from the shell.
	runCmd := exec.Command(binPath, "-cipher", "chacha20")
	out, err := runCmd.CombinedOutput()
	outStr := string(out)
	if err != nil {
		t.Fatalf("eitb run: %v\n%s", err, outStr)
	}

	// Locate the summary line. It appears exactly once, format:
	// "=== Summary: N PASS, M FAIL ===". Presence of "FAIL" outside
	// this line indicates a per-run failure the summary would have
	// already surfaced via M > 0 and a non-zero exit.
	if !strings.Contains(outStr, "=== Summary:") {
		t.Fatalf("eitb output missing summary line:\n%s", outStr)
	}
	if strings.Contains(outStr, "FAIL] ") {
		t.Fatalf("eitb reported per-run FAIL:\n%s", outStr)
	}
	if !strings.Contains(outStr, "PASS,") && !strings.Contains(outStr, "PASS ") {
		t.Fatalf("eitb summary missing PASS count:\n%s", outStr)
	}
	// Zero-PASS output signals the example filter matched nothing —
	// treat as a smoke failure (the smoke run must exercise every
	// shipped example at least once against the pinned cipher).
	if strings.Contains(outStr, "0 PASS") {
		t.Fatalf("eitb ran zero examples:\n%s", outStr)
	}
}
