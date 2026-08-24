package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEITBSmoke builds the fleet-common eitb utility and exercises
// each of its four subcommands (version, hashes, encrypt, decrypt)
// against one Single Message profile and one Streaming profile so both
// dispatch arms are covered. The out-file path lives under a nested
// directory that does not exist beforehand, which also verifies the
// auto-mkdir behaviour the fleet contract requires.
func TestEITBSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping eitb smoke test in -short mode")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "eitb")

	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = pkgDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build eitb: %v\n%s", err, out)
	}

	// A fixed sample in-file lives at tools/eitb/in-file.txt so the
	// smoke run does not depend on the CWD.
	inFile := filepath.Join(pkgDir, "in-file.txt")
	if _, err := os.Stat(inFile); err != nil {
		t.Fatalf("in-file.txt missing at %s: %v", inFile, err)
	}
	original, err := os.ReadFile(inFile)
	if err != nil {
		t.Fatalf("read in-file: %v", err)
	}

	// eitb version — must print two lines starting with libitb / itb-go.
	verCmd := exec.Command(binPath, "version")
	verOut, err := verCmd.Output()
	if err != nil {
		t.Fatalf("eitb version: %v", err)
	}
	if !strings.Contains(string(verOut), "libitb ") || !strings.Contains(string(verOut), "itb-go ") {
		t.Fatalf("eitb version output missing expected lines:\n%s", verOut)
	}

	// eitb hashes — non-empty roster.
	hashesCmd := exec.Command(binPath, "hashes")
	hashesOut, err := hashesCmd.Output()
	if err != nil {
		t.Fatalf("eitb hashes: %v", err)
	}
	if len(bytes.TrimSpace(hashesOut)) == 0 {
		t.Fatalf("eitb hashes: empty output")
	}

	// Round-trip both Single Message and Streaming profiles. Streaming
	// dispatch exercises the "streaming-" prefix branch.
	profiles := []string{
		"singlemsg-triple-mac-v1",
		"streaming-noaead-triple-v1",
	}
	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			// Nested out-file directory — must be auto-created.
			outFile := filepath.Join(tmpDir, "nested", profile, "out.bin")
			encCmd := exec.Command(binPath, "encrypt", profile, inFile, outFile)
			var encStderr bytes.Buffer
			encCmd.Stderr = &encStderr
			if _, err := encCmd.Output(); err != nil {
				t.Fatalf("eitb encrypt %s: %v\nstderr: %s", profile, err, encStderr.String())
			}
			blobHex := strings.TrimSpace(encStderr.String())
			// Blob hex is the last non-empty line on stderr.
			if idx := strings.LastIndex(blobHex, "\n"); idx >= 0 {
				blobHex = strings.TrimSpace(blobHex[idx+1:])
			}
			if blobHex == "" {
				t.Fatalf("eitb encrypt %s: empty blob hex on stderr", profile)
			}
			if _, err := os.Stat(outFile); err != nil {
				t.Fatalf("eitb encrypt %s: out-file missing: %v", profile, err)
			}

			backFile := filepath.Join(tmpDir, "back", profile, "back.bin")
			decCmd := exec.Command(binPath, "decrypt", profile, blobHex, outFile, backFile)
			if out, err := decCmd.CombinedOutput(); err != nil {
				t.Fatalf("eitb decrypt %s: %v\n%s", profile, err, out)
			}
			recovered, err := os.ReadFile(backFile)
			if err != nil {
				t.Fatalf("read recovered plaintext: %v", err)
			}
			if !bytes.Equal(recovered, original) {
				t.Fatalf("eitb %s: recovered plaintext does not match original", profile)
			}
		})
	}
}
