package main

import (
	"bytes"
	"testing"
)

// repoRoot is the repository root relative to this package directory.
const repoRoot = "../.."

// TestDocumentationFigures computes every figure through the library
// and checks the documentation against it, so a format or parameter
// change that leaves a published number stale fails `go test ./...`.
func TestDocumentationFigures(t *testing.T) {
	f, err := Compute()
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	results, ok := Check(repoRoot, Registry(f))
	if ok {
		t.Logf("%d expectations OK", len(results))
		return
	}
	var buf bytes.Buffer
	for _, r := range results {
		if r.Status != "OK" {
			buf.WriteString(r.String())
			buf.WriteByte('\n')
		}
	}
	t.Fatalf("documentation figures out of date:\n%s", buf.String())
}
