package itb

import (
	"os"
	"testing"
)

// TestMain honours the ITB_BITSOUP environment variable. When set to a
// non-zero value before `go test` is invoked, the entire test suite runs
// in bit-soup mode (SetBitSoup(1) called before any test or benchmark).
// Unset or "0" leaves the default byte-level Triple Ouroboros behaviour.
//
//	go test ./...                    # byte-level Triple Ouroboros (default)
//	ITB_BITSOUP=1 go test ./...      # bit-soup Triple Ouroboros
//	ITB_BITSOUP=1 go test -bench=.   # bit-soup benchmarks
//
// Works for every Triple Ouroboros test and benchmark in the package:
// plain Encrypt3x*, EncryptAuthenticated3x*, and EncryptStream3x* all
// route through splitForTriple / interleaveForTriple, which read the
// atomic mode flag at dispatch time. No duplicated test code required.
func TestMain(m *testing.M) {
	if v := os.Getenv("ITB_BITSOUP"); v != "" && v != "0" {
		SetBitSoup(1)
	}
	os.Exit(m.Run())
}
