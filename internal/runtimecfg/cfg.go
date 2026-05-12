// Package runtimecfg reads the ITB_GOMEMLIMIT and ITB_GOGC env vars at
// libitb load time and applies them to the Go runtime via runtime/debug.
// Programmatic setters (itb.SetMemoryLimit, itb.SetGCPercent,
// ITB_SetMemoryLimit, ITB_SetGCPercent) override the env-set values.
package runtimecfg

import (
	"errors"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

func init() {
	if v := os.Getenv("ITB_GOMEMLIMIT"); v != "" {
		if n, err := parseSize(v); err == nil && n > 0 {
			debug.SetMemoryLimit(n)
		}
	}
	if v := os.Getenv("ITB_GOGC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			debug.SetGCPercent(n)
		}
	}
}

// errInvalidSize is returned by parseSize when the input does not
// parse to a non-negative integer followed by an optional supported
// suffix.
var errInvalidSize = errors.New("runtimecfg: invalid size")

// parseSize accepts a plain integer (bytes) or a string with a suffix
// B / KiB / MiB / GiB / TiB. Matches Go's own GOMEMLIMIT parsing
// semantics. Returns the value in bytes.
//
// Suffix matching is case-sensitive: B (or unitless) means bytes;
// KiB / MiB / GiB / TiB are the binary multiples 1024^1 .. 1024^4.
// The numeric portion is integer only. Whitespace is not trimmed;
// the caller is expected to pass a clean env-var value.
func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, errInvalidSize
	}
	// Match the longest suffix first so that "MiB" is not shadowed
	// by "B".
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40},
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"B", 1},
	}
	numPart := s
	var mult int64 = 1
	matched := false
	for _, sf := range suffixes {
		if strings.HasSuffix(s, sf.suffix) {
			numPart = s[:len(s)-len(sf.suffix)]
			mult = sf.mult
			matched = true
			break
		}
	}
	if numPart == "" {
		return 0, errInvalidSize
	}
	// Reject any non-digit characters in the numeric portion. Plain
	// strconv.ParseInt would accept a leading sign and surrounding
	// whitespace; GOMEMLIMIT semantics do not.
	for i := 0; i < len(numPart); i++ {
		c := numPart[i]
		if c < '0' || c > '9' {
			return 0, errInvalidSize
		}
	}
	n, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil {
		return 0, errInvalidSize
	}
	_ = matched
	// Overflow check on multiplication. n is non-negative here.
	if n != 0 && mult != 0 && n > (1<<62)/mult {
		return 0, errInvalidSize
	}
	return n * mult, nil
}
