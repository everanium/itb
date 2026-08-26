package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseSize parses a human byte-size string ("16MB", "1MiB", "512K",
// "1073741824") into a byte count. All suffixes are binary multiples:
// K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3.
func parseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	upper := strings.ToUpper(t)
	mult := int64(1)
	switch {
	case strings.HasSuffix(upper, "KIB"), strings.HasSuffix(upper, "KB"):
		mult = 1 << 10
	case strings.HasSuffix(upper, "MIB"), strings.HasSuffix(upper, "MB"):
		mult = 1 << 20
	case strings.HasSuffix(upper, "GIB"), strings.HasSuffix(upper, "GB"):
		mult = 1 << 30
	case strings.HasSuffix(upper, "K"):
		mult = 1 << 10
	case strings.HasSuffix(upper, "M"):
		mult = 1 << 20
	case strings.HasSuffix(upper, "G"):
		mult = 1 << 30
	case strings.HasSuffix(upper, "B"):
		mult = 1
	}
	digits := strings.TrimRight(upper, "KMGIB")
	n, err := strconv.ParseInt(strings.TrimSpace(digits), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("size must be non-negative, got %q", s)
	}
	return n * mult, nil
}

// humanBytes renders a byte count with a binary-unit suffix.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

// humanBytesSigned renders a possibly-negative byte delta with an
// explicit sign.
func humanBytesSigned(n int64) string {
	if n < 0 {
		return "-" + humanBytes(-n)
	}
	return "+" + humanBytes(n)
}

// humanRate renders a bytes-over-duration throughput as MB/s (binary
// MiB per second).
func humanRate(n int64, d time.Duration) string {
	if d <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1fMB/s", float64(n)/float64(1<<20)/d.Seconds())
}

// humanRateBare renders a bytes-over-duration throughput as a bare
// MiB/s figure with no unit suffix. Used by the mid-run progress line
// to compose "enc:X dec:Y combined:ZMB/s" — the suffix appears once at
// the end.
func humanRateBare(n int64, d time.Duration) string {
	if d <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", float64(n)/float64(1<<20)/d.Seconds())
}
