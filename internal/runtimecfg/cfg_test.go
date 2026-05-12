package runtimecfg

import "testing"

func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		// Plain integer (unitless == bytes).
		{"0", 0, false},
		{"1", 1, false},
		{"512", 512, false},
		{"1024", 1024, false},

		// Explicit B suffix.
		{"0B", 0, false},
		{"1B", 1, false},
		{"4096B", 4096, false},

		// Binary multiples.
		{"1KiB", 1 << 10, false},
		{"512KiB", 512 << 10, false},
		{"1MiB", 1 << 20, false},
		{"512MiB", 512 << 20, false},
		{"1GiB", 1 << 30, false},
		{"8GiB", 8 << 30, false},
		{"1TiB", 1 << 40, false},
		{"2TiB", 2 << 40, false},

		// Invalid forms: empty, missing number, decimal point,
		// negative, leading sign, lowercase suffix, decimal suffix,
		// whitespace, mixed case.
		{"", 0, true},
		{"MiB", 0, true},
		{"GiB", 0, true},
		{"1.5GiB", 0, true},
		{"-1", 0, true},
		{"-1GiB", 0, true},
		{"+1GiB", 0, true},
		{"1kib", 0, true},
		{"1mib", 0, true},
		{"1gib", 0, true},
		{"1b", 0, true},
		{"1KB", 0, true},
		{"1MB", 0, true},
		{"1GB", 0, true},
		{"1K", 0, true},
		{"1M", 0, true},
		{"1G", 0, true},
		{"1 GiB", 0, true},
		{" 1GiB", 0, true},
		{"1GiB ", 0, true},
		{"abc", 0, true},
		{"1xMiB", 0, true},

		// Overflow: 9223372036854775807 bytes is the max int64;
		// 1TiB * (1<<24) overflows.
		{"99999999999999TiB", 0, true},
	}
	for _, c := range cases {
		got, err := parseSize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseSize(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSize(%q) returned error %v, want %d", c.in, err, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("parseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
