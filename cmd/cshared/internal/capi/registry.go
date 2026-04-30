package capi

import "github.com/everanium/itb/hashes"

// HashCount returns the number of PRF-grade hash primitives shipped
// with the library — currently 9, matching len(hashes.Registry).
func HashCount() int { return len(hashes.Registry) }

// HashName returns the canonical name of the i-th hash primitive
// in iteration order, or "" when i is out of range.
func HashName(i int) string {
	if i < 0 || i >= len(hashes.Registry) {
		return ""
	}
	return hashes.Registry[i].Name
}

// HashWidth returns the native intermediate-state width of the i-th
// hash primitive in bits (128 / 256 / 512), or 0 when i is out of
// range.
func HashWidth(i int) int {
	if i < 0 || i >= len(hashes.Registry) {
		return 0
	}
	return int(hashes.Registry[i].Width)
}
