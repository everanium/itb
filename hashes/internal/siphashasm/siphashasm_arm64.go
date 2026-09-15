//go:build arm64 && !purego && !noitbasm

package siphashasm

var (
	// HasNEONX16 selects the NEON batch-16 arm (two calls of the
	// eight-lane NEON fill kernel). NEON is baseline on arm64, so the flag
	// is true unless a forcetier variable clears it.
	HasNEONX16 = true

	// The amd64 batch-16 tier flags are always false on arm64 builds.
	HasAVX512X16 = false
	HasAVX2X16   = false
)
