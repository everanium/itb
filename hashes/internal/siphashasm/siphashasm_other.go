//go:build (!amd64 && !arm64) || purego || noitbasm

package siphashasm

// No assembly tier applies on this build; every dispatcher routes to the
// scalar reference. The flags exist so callers compile uniformly.
var (
	// Batch-16 tier flags — always false without an assembly tier.
	HasAVX512X16 = false
	HasAVX2X16   = false
	HasNEONX16   = false
)
