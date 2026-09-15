//go:build (!amd64 && !arm64) || purego || noitbasm

package aescmacasm

// No assembly tier applies on this build; every dispatcher routes to the
// scalar reference. The flags exist so callers compile uniformly.
var (
	// Batch-16 tier flags — always false without an assembly tier.
	HasVAESAVX512X16 = false
	HasVAESAVX2X16   = false
	HasAVXAESNIX16   = false
	HasAESNIX16      = false
	HasARMAESX16     = false
)
