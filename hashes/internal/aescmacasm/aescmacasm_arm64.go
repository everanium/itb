//go:build arm64 && !purego && !noitbasm

package aescmacasm

import aes "github.com/jedisct1/go-aes"

var (
	// HasARMAESX16 selects the NEON batch-16 kernel for the 13-byte shape.
	// Auto-selected on hosts that carry the ARM crypto extension.
	HasARMAESX16 = aes.CPU.HasARMCrypto

	// The amd64 batch-16 tier flags are always false on arm64 builds.
	HasVAESAVX512X16 = false
	HasVAESAVX2X16   = false
	HasAVXAESNIX16   = false
	HasAESNIX16      = false
)
