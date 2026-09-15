//go:build arm64 && !purego && !noitbasm

package aesitbasm

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

// AESITB128ChainAbsorb13x4 evaluates the 13-byte shape on four lanes.
func AESITB128ChainAbsorb13x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 13, out)
}

// AESITB128ChainAbsorb20x4 evaluates the 20-byte shape on four lanes.
func AESITB128ChainAbsorb20x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 20, out)
}

// AESITB128ChainAbsorb36x4 evaluates the 36-byte shape on four lanes.
func AESITB128ChainAbsorb36x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 36, out)
}

// AESITB128ChainAbsorb68x4 evaluates the 68-byte shape on four lanes.
func AESITB128ChainAbsorb68x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarBatch(key, seeds, dataPtrs, 68, out)
}
