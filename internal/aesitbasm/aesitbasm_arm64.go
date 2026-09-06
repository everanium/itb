//go:build arm64 && !purego && !noitbasm

package aesitbasm

import aes "github.com/jedisct1/go-aes"

var (
	// HasARMAESBatched selects the NEON crypto-extension kernels
	// (AESE + AESMC): one lane per vector register, four independent
	// chains.
	HasARMAESBatched = aes.CPU.HasARMCrypto

	// HasARMAESX16 selects the NEON batch-16 kernel for the 13-byte shape.
	// Auto-selected when HasARMAESBatched is true.
	HasARMAESX16 = aes.CPU.HasARMCrypto

	// The amd64 tier flags are always false on arm64 builds.
	HasVAESAVX512       = false
	HasVAESAVX2NoAVX512 = false
	HasAVXAESNIBatched  = false
	HasAESNIBatched     = false

	// The amd64 batch-16 tier flags are always false on arm64 builds.
	HasVAESAVX512X16 = false
	HasVAESAVX2X16   = false
	HasAVXAESNIX16   = false
	HasAESNIX16      = false
)

// AESITB128ChainAbsorb13x4 evaluates the 13-byte shape on four lanes.
func AESITB128ChainAbsorb13x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if HasARMAESBatched {
		aesITB128ChainAbsorb13x4NeonAsm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch(key, seeds, dataPtrs, 13, out)
}

// AESITB128ChainAbsorb20x4 evaluates the 20-byte shape on four lanes.
func AESITB128ChainAbsorb20x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if HasARMAESBatched {
		aesITB128ChainAbsorb20x4NeonAsm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch(key, seeds, dataPtrs, 20, out)
}

// AESITB128ChainAbsorb36x4 evaluates the 36-byte shape on four lanes.
func AESITB128ChainAbsorb36x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if HasARMAESBatched {
		aesITB128ChainAbsorb36x4NeonAsm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch(key, seeds, dataPtrs, 36, out)
}

// AESITB128ChainAbsorb68x4 evaluates the 68-byte shape on four lanes.
func AESITB128ChainAbsorb68x4(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if HasARMAESBatched {
		aesITB128ChainAbsorb68x4NeonAsm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch(key, seeds, dataPtrs, 68, out)
}

// NEON crypto-extension kernels (aesitb_chain128_*_neon_arm64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x4NeonAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb20x4NeonAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb36x4NeonAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128ChainAbsorb68x4NeonAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

// NEON batch-16 kernel (aesitb_chain128_13x16_neon_arm64.s).
//
//go:noescape
func aesITB128ChainAbsorb13x16NeonAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)

// AESITB128ChainAbsorb13x16 evaluates the 13-byte shape on 16 lanes.
func AESITB128ChainAbsorb13x16(key *[16]byte, seed0, seed1 uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if HasARMAESX16 {
		aesITB128ChainAbsorb13x16NeonAsm(key, seed0, seed1, groupIdxBase, out)
		return
	}
	scalarBatchX16(key, groupIdxBase, seed0, seed1, out)
}
