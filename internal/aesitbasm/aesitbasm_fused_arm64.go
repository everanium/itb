//go:build arm64 && !purego && !noitbasm

package aesitbasm

import aes "github.com/jedisct1/go-aes"

var (
	// FusedHasARMAES selects the NEON fused kernels on arm64 hosts that
	// carry the AES crypto extension. Runtime-gated on
	// aes.CPU.HasARMCrypto so the pure-Go scalar cascade runs on cores
	// without the extension. The per-round NEON kernels remain on the
	// same gate.
	FusedHasARMAES = aes.CPU.HasARMCrypto

	FusedHasVAESAVX512 = false
	FusedHasVAESAVX2   = false
	FusedHasAVXAESNI   = false
	FusedHasAESNI      = false
)

func FusedChain13x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain13x4NeonAsm(key, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(key, components, dataPtrs, 13, out)
}
func FusedChain20x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain20x4NeonAsm(key, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(key, components, dataPtrs, 20, out)
}
func FusedChain36x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain36x4NeonAsm(key, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(key, components, dataPtrs, 36, out)
}
func FusedChain68x4(key *[16]byte, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain68x4NeonAsm(key, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(key, components, dataPtrs, 68, out)
}
func FusedChain13x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain13x1NeonAsm(key, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(key, components, data, 13, out)
}
func FusedChain20x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain20x1NeonAsm(key, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(key, components, data, 20, out)
}
func FusedChain36x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain36x1NeonAsm(key, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(key, components, data, 36, out)
}
func FusedChain68x1(key *[16]byte, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesITB128FusedChain68x1NeonAsm(key, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(key, components, data, 68, out)
}

//go:noescape
func aesITB128FusedChain13x4NeonAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain20x4NeonAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain36x4NeonAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain68x4NeonAsm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesITB128FusedChain13x1NeonAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain20x1NeonAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain36x1NeonAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesITB128FusedChain68x1NeonAsm(key *[16]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

// FusedChain13x16 runs the cascade on the 16 lanes of the Interlocked
// Barrier fill (see the amd64 dispatcher); the NEON kernel is gated on
// the batch-16 flag HasARMAESX16.
func FusedChain13x16(key *[16]byte, components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if HasARMAESX16 && validComponents(components) {
		aesITB128FusedChain13x16NeonAsm(key, &components[0], len(components)/2, groupIdxBase, out)
		return
	}
	scalarFusedX16(key, components, groupIdxBase, out)
}

//go:noescape
func aesITB128FusedChain13x16NeonAsm(key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
