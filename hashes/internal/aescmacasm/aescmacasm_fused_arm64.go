//go:build arm64 && !purego && !noitbasm

package aescmacasm

import aes "github.com/jedisct1/go-aes"

var (
	// FusedHasARMAES selects the NEON fused kernels on arm64 hosts that
	// carry the AES crypto extension. Runtime-gated on
	// aes.CPU.HasARMCrypto so the pure-Go scalar cascade runs on cores
	// without the extension. The batch-16 fill kernel is gated
	// separately via HasARMAESX16.
	FusedHasARMAES = aes.CPU.HasARMCrypto

	FusedHasVAESAVX512 = false
	FusedHasVAESAVX2   = false
	FusedHasAVXAESNI   = false
	FusedHasAESNI      = false
)

// FusedAvailable reports whether the NEON fused cascade tier is selected.
func FusedAvailable() bool { return FusedHasARMAES }

func FusedChain13x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain13x4NeonAsm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(s, components, dataPtrs, 13, out)
}
func FusedChain20x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain20x4NeonAsm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(s, components, dataPtrs, 20, out)
}
func FusedChain36x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain36x4NeonAsm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(s, components, dataPtrs, 36, out)
}
func FusedChain68x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain68x4NeonAsm(&s.roundKeys, &components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(s, components, dataPtrs, 68, out)
}
func FusedChain13x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain13x1NeonAsm(&s.roundKeys, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(s, components, data, 13, out)
}
func FusedChain20x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain20x1NeonAsm(&s.roundKeys, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(s, components, data, 20, out)
}
func FusedChain36x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain36x1NeonAsm(&s.roundKeys, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(s, components, data, 36, out)
}
func FusedChain68x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	if FusedHasARMAES && validComponents(components) {
		aesCMAC128FusedChain68x1NeonAsm(&s.roundKeys, &components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(s, components, data, 68, out)
}

//go:noescape
func aesCMAC128FusedChain13x4NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain20x4NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain36x4NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain68x4NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func aesCMAC128FusedChain13x1NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain20x1NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain36x1NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func aesCMAC128FusedChain68x1NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, data *byte, out *[2]uint64)

// FusedChain13x16 runs the cascade on the 16 lanes of the Interlocked
// Barrier fill (see the amd64 dispatcher); the NEON kernel is gated on
// the batch-16 flag HasARMAESX16.
func FusedChain13x16(s *Schedule, components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if HasARMAESX16 && validComponents(components) {
		aesCMAC128FusedChain13x16NeonAsm(&s.roundKeys, &components[0], len(components)/2, groupIdxBase, out)
		return
	}
	scalarFusedX16(s, components, groupIdxBase, out)
}

//go:noescape
func aesCMAC128FusedChain13x16NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)
