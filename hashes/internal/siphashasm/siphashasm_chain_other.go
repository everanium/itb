//go:build !amd64 || purego

package siphashasm

// SipHash24Chain128Absorb20x4 — non-amd64 / purego dispatcher.
// Always delegates to the scalar 4-lane reference. See
// siphashasm_chain_amd64.go for the full contract description; the
// scalar path produces bit-exact identical output, only without the
// AVX-512 fused acceleration.
func SipHash24Chain128Absorb20x4(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	scalarBatch128ChainAbsorb20(seeds, dataPtrs, out)
}

// SipHash24Chain128Absorb36x4 — non-amd64 / purego dispatcher.
func SipHash24Chain128Absorb36x4(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	scalarBatch128ChainAbsorb36(seeds, dataPtrs, out)
}

// SipHash24Chain128Absorb68x4 — non-amd64 / purego dispatcher.
func SipHash24Chain128Absorb68x4(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	scalarBatch128ChainAbsorb68(seeds, dataPtrs, out)
}
