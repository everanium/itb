//go:build !amd64 || purego

package blake3asm

// Blake3256ChainAbsorb20x4 — non-amd64 / purego dispatcher. Always
// delegates to the scalar 4-lane reference. See
// blake3asm_chain_amd64.go for the full contract description; the
// scalar path produces bit-exact identical output, only without the
// AVX-512 fused acceleration.
func Blake3256ChainAbsorb20x4(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	scalarBatch256ChainAbsorb20(key, seeds, dataPtrs, out)
}

// Blake3256ChainAbsorb36x4 — non-amd64 / purego dispatcher.
func Blake3256ChainAbsorb36x4(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	scalarBatch256ChainAbsorb36(key, seeds, dataPtrs, out)
}

// Blake3256ChainAbsorb68x4 — non-amd64 / purego dispatcher.
func Blake3256ChainAbsorb68x4(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	scalarBatch256ChainAbsorb68(key, seeds, dataPtrs, out)
}
