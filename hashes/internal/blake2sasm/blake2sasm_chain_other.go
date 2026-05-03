//go:build !amd64 || purego || noitbasm

package blake2sasm

// Blake2s256ChainAbsorb20x4 — non-amd64 / purego dispatcher. Always
// delegates to the scalar 4-lane reference. See
// blake2sasm_chain_amd64.go for the full contract description; the
// scalar path produces bit-exact identical output, only without the
// AVX-512 fused acceleration.
func Blake2s256ChainAbsorb20x4(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	scalarBatch256ChainAbsorb20(h0, b2key, seeds, dataPtrs, out)
}

// Blake2s256ChainAbsorb36x4 — non-amd64 / purego dispatcher.
func Blake2s256ChainAbsorb36x4(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	scalarBatch256ChainAbsorb36(h0, b2key, seeds, dataPtrs, out)
}

// Blake2s256ChainAbsorb68x4 — non-amd64 / purego dispatcher.
func Blake2s256ChainAbsorb68x4(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	scalarBatch256ChainAbsorb68(h0, b2key, seeds, dataPtrs, out)
}
