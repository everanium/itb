//go:build !amd64 || purego

package blake2basm

// Blake2b512ChainAbsorb20x4 — non-amd64 / purego dispatcher. Always
// delegates to the scalar 4-lane reference. See
// blake2basm_chain_amd64.go for the full contract description; the
// scalar path produces bit-exact identical output, only without the
// AVX-512 fused acceleration.
func Blake2b512ChainAbsorb20x4(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	scalarBatch512ChainAbsorb20(h0, b2key, seeds, dataPtrs, out)
}

// Blake2b512ChainAbsorb36x4 — non-amd64 / purego dispatcher.
func Blake2b512ChainAbsorb36x4(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	scalarBatch512ChainAbsorb36(h0, b2key, seeds, dataPtrs, out)
}

// Blake2b512ChainAbsorb68x4 — non-amd64 / purego dispatcher.
func Blake2b512ChainAbsorb68x4(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	scalarBatch512ChainAbsorb68(h0, b2key, seeds, dataPtrs, out)
}

// Blake2b256ChainAbsorb20x4 — non-amd64 / purego dispatcher for the
// BLAKE2b-256 batched kernel.
func Blake2b256ChainAbsorb20x4(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	scalarBatch256ChainAbsorb20(h0, b2key, seeds, dataPtrs, out)
}

// Blake2b256ChainAbsorb36x4 — non-amd64 / purego dispatcher.
func Blake2b256ChainAbsorb36x4(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	scalarBatch256ChainAbsorb36(h0, b2key, seeds, dataPtrs, out)
}

// Blake2b256ChainAbsorb68x4 — non-amd64 / purego dispatcher.
func Blake2b256ChainAbsorb68x4(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	scalarBatch256ChainAbsorb68(h0, b2key, seeds, dataPtrs, out)
}
