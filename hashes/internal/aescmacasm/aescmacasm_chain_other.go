//go:build !amd64 || purego || noitbasm

package aescmacasm

// AESCMAC128ChainAbsorb20x4 — non-amd64 / purego dispatcher. Always
// delegates to the scalar 4-lane reference. See
// aescmacasm_chain_amd64.go for the full contract description; the
// scalar path produces bit-exact identical output, only without the
// VAES + AVX-512 fused acceleration. roundKeys is unused on this
// build (the scalar path uses crypto/aes.cipher.Block which carries
// its own internal schedule).
func AESCMAC128ChainAbsorb20x4(
	roundKeys *[176]byte,
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	scalarBatch128ChainAbsorb20(key, seeds, dataPtrs, out)
}

// AESCMAC128ChainAbsorb36x4 — non-amd64 / purego dispatcher.
func AESCMAC128ChainAbsorb36x4(
	roundKeys *[176]byte,
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	scalarBatch128ChainAbsorb36(key, seeds, dataPtrs, out)
}

// AESCMAC128ChainAbsorb68x4 — non-amd64 / purego dispatcher.
func AESCMAC128ChainAbsorb68x4(
	roundKeys *[176]byte,
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	scalarBatch128ChainAbsorb68(key, seeds, dataPtrs, out)
}
