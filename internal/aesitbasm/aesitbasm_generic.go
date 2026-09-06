//go:build (!amd64 && !arm64) || purego || noitbasm

package aesitbasm

// AESITB128ChainAbsorb13x16 evaluates the 13-byte shape on 16 lanes.
// On amd64 with ASM enabled, this dispatches to the appropriate tier (vex, aesni, etc.).
// On arm64 with ASM enabled, this dispatches to the neon tier.
// On other platforms or with purego/noitbasm, it falls back to the scalar reference.
func AESITB128ChainAbsorb13x16(key *[16]byte, seed0, seed1 uint64, groupIdxBase uint64, out *[16][2]uint64) {
	scalarBatchX16(key, groupIdxBase, seed0, seed1, out)
}
