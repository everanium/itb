//go:build amd64 && !purego

package areionasm

// Areion256ChainAbsorb20x4 is the single-round specialised fused
// chained-absorb VAES kernel for Areion-SoEM-256 with 20-byte per-lane
// data shape (the ITB SetNonceBits(128) buf shape — default config).
//
// 20 bytes ≤ 24-byte Areion-SoEM-256 chunkSize, so the absorb is one
// SoEM round; the kernel runs the 10-round Areion256 permutation
// interleaved on state1 and state2, computes the SoEM XOR
// `state1' ⊕ state2'` in registers, and writes the 32-byte digest per
// lane.
//
// Inputs:
//   - fixedKey:  shared 32-byte fixed key (Areion-SoEM-256 SoEM uses key1 = 32 B).
//   - seeds:     per-lane seed components (4 lanes × 4 uint64 = 32 B per lane).
//   - dataPtrs:  4 pointers, each to ≥20 bytes.
//   - out:       output buffer; lane i's 32-byte digest at out[i] as
//                4 little-endian uint64 words.
//
//go:noescape
func Areion256ChainAbsorb20x4(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb36x4 — 2-round specialisation for the 36-byte
// per-lane data shape (ITB SetNonceBits(256)). State is held in
// (Z14, Z15) ZMM registers across both CBC-MAC absorb rounds — no
// memory roundtrip between rounds.
//
//go:noescape
func Areion256ChainAbsorb36x4(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// Areion256ChainAbsorb68x4 — 3-round specialisation for the 68-byte
// per-lane data shape (ITB SetNonceBits(512)). State is held in
// (Z14, Z15) ZMM registers across all three CBC-MAC absorb rounds —
// no memory roundtrip between rounds.
//
//go:noescape
func Areion256ChainAbsorb68x4(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)
