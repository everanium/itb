//go:build amd64 && !purego

package areionasm

// Areion512ChainAbsorb20x4 is the single-round specialised fused
// chained-absorb VAES kernel for Areion-SoEM-512 with 20-byte per-lane
// data shape (the ITB SetNonceBits(128) buf shape — default config).
//
// 20 bytes ≤ 56-byte SoEM-512 chunkSize, so the absorb is one SoEM
// round; the kernel runs the 15-round Areion512 permutation
// interleaved on state1 and state2, applies the cyclic rotation
// `(x0,x1,x2,x3) → (x3,x0,x1,x2)` fused with the SoEM XOR, and writes
// the 64-byte digest per lane.
//
// Inputs:
//   - fixedKey:  shared 64-byte fixed key (Areion512 SoEM uses key1 = 64 B).
//   - seeds:     per-lane seed components (4 lanes × 8 uint64 = 64 B per lane).
//   - dataPtrs:  4 pointers, each to ≥20 bytes.
//   - out:       output buffer; lane i's 64-byte digest at out[i] as
//                8 little-endian uint64 words.
//
//go:noescape
func Areion512ChainAbsorb20x4(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb36x4 — single-round specialisation for the
// 36-byte per-lane data shape (ITB SetNonceBits(256)). 36 ≤ 56-byte
// chunkSize so still one round; only the data layout in the initial
// state differs from the 20-byte case.
//
//go:noescape
func Areion512ChainAbsorb36x4(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Areion512ChainAbsorb68x4 — 2-round specialisation for the 68-byte
// per-lane data shape (ITB SetNonceBits(512)). State held in
// (Z14, Z15, Z16, Z17) ZMM registers across both CBC-MAC absorb
// rounds — no memory roundtrip between rounds.
//
//go:noescape
func Areion512ChainAbsorb68x4(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)
