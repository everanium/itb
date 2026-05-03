//go:build amd64 && !purego && !noitbasm

// Package areionasm holds the AVX-512 + VAES (and AVX-2 fallback)
// assembly implementation of the 4-way batched Areion family for the
// parent `itb` package. It lives in an internal subpackage because
// `itb` uses CGO (Go's build system does not allow Go assembly files
// in CGO-using packages).
//
// Exported kernels:
//
//   - Areion256Permutex4 / Areion512Permutex4 — per-half AVX-512 + VAES
//     permutations. On amd64 production hot paths these are reached
//     only via the AVX-2 sibling (see below) and the fused /
//     chained-absorb kernels; the per-half AVX-512 entries remain
//     primarily as the fast-known-good reference for parity tests.
//   - Areion256Permutex4Avx2 / Areion512Permutex4Avx2 — AVX-2 + VAES
//     fallbacks for hosts with VAES but no AVX-512 (some Alder Lake /
//     Raptor Lake E-core configurations, certain Zen 3 SKUs).
//   - Areion256SoEMPermutex4Interleaved /
//     Areion512SoEMPermutex4Interleaved — fused per-half kernels that
//     interleave state1 and state2 permutations on independent ZMM
//     dependency chains and fold the SoEM output XOR (and Areion512's
//     final cyclic rotation) into the writeback.
//   - Areion256ChainAbsorb20x4 / 36x4 / 68x4 (and the Areion-SoEM-512
//     trio) — specialised CBC-MAC chained-absorb kernels for the three
//     ITB SetNonceBits buf shapes (1, 2 or 3 absorb rounds on -256;
//     1, 1 or 2 on -512). State is held in ZMM registers across all
//     absorb rounds; broadcast fixedKey and SoA-packed seedKey are
//     loaded once at function entry.
//
// Also exported: the pre-broadcast round-constant table `AreionRC4x`
// and the Areion-SoEM-256 domain-separation constant
// `AreionSoEMDomainSep256`. AoS <-> SoA pack/unpack, runtime dispatch,
// and the Go-side hash closures live in the parent `itb` package.
package areionasm

import "github.com/jedisct1/go-aes"

// AreionRC4x holds the 15 Areion round constants in pre-broadcast form
// (each 16-byte constant replicated four times to fill a 64-byte ZMM
// register). Layout: rc[r] occupies bytes [r*64 : (r+1)*64], with the
// 16-byte constant copied at offsets {0, 16, 32, 48} within each block.
//
// Initialised by `init()` from the canonical 16-byte constants in
// `Constants`. The assembly file `areion_amd64.s` references this
// symbol as `·AreionRC4x(SB)`.
var AreionRC4x [15 * 64]byte

// AreionSoEMDomainSep256 is the SoEM-256 domain-separation constant
// pre-broadcast to SoA Block4 layout: 0x01 in byte[0] of each 16-byte
// lane slot, zero elsewhere. Used by the chained-absorb kernels to
// XOR `d` into state2's first u64 word per SoEM construction.
var AreionSoEMDomainSep256 = [64]byte{
	0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // lane 0
	0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // lane 1
	0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // lane 2
	0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // lane 3
}

// Constants is the canonical 15-entry round constant table — digits of
// pi in little-endian byte order, copied verbatim from
// `github.com/jedisct1/go-aes/areion.go:areionRoundConstants`. Areion256
// uses entries 0..9; Areion512 uses entries 0..14.
var Constants = [15][16]byte{
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
	{0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
	{0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
	{0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
	{0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
	{0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57},
}

func init() {
	for r := 0; r < 15; r++ {
		for copyIdx := 0; copyIdx < 4; copyIdx++ {
			copy(AreionRC4x[r*64+copyIdx*16:r*64+copyIdx*16+16], Constants[r][:])
		}
	}
}

// Areion256Permutex4 applies the 10-round Areion256 permutation to four
// independent states packed in SoA layout: `*x0` holds the four lanes'
// first 16-byte AES blocks (Block4 = 64 bytes), `*x1` holds the second
// 16-byte blocks. Implemented in `areion_amd64.s` using AVX-512 + VAES
// instructions on ZMM registers.
//
//go:noescape
func Areion256Permutex4(x0, x1 *aes.Block4)

// Areion512Permutex4 applies the 15-round Areion512 permutation to four
// independent states packed in SoA layout: each `*xN` holds the four
// lanes' N-th 16-byte AES block (Block4 = 64 bytes). Includes the final
// cyclic state rotation `(x0,x1,x2,x3) → (x3,x0,x1,x2)` documented in
// the Areion paper / `areion512PermuteSoftware`. Implemented in
// `areion_amd64.s`.
//
//go:noescape
func Areion512Permutex4(x0, x1, x2, x3 *aes.Block4)

// Areion256Permutex4Avx2 is the AVX2 + VAES variant of
// Areion256Permutex4, written for x86_64 CPUs that have VAES but no
// AVX-512 (some Intel Alder Lake / Raptor Lake E-core configurations
// when isolated, certain AMD Zen 3 SKUs). Same SoA layout and bit-exact
// parity invariant as the AVX-512 path; the only difference is the
// internal VAESENC instructions operate on YMM registers (2 AES blocks
// per call) instead of ZMM (4 blocks per call), so each Areion round
// body runs twice — once for lanes 0-1 and once for lanes 2-3.
//
//go:noescape
func Areion256Permutex4Avx2(x0, x1 *aes.Block4)

// Areion512Permutex4Avx2 is the AVX2 + VAES counterpart for the 512-bit
// permutation. Same constraints as Areion256Permutex4Avx2 — VAES on
// YMM, no AVX-512 required, 2 AES blocks per VAES instruction. Each
// of the 15 rounds runs twice (one body per lane pair), plus the final
// cyclic state rotation. Bit-exact parity invariant identical to the
// AVX-512 path.
//
//go:noescape
func Areion512Permutex4Avx2(x0, x1, x2, x3 *aes.Block4)

// HasVAESAVX512 caches whether the runtime CPU supports VAES + AVX-512.
// Resolved once at init time from the upstream `aes` package's
// CPUID-driven detection. Both flags must be set for the AVX-512 path
// to be selected.
var HasVAESAVX512 = aes.CPU.HasVAES && aes.CPU.HasAVX512

// HasVAESAVX2NoAVX512 is true for x86_64 CPUs that have VAES + AVX2 but
// lack AVX-512. The runtime dispatcher in the parent itb package picks
// this path when HasVAESAVX512 is false but VAES is still available, so
// the YMM assembly variants run instead of falling all the way back to
// the portable Go path.
var HasVAESAVX2NoAVX512 = aes.CPU.HasVAES && aes.CPU.HasAVX2 && !aes.CPU.HasAVX512
