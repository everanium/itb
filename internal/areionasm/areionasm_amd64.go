//go:build amd64 && !purego && !noitbasm

// Package areionasm holds the AVX-512 + VAES, AVX2 + VAES and legacy-SSE
// AES-NI assembly implementation of the 4-way batched Areion family for
// the parent `itb` package. It lives in an internal subpackage because
// `itb` uses CGO (Go's build system does not allow Go assembly files
// in CGO-using packages).
//
// The SoEM round function is SoEM22: F(m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕
// k1 ⊕ k2, with P1 the Areion permutation under the round constants of
// AreionRCTable and P2 the Areion permutation under the second table
// AreionRCTable2.
//
// Exported kernels:
//
//   - Areion256Permutex4 / Areion512Permutex4 (P1) and Areion256Permute2x4
//     / Areion512Permute2x4 (P2) — per-half AVX-512 + VAES permutations;
//     the fast-known-good reference for parity tests.
//   - the Avx2 and AesNi forms of the same four — AVX2 + VAES for hosts
//     with VAES but no AVX-512 (some Alder Lake / Raptor Lake E-core
//     configurations, certain Zen 3 SKUs); legacy-SSE AES-NI XMM for
//     hosts without VAES.
//   - Areion256SoEMPermutex4Interleaved /
//     Areion512SoEMPermutex4Interleaved — fused kernels that interleave
//     the P1 and P2 permutations on independent ZMM dependency chains
//     and fold the SoEM output XOR (and Areion512's final cyclic
//     rotation) into the writeback; Areion256SoEMPermutex4AesNi /
//     Areion512SoEMPermutex4AesNi — the XMM AES-NI fused kernels of the
//     same contract. The whitening k1 ⊕ k2 is the caller's.
//   - the fused ChainHash cascade kernels of areionasm_fused.go
//     (areion_fusedchain{256,512}_*.s) — the whole component cascade
//     per lane per call, reached through the hooks the hashes package
//     attaches.
//
// Also exported: the pre-broadcast round-constant tables `AreionRC4x`
// (P1) and `AreionRC4x2` (P2). AoS <-> SoA pack/unpack, runtime
// dispatch, and the Go-side hash closures live in the parent `itb`
// package.
package areionasm

import (
	"github.com/everanium/itb/third/goaes"

	"github.com/everanium/itb/internal/cpuid"
)

// AreionRC4x holds the 15 Areion round constants of P1 in pre-broadcast
// form (each 16-byte constant replicated four times to fill a 64-byte
// ZMM register). Layout: rc[r] occupies bytes [r*64 : (r+1)*64], with
// the 16-byte constant copied at offsets {0, 16, 32, 48} within each
// block.
//
// Initialised by `init()` from the canonical 16-byte constants in
// `Constants`. The assembly kernels reference this symbol as
// `·AreionRC4x(SB)`, or receive its address as the constant-table
// argument of the permutation kernels.
var AreionRC4x [15 * 64]byte

// AreionRC4x2 is the pre-broadcast form of the second round-constant
// table AreionRCTable2 (the P2 permutation of SoEM22), same layout as
// AreionRC4x. Referenced as `·AreionRC4x2(SB)`.
var AreionRC4x2 [15 * 64]byte

// Constants is the canonical 15-entry round constant table of P1 —
// digits of pi in little-endian byte order, equal to the vendored
// third/goaes areionRoundConstants and to AreionRCTable. Areion256 uses
// entries 0..9; Areion512 uses entries 0..14.
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
			copy(AreionRC4x2[r*64+copyIdx*16:r*64+copyIdx*16+16], AreionRCTable2[r][:])
		}
	}
}

// The assembly permutation kernels take the pre-broadcast constant
// table of the permutation to run: AreionRC4x for P1, AreionRC4x2 for
// P2. The exported wrappers below bind the table.

//go:noescape
func areion256Permutex4RC(x0, x1 *aes.Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4RC(x0, x1, x2, x3 *aes.Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4Avx2RC(x0, x1 *aes.Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4Avx2RC(x0, x1, x2, x3 *aes.Block4, rc *[15 * 64]byte)

//go:noescape
func areion256Permutex4AesNiRC(x0, x1 *aes.Block4, rc *[15 * 64]byte)

//go:noescape
func areion512Permutex4AesNiRC(x0, x1, x2, x3 *aes.Block4, rc *[15 * 64]byte)

// Areion256Permutex4 applies the 10-round Areion256 permutation P1 to
// four independent states packed in SoA layout: `*x0` holds the four
// lanes' first 16-byte AES blocks (Block4 = 64 bytes), `*x1` holds the
// second 16-byte blocks. Implemented in `areion_amd64.s` using AVX-512
// + VAES instructions on ZMM registers.
func Areion256Permutex4(x0, x1 *aes.Block4) { areion256Permutex4RC(x0, x1, &AreionRC4x) }

// Areion256Permute2x4 is Areion256Permutex4 under the second constant
// table: the P2 permutation of SoEM22.
func Areion256Permute2x4(x0, x1 *aes.Block4) { areion256Permutex4RC(x0, x1, &AreionRC4x2) }

// Areion512Permutex4 applies the 15-round Areion512 permutation P1 to
// four independent states packed in SoA layout: each `*xN` holds the
// four lanes' N-th 16-byte AES block (Block4 = 64 bytes). Includes the
// final cyclic state rotation `(x0,x1,x2,x3) → (x3,x0,x1,x2)`
// documented in the Areion paper / `areion512PermuteSoftware`.
// Implemented in `areion_amd64.s`.
func Areion512Permutex4(x0, x1, x2, x3 *aes.Block4) {
	areion512Permutex4RC(x0, x1, x2, x3, &AreionRC4x)
}

// Areion512Permute2x4 is Areion512Permutex4 under the second constant
// table: the P2 permutation of SoEM22.
func Areion512Permute2x4(x0, x1, x2, x3 *aes.Block4) {
	areion512Permutex4RC(x0, x1, x2, x3, &AreionRC4x2)
}

// Areion256Permutex4Avx2 is the AVX2 + VAES variant of
// Areion256Permutex4, written for x86-64 CPUs that have VAES but no
// AVX-512 (some Intel Alder Lake / Raptor Lake E-core configurations
// when isolated, certain AMD Zen 3 SKUs). Same SoA layout and bit-exact
// parity invariant as the AVX-512 path; the only difference is the
// internal VAESENC instructions operate on YMM registers (2 AES blocks
// per call) instead of ZMM (4 blocks per call), so each Areion round
// body runs twice — once for lanes 0-1 and once for lanes 2-3.
func Areion256Permutex4Avx2(x0, x1 *aes.Block4) { areion256Permutex4Avx2RC(x0, x1, &AreionRC4x) }

// Areion256Permute2x4Avx2 is Areion256Permutex4Avx2 under the second
// constant table (P2).
func Areion256Permute2x4Avx2(x0, x1 *aes.Block4) { areion256Permutex4Avx2RC(x0, x1, &AreionRC4x2) }

// Areion512Permutex4Avx2 is the AVX2 + VAES counterpart for the 512-bit
// permutation. Same constraints as Areion256Permutex4Avx2 — VAES on
// YMM, no AVX-512 required, 2 AES blocks per VAES instruction. Each
// of the 15 rounds runs twice (one body per lane pair), plus the final
// cyclic state rotation. Bit-exact parity invariant identical to the
// AVX-512 path.
func Areion512Permutex4Avx2(x0, x1, x2, x3 *aes.Block4) {
	areion512Permutex4Avx2RC(x0, x1, x2, x3, &AreionRC4x)
}

// Areion512Permute2x4Avx2 is Areion512Permutex4Avx2 under the second
// constant table (P2).
func Areion512Permute2x4Avx2(x0, x1, x2, x3 *aes.Block4) {
	areion512Permutex4Avx2RC(x0, x1, x2, x3, &AreionRC4x2)
}

// Areion256Permutex4AesNi is the legacy-SSE AES-NI XMM variant of
// Areion256Permutex4 for hosts without VAES: the four lanes run as four
// independent AESENC chains per round on XMM registers. Emitted by
// scripts/kernels/areion/gen_fused_kernels.py into
// areion_soem_aesni_amd64.s from the same round body as the AES-NI
// cascade kernels.
func Areion256Permutex4AesNi(x0, x1 *aes.Block4) { areion256Permutex4AesNiRC(x0, x1, &AreionRC4x) }

// Areion256Permute2x4AesNi is Areion256Permutex4AesNi under the second
// constant table (P2).
func Areion256Permute2x4AesNi(x0, x1 *aes.Block4) { areion256Permutex4AesNiRC(x0, x1, &AreionRC4x2) }

// Areion512Permutex4AesNi is the legacy-SSE AES-NI XMM counterpart for
// the 512-bit permutation: two lanes per pass, two passes, final cyclic
// rotation included.
func Areion512Permutex4AesNi(x0, x1, x2, x3 *aes.Block4) {
	areion512Permutex4AesNiRC(x0, x1, x2, x3, &AreionRC4x)
}

// Areion512Permute2x4AesNi is Areion512Permutex4AesNi under the second
// constant table (P2).
func Areion512Permute2x4AesNi(x0, x1, x2, x3 *aes.Block4) {
	areion512Permutex4AesNiRC(x0, x1, x2, x3, &AreionRC4x2)
}

// HasVAESAVX512 caches whether the runtime CPU supports VAES + AVX-512.
// Resolved once at init time from the upstream `aes` package's
// CPUID-driven detection. Both flags must be set for the AVX-512 path
// to be selected.
var HasVAESAVX512 = cpuid.VAESZMM

// HasVAESAVX2NoAVX512 is true for x86-64 CPUs that have VAES + AVX2 but
// lack AVX-512. The runtime dispatcher in the parent itb package picks
// this path when HasVAESAVX512 is false but VAES is still available, so
// the YMM assembly variants run instead of falling all the way back to
// the portable Go path.
var HasVAESAVX2NoAVX512 = cpuid.VAESYMM && !cpuid.AVX512F

// HasAESNIBatched is true for x86-64 CPUs with AES-NI but no VAES
// (Skylake / Cascade Lake, Zen 1 / Zen 2, and every older AES-NI
// host). The dispatcher then runs the batched SoEM through the XMM
// AES-NI fused kernels instead of the portable Go permutation. At most
// one of HasVAESAVX512 / HasVAESAVX2NoAVX512 / HasAESNIBatched is true.
var HasAESNIBatched = cpuid.AESNI && !cpuid.VAESYMM && !cpuid.VAESZMM

// HasARMAESBatched is always false on amd64 builds — this is the ARM
// Crypto Extension batched flag set by areionasm_arm64.go on arm64
// hosts. Declared here so the parent itb package's gates compile
// uniformly across architectures without per-arch build tag fences
// inside the gate expression.
var HasARMAESBatched = false
