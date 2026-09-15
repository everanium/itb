//go:build arm64 && !purego && !noitbasm

// Package areionasm — arm64 build path. Provides 4-way batched Areion
// permute kernels in Plan9 AArch64 ASM, exploiting the ARM Crypto
// Extension (AESE / AESMC) for Neoverse / Cortex / Apple-class CPUs.
//
// The kernels mirror the bit-exact round structure of the portable Go
// reference (`areion{256,512}Permutex4Default` in the parent itb
// package) — verified by parity tests
// (`TestAreionSoEM{256,512}x4PureGoParityDirect`,
// `TestAreionSoEM512x4EdgeCases`, `TestAreionSoEM256x4LaneIndependence`).
//
// 4-way parallelism is the load-bearing optimisation: ARM AES extension
// dispatches AESE/AESMC at 1 instruction/cycle with 2-cycle latency on
// Neoverse V2, so 4 independent state chains hide latency completely.
// Each round body issues 16 AES instructions across 4 disjoint register
// chains, plus 4 VEOR for the round-constant XOR / temp combine.
//
// Layout convention — same SoA as the amd64 path: lane i's contribution
// to state position k lives at `bk[i*16 : i*16+16]`.
package areionasm

import "github.com/jedisct1/go-aes"

var (
	// AreionRC4x is unused on arm64 builds; declared for symbol
	// consistency with the amd64 build only. The arm64 ASM uses a
	// local rodata round-constant table inside `areion_arm64.s`.
	AreionRC4x [15 * 64]byte
	// HasVAESAVX512 is always false on arm64 builds.
	HasVAESAVX512 = false
	// HasVAESAVX2NoAVX512 is always false on arm64 builds.
	HasVAESAVX2NoAVX512 = false
	// HasARMAESBatched is true when the runtime ARM CPU exposes the
	// AES Crypto Extension. On hosts with this flag the parent itb
	// package's MakeAreionSoEM{256,512}Hash factories provide a
	// non-nil batched arm that routes through `Areion{256,512}Permutex4`,
	// running 4 independent ARM AES extension chains in one ASM block.
	HasARMAESBatched = aes.CPU.HasARMCrypto
)

// Areion256Permutex4 applies the 10-round Areion256 permutation to four
// independent states packed in SoA layout: `*x0` holds the four lanes'
// first 16-byte AES blocks (Block4 = 64 bytes), `*x1` holds the second
// 16-byte blocks. Implemented in `areion_arm64.s` using ARM Crypto
// Extension (AESE / AESMC) instructions on NEON registers.
//
//go:noescape
func Areion256Permutex4(x0, x1 *aes.Block4)

// Areion512Permutex4 applies the 15-round Areion512 permutation to four
// independent states packed in SoA layout: each `*xN` holds the four
// lanes' N-th 16-byte AES block (Block4 = 64 bytes). Includes the final
// cyclic state rotation `(x0,x1,x2,x3) → (x3,x0,x1,x2)` documented in
// the Areion paper / `areion512PermuteSoftware`. Implemented in
// `areion_arm64.s`.
//
//go:noescape
func Areion512Permutex4(x0, x1, x2, x3 *aes.Block4)

// The Avx2 entry points are amd64-only; on arm64 they remain unreachable
// panic stubs so the cross-platform import of this package resolves
// cleanly. The arm64 dispatcher in the parent itb package never reaches
// these symbols (it routes via `Areion{256,512}Permutex4` directly).

// Areion256Permutex4Avx2 is unavailable on arm64 builds.
func Areion256Permutex4Avx2(x0, x1 *aes.Block4) {
	panic("areionasm: Areion256Permutex4Avx2 unavailable on arm64 build")
}

// Areion512Permutex4Avx2 is unavailable on arm64 builds.
func Areion512Permutex4Avx2(x0, x1, x2, x3 *aes.Block4) {
	panic("areionasm: Areion512Permutex4Avx2 unavailable on arm64 build")
}
