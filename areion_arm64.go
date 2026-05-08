//go:build arm64 && !purego && !noitbasm

package itb

import (
	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/areionasm"
)

// On arm64 with the ARM Crypto Extension, the 4-way batched permutex
// dispatches to a single Plan9 ASM block in `internal/areionasm/areion_arm64.s`,
// running 4 independent ARM Crypto Extension AES chains per call.
// Neoverse V2 dispatches AESE/AESMC at 1 instr/cycle with 2-cycle
// latency, so 4 disjoint state chains in one kernel hide latency
// completely — significantly better throughput than the Phase 1
// lane-by-lane (*aes.Areion).Permute() path that this file used
// before Phase 2.

// areion256Permutex4SoA runs the Areion256 permutation on each of the 4
// lanes carried interleaved across (b0, b1) — for lane i, b0[i*16:i*16+16]
// holds the first 16-byte AES block and b1[i*16:i*16+16] the second.
//
// On arm64 this dispatches to `areionasm.Areion256Permutex4` — a single
// Plan9 AArch64 ASM block running all 10 rounds across 4 independent
// ARM AES extension chains. Bit-exact with the portable scalar
// reference (verified by parity tests in areion_test.go).
func areion256Permutex4SoA(b0, b1 *aes.Block4) {
	areionasm.Areion256Permutex4(b0, b1)
}

// areion512Permutex4SoA runs the Areion512 permutation on each of the 4
// lanes carried interleaved across (b0, b1, b2, b3) — same layout as
// the 256-bit case, scaled to four 16-byte AES blocks per lane.
//
// On arm64 this dispatches to `areionasm.Areion512Permutex4` — a single
// Plan9 AArch64 ASM block running all 15 rounds (12 main + 3 final) and
// the spec final cyclic rotation across 4 independent ARM AES extension
// chains.
func areion512Permutex4SoA(b0, b1, b2, b3 *aes.Block4) {
	areionasm.Areion512Permutex4(b0, b1, b2, b3)
}

// areionSoEM256Permutex4SoA — fused per-half permute + SoEM XOR fold.
// Mirrors the SoA-fallback shape in areion_other.go: two separate
// per-half permutes through the new arm64 fast path, plus a manual
// 64-byte XOR loop. Bit-exact identical to the amd64 fused result.
func areionSoEM256Permutex4SoA(s1b0, s1b1, s2b0, s2b1 *aes.Block4) {
	areion256Permutex4SoA(s1b0, s1b1)
	areion256Permutex4SoA(s2b0, s2b1)
	for i := 0; i < 64; i++ {
		s1b0[i] ^= s2b0[i]
		s1b1[i] ^= s2b1[i]
	}
}

// areionSoEM512Permutex4SoA — fused per-half permute + SoEM XOR fold for
// the 512-bit width. Same shape as the SoEM-256 fallback, scaled to 4
// Block4 buffers per state.
func areionSoEM512Permutex4SoA(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4) {
	areion512Permutex4SoA(a1, b1, c1, d1)
	areion512Permutex4SoA(a2, b2, c2, d2)
	for i := 0; i < 64; i++ {
		a1[i] ^= a2[i]
		b1[i] ^= b2[i]
		c1[i] ^= c2[i]
		d1[i] ^= d2[i]
	}
}

// areionSoEM512ChainAbsorbHot — arm64 stub. The amd64 fast track
// uses ZMM 20/36/68 chain-absorb kernels which have no ARM analog;
// returning ok=false routes through the closure's general path.
func areionSoEM512ChainAbsorbHot(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	data *[4][]byte,
	commonLen int,
) (out [4][8]uint64, ok bool) {
	return out, false
}

// areionSoEM256ChainAbsorbHot — arm64 stub mirroring the 512-bit
// counterpart. Returns ok=false so the closure's general CBC-MAC chain
// path runs.
func areionSoEM256ChainAbsorbHot(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	data *[4][]byte,
	commonLen int,
) (out [4][4]uint64, ok bool) {
	return out, false
}
