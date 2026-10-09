//go:build arm64 && !purego && !noitbasm

package itb

import (
	"github.com/everanium/itb/third/goaes"

	"github.com/everanium/itb/internal/areionasm"
)

// On arm64 with the ARM Crypto Extension, the 4-way batched permutex
// dispatches to a single Plan9 ASM block in `internal/areionasm/areion_arm64.s`,
// running 4 independent ARM Crypto Extension AES chains per call.
// Neoverse V2 dispatches AESE/AESMC at 1 instr/cycle with 2-cycle
// latency, so 4 disjoint state chains in one kernel hide latency
// completely — significantly better throughput than a lane-by-lane
// (*aes.Areion).Permute() path.

// areion256Permutex4SoA runs the Areion256 permutation — P1 under
// areionRC, or P2 under areionRC2 when second is set — on each of the 4
// lanes carried interleaved across (b0, b1) — for lane i,
// b0[i*16:i*16+16] holds the first 16-byte AES block and
// b1[i*16:i*16+16] the second.
//
// On arm64 with the ARM Crypto Extension ([areionasm.HasARMAESBatched])
// this dispatches to `areionasm.Areion256Permutex4` /
// `areionasm.Areion256Permute2x4` — a single Plan9 AArch64 ASM block
// running all 10 rounds across 4 independent ARM AES extension chains.
// Bit-exact with the portable scalar reference (verified by parity
// tests in areion_test.go). Without the extension, or under
// ITB_FORCE_HASH_TIER=scalar, the portable Go permutation runs.
func areion256Permutex4SoA(b0, b1 *aes.Block4, second bool) {
	if areionasm.HasARMAESBatched {
		if second {
			areionasm.Areion256Permute2x4(b0, b1)
		} else {
			areionasm.Areion256Permutex4(b0, b1)
		}
		return
	}
	rcs := &areionRC
	if second {
		rcs = &areionRC2
	}
	var states [4][32]byte
	unpack256x4SoA(b0, b1, &states)
	areion256Permutex4Default(&states, rcs)
	*b0, *b1 = pack256x4SoA(&states)
}

// areion512Permutex4SoA runs the Areion512 permutation (P1, or P2 when
// second is set) on each of the 4 lanes carried interleaved across
// (b0, b1, b2, b3) — same layout as the 256-bit case, scaled to four
// 16-byte AES blocks per lane.
//
// On arm64 this dispatches to `areionasm.Areion512Permutex4` /
// `areionasm.Areion512Permute2x4` — a single Plan9 AArch64 ASM block
// running all 15 rounds (12 main + 3 final) and the spec final cyclic
// rotation across 4 independent ARM AES extension chains, under the
// same [areionasm.HasARMAESBatched] gate and portable fallback as the
// 256-bit case.
func areion512Permutex4SoA(b0, b1, b2, b3 *aes.Block4, second bool) {
	if areionasm.HasARMAESBatched {
		if second {
			areionasm.Areion512Permute2x4(b0, b1, b2, b3)
		} else {
			areionasm.Areion512Permutex4(b0, b1, b2, b3)
		}
		return
	}
	rcs := &areionRC
	if second {
		rcs = &areionRC2
	}
	var states [4][64]byte
	unpack512x4SoA(b0, b1, b2, b3, &states)
	areion512Permutex4Default(&states, rcs)
	*b0, *b1, *b2, *b3 = pack512x4SoA(&states)
}

// areionSoEM256Permutex4SoA — P1 on state1, P2 on state2, XOR fold.
// Mirrors the SoA-fallback shape in areion_other.go: two separate
// per-half permutes through the arm64 fast path, plus a manual 64-byte
// XOR loop. Bit-exact identical to the amd64 fused result; the SoEM22
// whitening is the caller's.
func areionSoEM256Permutex4SoA(s1b0, s1b1, s2b0, s2b1 *aes.Block4) {
	areion256Permutex4SoA(s1b0, s1b1, false)
	areion256Permutex4SoA(s2b0, s2b1, true)
	for i := 0; i < 64; i++ {
		s1b0[i] ^= s2b0[i]
		s1b1[i] ^= s2b1[i]
	}
}

// areionSoEM512Permutex4SoA — P1 on state1, P2 on state2, XOR fold for
// the 512-bit width. Same shape as the SoEM-256 fallback, scaled to 4
// Block4 buffers per state.
func areionSoEM512Permutex4SoA(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4) {
	areion512Permutex4SoA(a1, b1, c1, d1, false)
	areion512Permutex4SoA(a2, b2, c2, d2, true)
	for i := 0; i < 64; i++ {
		a1[i] ^= a2[i]
		b1[i] ^= b2[i]
		c1[i] ^= c2[i]
		d1[i] ^= d2[i]
	}
}
