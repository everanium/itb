//go:build amd64 && !purego

package areionasm

import "github.com/jedisct1/go-aes"

// Areion512SoEMPermutex4Interleaved runs the Areion-SoEM-512 4-way batched
// PRF in a single fused VAES kernel. Caller is responsible for the SoEM
// input setup (in SoA Block4 layout):
//
//	(a1, b1, c1, d1) = input ⊕ key1
//	(a2, b2, c2, d2) = input ⊕ key2 ⊕ domainSep
//
// Each Block4 is 64 bytes and holds the same 16-byte AES sub-block
// across the 4 lanes (Areion-SoEM-512's state is 64 bytes = 4 AES blocks
// per lane, hence 4 Block4 buffers per state).
//
// The kernel runs both 15-round Areion512 permutations interleaved (one
// VAESENC of each state per critical-path step, masking the 5-cycle
// VAESENC latency on Intel Sunny Cove / Cypress Cove and AMD Zen 4),
// applies the cyclic state rotation `(x0,x1,x2,x3) → (x3,x0,x1,x2)`
// fused with the SoEM output XOR `state1' ⊕ state2'`, and writes the
// result to (a1, b1, c1, d1). The (a2, b2, c2, d2) buffers are scratch
// and their contents after the call are unspecified.
//
// Compared with two back-to-back `Areion512Permutex4` calls plus a
// Go-side per-Block4 XOR loop, the fused path saves:
//   - 15 round-constant loads (RC pre-load runs once instead of twice)
//   - the function-call boundary between the two permutes
//   - the post-permute XOR + unpack work in the AoS-side caller
//   - per-round VAESENC dependency stalls (interleaved chains hide
//     the 5-cycle latency)
//   - 8 VMOVDQA64 final-rotation moves (rotation is folded into the
//     SoEM XOR pattern by routing register contents directly to the
//     correct output slots)
//
//go:noescape
func Areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4)
