//go:build amd64 && !purego

package areionasm

import "github.com/jedisct1/go-aes"

// Areion256SoEMPermutex4Interleaved runs the Areion-SoEM-256 4-way batched
// PRF in a single fused VAES kernel. Caller is responsible for
// preparing the SoEM half-states in SoA Block4 layout (lane i's two
// AES sub-blocks live at &Block4[i*16:i*16+16]):
//
//	s1b0, s1b1 = input ⊕ key1
//	s2b0, s2b1 = input ⊕ key2 ⊕ domainSep
//
// The kernel runs both 10-round Areion256 permutations interleaved (one
// VAESENC of each state per critical-path step, masking the 5-cycle
// VAESENC latency on Intel Sunny Cove / Cypress Cove and AMD Zen 4),
// then computes the SoEM output `state1' ⊕ state2'` in registers and
// writes the result back into (s1b0, s1b1). The (s2b0, s2b1) buffers
// are scratch and their contents after the call are unspecified.
//
// Compared with two back-to-back `Areion256Permutex4` calls plus a
// Go-side per-lane uint64 XOR loop, the fused path saves:
//   - 10 round-constant loads (RC pre-load runs once instead of twice)
//   - the function-call boundary between the two permutes
//   - the post-permute XOR + unpack loop in the AoS-side caller
//   - per-round dependency stalls (interleaved VAESENC pairs hide latency)
//
//go:noescape
func Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *aes.Block4)
