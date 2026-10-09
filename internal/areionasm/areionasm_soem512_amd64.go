//go:build amd64 && !purego && !noitbasm

package areionasm

import "github.com/everanium/itb/third/goaes"

// Areion512SoEMPermutex4Interleaved runs the two permutations of the
// Areion-SoEM-512 4-way batched PRF in a single fused VAES kernel. Caller
// is responsible for the SoEM input setup (in SoA Block4 layout):
//
//	(a1, b1, c1, d1) = input ⊕ key1
//	(a2, b2, c2, d2) = input ⊕ key2
//
// Each Block4 is 64 bytes and holds the same 16-byte AES sub-block
// across the 4 lanes (Areion-SoEM-512's state is 64 bytes = 4 AES blocks
// per lane, hence 4 Block4 buffers per state).
//
// The kernel runs P1 on state1 and P2 on state2 (the 15-round Areion512
// permutation under the first and the second round-constant table)
// interleaved — one VAESENC of each state per critical-path step,
// masking the 5-cycle VAESENC latency on Intel Sunny Cove / Cypress
// Cove and AMD Zen 4 — applies the cyclic state rotation `(x0,x1,x2,x3)
// → (x3,x0,x1,x2)` fused with the output XOR `P1(state1) ⊕
// P2(state2)`, and writes the result to (a1, b1, c1, d1). The (a2, b2,
// c2, d2) buffers are left intact. The SoEM22 whitening `⊕ key1 ⊕ key2`
// is applied by the caller.
//
// Compared with two back-to-back permutation calls plus a Go-side
// per-Block4 XOR loop, the fused path saves:
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

// Areion512SoEMPermutex4AesNi is the legacy-SSE AES-NI XMM form of
// Areion512SoEMPermutex4Interleaved for hosts without VAES: one lane per
// pass, the P1 and P2 chains of the lane interleaved per round, the final
// rotation folded into the writeback. Same contract (result into the
// state1 buffers, state2 buffers intact, whitening by the caller).
// Emitted by scripts/kernels/areion/gen_fused_kernels.py into
// areion_soem_aesni_amd64.s.
//
//go:noescape
func Areion512SoEMPermutex4AesNi(a1, b1, c1, d1, a2, b2, c2, d2 *aes.Block4)
