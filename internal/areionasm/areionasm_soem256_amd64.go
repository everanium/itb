//go:build amd64 && !purego && !noitbasm

package areionasm

import "github.com/everanium/itb/third/goaes"

// Areion256SoEMPermutex4Interleaved runs the two permutations of the
// Areion-SoEM-256 4-way batched PRF in a single fused VAES kernel.
// Caller is responsible for preparing the SoEM half-states in SoA Block4
// layout (lane i's two AES sub-blocks live at &Block4[i*16:i*16+16]):
//
//	s1b0, s1b1 = input ⊕ key1
//	s2b0, s2b1 = input ⊕ key2
//
// The kernel runs P1 on state1 and P2 on state2 (the 10-round Areion256
// permutation under the first and the second round-constant table)
// interleaved — one VAESENC of each state per critical-path step,
// masking the 5-cycle VAESENC latency on Intel Sunny Cove / Cypress
// Cove and AMD Zen 4 — then computes `P1(state1) ⊕ P2(state2)` in
// registers and writes the result back into (s1b0, s1b1). The (s2b0,
// s2b1) buffers are left intact. The SoEM22 whitening `⊕ key1 ⊕ key2`
// is applied by the caller.
//
// Compared with two back-to-back permutation calls plus a Go-side
// per-lane uint64 XOR loop, the fused path saves:
//   - the function-call boundary between the two permutes
//   - the post-permute XOR + unpack loop in the AoS-side caller
//   - per-round dependency stalls (interleaved VAESENC pairs hide latency)
//
//go:noescape
func Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1 *aes.Block4)

// Areion256SoEMPermutex4AesNi is the legacy-SSE AES-NI XMM form of
// Areion256SoEMPermutex4Interleaved for hosts without VAES: two lanes per
// pass, the P1 and P2 chains of both lanes interleaved per round. Same
// contract (result into the s1 buffers, s2 buffers intact, whitening by
// the caller). Emitted by scripts/kernels/areion/gen_fused_kernels.py
// into areion_soem_aesni_amd64.s.
//
//go:noescape
func Areion256SoEMPermutex4AesNi(s1b0, s1b1, s2b0, s2b1 *aes.Block4)
