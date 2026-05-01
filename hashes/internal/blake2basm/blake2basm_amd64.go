//go:build amd64 && !purego

// Package blake2basm holds the AVX-512 + VL fused chain-absorb kernel
// implementation of BLAKE2b for the parent hashes/ package. The chain
// kernels are specialised at three input widths (20 / 36 / 68 bytes —
// covering the ITB SetNonceBits 128 / 256 / 512 buf shapes) and hold
// BLAKE2b state in ZMM registers across the absorb rounds, eliminating
// the per-round memory round-trip taken by the upstream
// `golang.org/x/crypto/blake2b` path.
//
// One ASM kernel set covers both the 256-bit and 512-bit BLAKE2b
// factories in the parent hashes/ package. BLAKE2b's compression
// engine is identical for both digest widths — the digestLength
// parameter is XOR'd into h[0] of the parameter block at state init,
// and -256 truncates the 64-byte output to 32 bytes. Both adjustments
// happen in the calling Go closure, not in ASM.
//
// Below the AVX-512 + VL + VAES tier, the parent package's dispatch
// falls through to the existing `golang.org/x/crypto/blake2b` AVX2 /
// SSE2 / scalar paths. No AVX2 / SSE4 / SSSE3 ASM is provided here —
// the upstream library already covers those tiers, and the fused
// chain-absorb trick that motivates this package is AVX-512-only by
// construction (state-residency requires ZMM; VPRORQ requires
// AVX-512 + VL).
//
// Reference layout: github.com/saucecontrol/Blake2Fast (MIT) —
// specifically src/Blake2Fast/Blake2b/Blake2bAvx512.g.cs. Bernstein
// 4×YMM row layout with VPRORQ for all four ARX rotates per G
// function. Per-file attribution lives in the corresponding
// blake2b_chain_*_amd64.s headers when the kernels land.
package blake2basm

import "golang.org/x/sys/cpu"

// HasAVX512Fused reports whether the runtime CPU supports the fused
// AVX-512 + VL chain-absorb kernels. The kernels are pure ARX (no AES
// rounds), so the detection requirement is weaker than the Areion-SoEM
// flag in `internal/areionasm` — only AVX-512F is needed at the
// CPUID-bit level. VPRORQ requires AVX-512F + VL, but on every
// shipping silicon where AVX-512F is present the rest of the AVX-512
// baseline (F + CD + BW + DQ + VL) ships with it (Intel Skylake-X+,
// AMD Zen 4+). The only chips with AVX-512F but no VL — Knights
// Landing / Knights Mill (Xeon Phi 2nd gen) — are extinct accelerator
// products that no Go runtime targets in practice.
var HasAVX512Fused = cpu.X86.HasAVX512F
