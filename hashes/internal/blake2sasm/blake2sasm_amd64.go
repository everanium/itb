//go:build amd64 && !purego && !noitbasm

// Package blake2sasm holds the AVX-512 + VL fused chain-absorb kernel
// implementation of BLAKE2s for the parent hashes/ package. The chain
// kernels are specialised at three input widths (20 / 36 / 68 bytes —
// covering the ITB SetNonceBits 128 / 256 / 512 buf shapes) and hold
// BLAKE2s state in ZMM registers across the absorb rounds, eliminating
// the per-round memory round-trip taken by the upstream
// `golang.org/x/crypto/blake2s` path.
//
// Below the AVX-512 + VL tier, the parent package's dispatch falls
// through to the existing `golang.org/x/crypto/blake2s` AVX2 / SSE2 /
// scalar paths. No AVX2 / SSE4 / SSSE3 ASM is provided here — the
// upstream library already covers those tiers, and the fused
// chain-absorb trick that motivates this package is AVX-512-only by
// construction (state-residency requires ZMM; VPRORD requires
// AVX-512 + VL).
//
// Reference layout: github.com/saucecontrol/Blake2Fast (MIT) —
// specifically src/Blake2Fast/Blake2s/Blake2sScalar.g.cs for the
// sigma table, IV constants, G rotates, and round structure. The
// AVX-512 round body is structured as a 4-pixel-batched lane-parallel
// design (no DIAG/UNDIAG permutations) rather than the upstream
// single-state Bernstein layout.
package blake2sasm

import "golang.org/x/sys/cpu"

// HasAVX512Fused reports whether the runtime CPU supports the fused
// AVX-512 + VL chain-absorb kernels. The kernels are pure ARX (no AES
// rounds), so the detection requirement is weaker than the Areion-SoEM
// flag in `internal/areionasm` — only AVX-512F is needed at the
// CPUID-bit level. VPRORD requires AVX-512F + VL, but on every
// shipping silicon where AVX-512F is present the rest of the AVX-512
// baseline (F + CD + BW + DQ + VL) ships with it (Intel Skylake-X+,
// AMD Zen 4+). The only chips with AVX-512F but no VL — Knights
// Landing / Knights Mill (Xeon Phi 2nd gen) — are extinct accelerator
// products that no Go runtime targets in practice.
var HasAVX512Fused = cpu.X86.HasAVX512F
