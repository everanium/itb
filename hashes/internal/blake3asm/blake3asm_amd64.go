//go:build amd64 && !purego && !noitbasm

// Package blake3asm holds the AVX-512 + VL fused chain-absorb kernel
// implementation of BLAKE3 for the parent hashes/ package. The chain
// kernels are specialised at three input widths (20 / 36 / 68 bytes —
// covering the ITB SetNonceBits 128 / 256 / 512 buf shapes) and hold
// BLAKE3 state in ZMM registers across the absorb rounds, eliminating
// the per-round memory round-trip taken by the upstream BLAKE3 path.
//
// The 4-pixel-batched lane-parallel layout matches blake2{b,s}asm —
// 16 ZMMs hold v[0..15] across all rounds (lanes 0..3 active in dword
// positions 0..3), 16 more ZMMs hold m[0..15]. The round body uses
// VPADDD/VPXORD/VPRORD with the BLAKE3-specific 7-round message
// schedule. Below the AVX-512 + VL tier the parent package falls
// through to github.com/zeebo/blake3, which already carries its own
// hand-written AVX-512 assembly for the compression — so the realistic
// uplift target here is amortising per-call overhead across 4 lanes
// rather than competing with kernel-internal SIMD work.
//
// Reference layout: github.com/saucecontrol/Blake2Fast (MIT) —
// specifically src/Blake2Fast/Blake3/Blake3Scalar.g.cs for the round
// structure and message schedule, and Blake3HashState.cs for the
// flag set (CHUNK_START / CHUNK_END / ROOT / KEYED_HASH).
package blake3asm

import "golang.org/x/sys/cpu"

// HasAVX512Fused reports whether the runtime CPU supports the fused
// AVX-512 + VL chain-absorb kernels. Same derivation as
// blake2{b,s}asm — only AVX-512F is needed at the CPUID-bit level
// (VPRORD is AVX-512F + VL, but on every shipping silicon where
// AVX-512F is present the rest of the AVX-512 baseline ships with
// it).
var HasAVX512Fused = cpu.X86.HasAVX512F
