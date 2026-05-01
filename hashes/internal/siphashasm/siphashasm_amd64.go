//go:build amd64 && !purego

// Package siphashasm holds the AVX-512 + VL fused chain-absorb
// kernel implementation of SipHash-2-4-128 for the parent hashes/
// package. The chain kernels are specialised at three input widths
// (20 / 36 / 68 bytes — covering the ITB SetNonceBits 128 / 256 /
// 512 buf shapes) and hold the 4-word SipHash state in just four
// ZMM registers (Z0..Z3, qwords 0..3 active per ZMM = one qword
// per lane).
//
// The 4-pixel-batched lane-parallel layout differs from the
// BLAKE2/3 / ChaCha20 ports in shape: SipHash's state is only
// 4 × u64 words, not 16, so register pressure is far lower —
// most of the 32 ZMMs go unused. The win comes from running
// four independent SipHash-2-4 chains through the same
// VPADDQ / VPXORQ / VPROLQ instruction stream concurrently
// rather than serially. Per-call SipHash via dchest/siphash is
// already very cheap (no closure overhead, no key schedule, no
// Hasher state to clone) so the realistic uplift envelope is
// modest on Rocket Lake (1.5×–2.5×); the structural gain is
// larger on AMD Zen 5 / Sapphire Rapids+ where full-width
// 512-bit ALUs and absent AVX-512 frequency throttle let the
// 4-lane parallelism translate directly into wall-clock wins.
//
// Below the AVX-512 + VL tier the parent package falls through
// to dchest/siphash directly; there is no AVX-2 fallback tier
// (VPROLQ requires AVX-512F + VL anyway, and a YMM tier would
// halve per-instruction throughput while doubling the dependency
// chain count — the existing fast scalar path already wins
// against that).
package siphashasm

import "golang.org/x/sys/cpu"

// HasAVX512Fused reports whether the runtime CPU supports the
// fused AVX-512 + VL chain-absorb kernels. Same derivation as
// blake2{b,s}asm / blake3asm / chacha20asm — only AVX-512F is
// needed at the CPUID level (VPROLQ is AVX-512F + VL, but on
// every shipping silicon where AVX-512F is present the rest of
// the AVX-512 baseline ships with it).
var HasAVX512Fused = cpu.X86.HasAVX512F
