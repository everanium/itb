//go:build amd64 && !purego

// Package chacha20asm holds the AVX-512 + VL fused chain-absorb kernel
// implementation of ChaCha20 for the parent hashes/ package. The chain
// kernels are specialised at three input widths (20 / 36 / 68 bytes —
// covering the ITB SetNonceBits 128 / 256 / 512 buf shapes) and hold
// ChaCha20 state in ZMM registers across the absorb rounds, eliminating
// the per-round memory round-trip taken by the upstream
// golang.org/x/crypto/chacha20 path.
//
// The 4-pixel-batched lane-parallel layout matches blake2{b,s}asm /
// blake3asm — 16 ZMMs hold v[0..15] across all rounds (lanes 0..3
// active in dword positions 0..3), with additional ZMMs holding the
// v_init copy used at the keystream `+ v_init` add and the absorb
// state held across compression boundaries. The round body uses
// VPADDD / VPXORD / VPROLD with ChaCha20's left-rotation schedule
// (16, 12, 8, 7) — distinct from BLAKE2/3's right-rotation schedule.
//
// Below the AVX-512 + VL tier the parent package falls through to
// golang.org/x/crypto/chacha20, which already carries hand-written
// AVX-512 assembly for the keystream block. The 4-pixel-batched arm
// wins primarily through 4-lane parallelism — four independent
// ChaCha20 state evolutions advance through one ZMM dispatch
// instead of four serial scalar calls.
package chacha20asm

import "golang.org/x/sys/cpu"

// HasAVX512Fused reports whether the runtime CPU supports the fused
// AVX-512 + VL chain-absorb kernels. Same derivation as
// blake2{b,s}asm / blake3asm — only AVX-512F is needed at the CPUID
// level; on every shipping silicon where AVX-512F is present the
// rest of the AVX-512 baseline (VPROLD, VPBROADCASTD on EVEX form)
// ships with it.
var HasAVX512Fused = cpu.X86.HasAVX512F
