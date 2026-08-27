//go:build amd64 && !purego && !noitbasm

// Package chacha20asm holds the AVX-512 + VL fused chain-absorb kernel
// implementation of ChaCha20 for the parent hashes/ package. The chain
// kernels are specialised at four input widths (13 / 20 / 36 / 68
// bytes — the 13-byte Interlocked Barrier PRF fill shape plus the ITB
// 128 / 256 / 512-bit nonce buf shapes) and hold ChaCha20 state in XMM
// registers across the absorb rounds — the XMM active width for the
// 32-bit word state — eliminating the per-round memory round-trip
// taken by the upstream golang.org/x/crypto/chacha20 path.
//
// The 4-pixel-batched lane-parallel layout matches blake2sasm /
// blake3asm — 16 XMMs hold v[0..15] across all rounds (the 4 lane
// dwords fill each XMM exactly), with additional XMMs holding the
// v_init copy used at the keystream `+ v_init` add and the absorb
// state held across compression boundaries. The 68-byte kernel is the
// exception: its two compressions (counter=0 and counter=1) run
// together in one YMM-batched round body. The round body uses
// VPADDD / VPXORD / VPROLD with ChaCha20's left-rotation schedule
// (16, 12, 8, 7) — distinct from BLAKE2/3's right-rotation schedule.
//
// Below the AVX-512 + VL tier the parent package falls through to
// golang.org/x/crypto/chacha20, which already carries hand-written
// AVX-512 assembly for the keystream block. The 4-pixel-batched arm
// wins primarily through 4-lane parallelism — four independent
// ChaCha20 state evolutions advance through one vector instruction
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

// HasAVX2Fused reports whether the runtime CPU supports the AVX2 4-lane
// chain-absorb kernels but lacks the AVX-512 tier (which stays
// first-choice when present). On these hosts (every AVX2-only CPU:
// Sandy/Ivy/Haswell/Broadwell, Skylake-client, AMD Zen 1–3, and every
// AVX2-no-AVX-512 cloud VM) the ChaCha20 chain-absorb dispatch routes to
// the AVX2 kernels: 4 pixel lanes packed per XMM (single-block widths)
// or a dual-counter YMM fusion (68-byte width), with the immediate
// rotates synthesized via VPSHUFB byte-masks and VPSLLD/VPSRLD/VPOR.
// Gated off when AVX-512F is present so AVX-512 hosts keep their tier.
var HasAVX2Fused = cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F
