// Package siphashasm holds the assembly kernels of the SipHash-2-4
// primitive (hashes.SipHash24) over the four fixed per-lane input
// lengths — 13 bytes (the Interlocked Barrier fill shape) and 20 / 36 /
// 68 bytes (the ITB 128 / 256 / 512-bit nonce buf shapes):
//
//   - fused ChainHash cascade kernels, one or four lanes per call
//     ([FusedChain13x1] / [FusedChain13x4] and siblings;
//     siphash_fusedchain128_*x1_*.s / *x4_*.s, emitted by
//     scripts/kernels/siphash/gen_fused_kernels.py): the whole component
//     cascade of itb.Seed128.ChainHash128 with the state kept in
//     registers between rounds — see siphashasm_fused.go; on the AVX-512
//     tier the three nonce-buf shapes also carry an eight-lane ZMM kernel
//     ([FusedChain20x8] / [FusedChain36x8] / [FusedChain68x8];
//     siphash_fusedchain128_*x8_avx512_amd64.s) — see
//     siphashasm_fused_x8.go;
//   - the batch-16 fused cascade of the Interlocked Barrier fill
//     ([FusedChain13x16]): sixteen lanes at the 13-byte shape with the
//     fill blocks synthesised from a group index base — one ZMM kernel
//     on the AVX-512 tier (siphash_fusedchain128_13x16_avx512_amd64.s),
//     two calls of an eight-lane kernel on the AVX2 and NEON tiers
//     (siphash_fusedchain128_13x8_{avx2_amd64,neon_arm64}.s).
//
// Every family runs SipHash-2-4 in its 128-bit-output form
// (Aumasson & Bernstein 2012 §2.4, as implemented by
// github.com/dchest/siphash Hash128) keyed per lane and per cascade round
// by the ChainHash128 seed pair (seed0, seed1) — SipHash has no fixed
// key, so the seed pair is the entire key and the primitive's factories
// take none. The reference implementations in this package ([ChainAbsorb]
// for one round, [ScalarFusedChain] for the cascade) run over
// dchest/siphash, and every assembly tier of every family is pinned to
// them by the in-package parity tests. Kernels read exactly the per-lane
// input length.
//
// Tier selection is runtime-gated on the amd64 CPUID flags (AVX-512F for
// the EVEX kernels, AVX2 for the VEX kernels; the single-lane GPR kernel
// runs under either) and on arm64 NEON is the baseline; ITB_FORCE_HASH_TIER
// and ITB_FORCE_INTERLOCK_PRF_FILL_TIER re-select an arm at init (see
// forcetier_amd64.go / forcetier_arm64.go). The -tags noitbasm build
// disables every kernel and routes through the Go reference.
package siphashasm

import "github.com/dchest/siphash"

// ChainAbsorb is the pure-Go reference of one SipHash-2-4-128 round of
// the ChainHash128 cascade: the digest of data under the key (seed0,
// seed1), exactly the closure hashes.SipHash24 returns.
func ChainAbsorb(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

// laneIdx16 holds the lane offsets 0..15 the batch-16 ZMM kernel adds to
// groupIdxBase: qwords 0..7 for the first eight-lane group, 8..15 for the
// second.
var laneIdx16 = [16]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// interleaveIdx16 holds the two VPERMT2Q index rows that interleave a
// register of eight lo words (table 1, indices 0..7) with a register of
// eight hi words (table 2, indices 8..15) into (lo, hi) pairs in lane
// order: the first row yields lanes 0..3, the second lanes 4..7.
var interleaveIdx16 = [16]uint64{0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15}
