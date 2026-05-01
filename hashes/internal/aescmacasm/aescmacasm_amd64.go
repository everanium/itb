//go:build amd64 && !purego

// Package aescmacasm holds the AVX-512 + VAES fused chain-absorb
// kernel implementation of AES-CMAC for the parent hashes/ package.
// The chain kernels are specialised at three input widths
// (20 / 36 / 68 bytes — covering the ITB SetNonceBits 128 / 256 / 512
// buf shapes) and hold the AES-CMAC state in a single ZMM register
// (4 lanes × 16-byte AES blocks per ZMM) across the absorb rounds,
// eliminating the per-round memory round-trip taken by the upstream
// crypto/aes.cipher.Block.Encrypt path.
//
// VAESENC on ZMM operates on four independent AES blocks per
// instruction — a perfect match for ITB's 4-pixel-batched lane
// layout. The 11 AES-128 round keys are pre-expanded at Pair-factory
// time (ExpandKeyAES128 above) and broadcast to all 4 lanes via
// VBROADCASTI32X4 at function entry; per-pixel work then runs as
// state ⊕= K0; (9 × VAESENC); VAESENCLAST per AES round, with the
// CBC-MAC absorb XOR happening between rounds at the cost of one
// VPXORD on a stack-staged data block.
//
// Below the AVX-512 + VAES tier the parent package falls through to
// the existing AESCMACWithKey closure (which uses crypto/aes — itself
// AES-NI accelerated on amd64 hosts that expose the AES round
// instructions). The 4-pixel-batched arm wins primarily through
// 4-lane parallelism — four independent AES-CMAC chains advance
// through one VAESENC instruction per round instead of four serial
// cipher.Block.Encrypt interface dispatches — combined with
// collapsing Go's interface-method dispatch on cipher.Block.Encrypt
// across the lanes.
//
// VAES + AVX-2 (no AVX-512) hosts dispatch to the same scalar
// fallback rather than a YMM-tiered kernel: the AVX-2 fallback is
// only kept on Areion-SoEM (where VAES is the headline win and
// halved per-VAES throughput still beats serial scalar); for AES-CMAC
// the existing AES-NI scalar path is already fast enough that a
// dedicated YMM tier would add code mass for negligible uplift.
package aescmacasm

import "github.com/jedisct1/go-aes"

// HasVAESAVX512 reports whether the runtime CPU supports the fused
// AVX-512 + VAES chain-absorb kernels. Resolved once at init time
// from the upstream github.com/jedisct1/go-aes capability bits, the
// same source areionasm uses (see internal/areionasm/areionasm_amd64.go
// for the prior-art rationale on why this single bit covers every
// AVX-512 sub-feature the kernels touch — VAES requires AVX-512+VL
// on every shipping silicon where AVX-512F is present, and the only
// AVX-512F-without-VL chips, Knights Landing / Knights Mill, lack
// VAES entirely and are excluded by the HasVAES clause).
var HasVAESAVX512 = aes.CPU.HasVAES && aes.CPU.HasAVX512
