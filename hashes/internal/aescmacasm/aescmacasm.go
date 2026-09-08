// Package aescmacasm holds the assembly kernels of the AES-CMAC primitive
// (hashes.AESCMAC) over the four fixed per-lane input lengths — 13 bytes
// (the Interlocked Barrier fill shape) and 20 / 36 / 68 bytes (the ITB
// 128 / 256 / 512-bit nonce buf shapes):
//
//   - fused ChainHash cascade kernels, one or four lanes per call
//     ([FusedChain13x1] / [FusedChain13x4] and siblings;
//     aescmac_fusedchain128_*x1_*.s / *x4_*.s, emitted by
//     scripts/kernels/aescmac/gen_fused_kernels.py): the whole component
//     cascade of itb.Seed128.ChainHash128 with the state kept in
//     registers between rounds — see aescmacasm_fused.go; on the ZMM tier
//     the three nonce-buf shapes also carry an eight-lane kernel
//     ([FusedChain20x8] / [FusedChain36x8] / [FusedChain68x8];
//     aescmac_fusedchain128_*x8_avx512_amd64.s) — see
//     aescmacasm_fused_x8.go;
//   - the batch-16 fused cascade kernel of the Interlocked Barrier fill
//     ([FusedChain13x16]; aescmac_fusedchain128_13x16_*.s, same generator):
//     sixteen lanes at the 13-byte shape with the fill blocks synthesised
//     in-register from a group index base.
//
// Each family runs the same construction. Per lane, with K the 16-byte
// AES-128 key of the primitive and (seed0, seed1) the ChainHash128 seed
// pair of that lane:
//
//	state  = LE64(seed0 XOR len) || LE64(seed1 XOR len)
//	state  = AES_K(state XOR block_0)
//	state  = AES_K(state XOR block_i)          for each further block i
//	out    = (LE64(state[0:8]), LE64(state[8:16]))
//
// where block_i is data[16i : 16i+16] zero-padded to 16 bytes (no
// padding block is appended) and AES_K is the full AES-128 permutation
// under the schedule K0..K10 of [ExpandKeyAES128]. Block counts per
// shape: 13 → 1, 20 → 2, 36 → 3, 68 → 5; AES-128 permutations per lane =
// blocks. The construction is bit-exact with the closure the parent
// package builds around the same key (hashes.AESCMACWithKey); the
// reference implementations in this package ([ChainAbsorb] for one
// round, [ScalarFusedChain] for the cascade) run over crypto/aes, and
// every assembly tier of every family is pinned to them by the
// in-package parity tests. Kernels read exactly the per-lane input
// length — the tail block is assembled from 4-byte (20 / 36 / 68) or
// 8+4+1-byte (13) loads — because callers hand over buffers sized to the
// shape with no slack.
package aescmacasm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// Schedule carries one AES-128 key in the two forms the package
// consumes: the 176-byte forward round-key schedule the kernels read
// (see [ExpandKeyAES128]) and the crypto/aes block the pure-Go reference
// runs. A Schedule is built once per key ([NewSchedule]) and shared by
// every call, so neither path allocates per invocation; it carries no
// per-call state and may be used concurrently.
type Schedule struct {
	roundKeys [176]byte
	block     cipher.Block
}

// NewSchedule expands key into a [Schedule].
func NewSchedule(key [16]byte) *Schedule {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return &Schedule{roundKeys: ExpandKeyAES128(key), block: block}
}

// absorb13Block is the 13-byte fill block of group index 0 zero-padded
// to 16 bytes: the domain tag 0x03 at byte 0, the LE64 group index at
// bytes 1..8 (zero here) and zero bytes at 9..15. The batch-16 kernels
// XOR the in-register group index into it to form every lane's block.
var absorb13Block = [16]byte{0x03}

// laneIdxZ holds per-group lane offsets for ZMM batch-16 groupIdx
// synthesis. Four groups, eight qwords per group; q1 entries are
// discarded by VPUNPCKLQDQ. Group j holds offsets [4j, 4j+1, 4j+2, 4j+3]
// packed as [q0, q1_unused, q0, q1_unused, ...].
var laneIdxZ = [4][8]uint64{
	{0, 0, 1, 0, 2, 0, 3, 0},
	{4, 0, 5, 0, 6, 0, 7, 0},
	{8, 0, 9, 0, 10, 0, 11, 0},
	{12, 0, 13, 0, 14, 0, 15, 0},
}

// ChainAbsorb is the pure-Go reference for one lane and one seed pair —
// the closure body of hashes.AESCMACWithKey over the schedule's
// crypto/aes block. Every kernel tier is checked against it.
func ChainAbsorb(s *Schedule, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	lenTag := uint64(len(data))
	var state [16]byte
	binary.LittleEndian.PutUint64(state[0:], seed0^lenTag)
	binary.LittleEndian.PutUint64(state[8:], seed1^lenTag)
	first := len(data)
	if first > 16 {
		first = 16
	}
	for i := 0; i < first; i++ {
		state[i] ^= data[i]
	}
	s.block.Encrypt(state[:], state[:])
	for off := 16; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		for i := 0; i < end-off; i++ {
			state[i] ^= data[off+i]
		}
		s.block.Encrypt(state[:], state[:])
	}
	return binary.LittleEndian.Uint64(state[:8]), binary.LittleEndian.Uint64(state[8:])
}
