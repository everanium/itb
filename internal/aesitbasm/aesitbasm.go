// Package aesitbasm holds the assembly kernels of the AES-ITB-128
// primitive for the parent itb package, in three families over the four
// fixed per-lane input lengths — 13 bytes (the Interlocked Barrier fill
// shape) and 20 / 36 / 68 bytes (the ITB 128 / 256 / 512-bit nonce buf
// shapes):
//
//   - per-round chain-absorb kernels, four lanes per call
//     ([AESITB128ChainAbsorb13x4] and siblings; aesitb_chain128_*.s,
//     emitted by scripts/kernels/aesitb128/gen_kernels.py): one evaluation
//     of the sponge below per lane, the arm of the batched hash closure
//     the parent package builds around the primitive;
//   - fused ChainHash cascade kernels, one or four lanes per call
//     ([FusedChain13x1] / [FusedChain13x4] and siblings;
//     aesitb_fusedchain128_*x1_*.s / *x4_*.s, emitted by
//     gen_fused_kernels.py): the whole component cascade of
//     itb.Seed128.ChainHash128 with the state kept in registers between
//     rounds — see aesitbasm_fused.go;
//   - the batch-16 fused cascade kernel of the Interlocked Barrier fill
//     ([FusedChain13x16]; aesitb_fusedchain128_13x16_*.s, same generator):
//     sixteen lanes at the 13-byte shape with the fill blocks synthesised
//     in-register from a group index base.
//
// Each family runs the same sponge. Per lane, with key = the primitive's
// 16-byte fixed key and (seed0, seed1) the ChainHash128 seed pair of that
// lane:
//
//	state  = key XOR (LE64(seed0) || LE64(seed1))
//	padded = data || PKCS#7 padding to a 16-byte multiple (always >= 1 byte)
//	state  = AESENC(state XOR block_i, RC[i mod 8])   for each block i
//	state  = AESENC(state, RC[0]); state = AESENC(state, RC[1])
//	out    = (LE64(state[0:8]), LE64(state[8:16]))
//
// AESENC is one full AES round (SubBytes, ShiftRows, MixColumns,
// AddRoundKey with the round constant). Block counts per shape: 13 → 1,
// 20 → 2, 36 → 3, 68 → 5; rounds per lane = blocks + 2.
//
// The construction is bit-exact with the single-lane closure the parent
// package builds around the same key (itb.MakeAESITB128Hash); the
// reference implementations in this package ([ChainAbsorb] for one
// round, [ScalarFusedChain] for the cascade) are pure Go over the
// software AES round, and every assembly tier of every family is pinned
// to them by the in-package parity tests. Kernels read exactly the
// per-lane input length — the tail block is assembled from 4-byte
// (20 / 36 / 68) or 8+4+1-byte (13) loads — because callers hand over
// buffers sized to the shape with no slack.
package aesitbasm

import (
	"encoding/binary"
	"unsafe"

	aes "github.com/jedisct1/go-aes"
)

// RC holds the eight AES-ITB round constants, big-endian packings of
// FIPS 180-4 initial-hash-value words: RC[0..1] SHA-256 IV, RC[2..5]
// SHA-512 IV, RC[6..7] SHA-384 IV (first four words). The table is a copy
// of the parent package's constant set; the parent's parity test pins the
// two tables equal.
var RC = [8][16]byte{
	{0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A},
	{0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C, 0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19},
	{0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xBB, 0x67, 0xAE, 0x85, 0x84, 0xCA, 0xA7, 0x3B},
	{0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B, 0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1},
	{0x51, 0x0E, 0x52, 0x7F, 0xAD, 0xE6, 0x82, 0xD1, 0x9B, 0x05, 0x68, 0x8C, 0x2B, 0x3E, 0x6C, 0x1F},
	{0x1F, 0x83, 0xD9, 0xAB, 0xFB, 0x41, 0xBD, 0x6B, 0x5B, 0xE0, 0xCD, 0x19, 0x13, 0x7E, 0x21, 0x79},
	{0xCB, 0xBB, 0x9D, 0x5D, 0xC1, 0x05, 0x9E, 0xD8, 0x62, 0x9A, 0x29, 0x2A, 0x36, 0x7C, 0xD5, 0x07},
	{0x91, 0x59, 0x01, 0x5A, 0x30, 0x70, 0xDD, 0x17, 0x15, 0x2F, 0xEC, 0xD8, 0xF7, 0x0E, 0x59, 0x39},
}

// pad4Tail is the PKCS#7 tail block of a 4-byte remainder with the data
// bytes zeroed: the kernels insert the 4 live bytes at [0:4] and XOR the
// whole block into the state.
var pad4Tail = [16]byte{
	0, 0, 0, 0,
	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
}

// pad13Tail is the PKCS#7 tail block of a 13-byte remainder with the data
// bytes zeroed (3 pad bytes of 0x03 at [13:16]).
var pad13Tail = [16]byte{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0x03, 0x03, 0x03,
}

// absorb13Block is the initial absorption block for the 13-byte shape,
// including domain tag [0x03] at byte 0 and PKCS#7 padding at bytes 13–15.
// Used by the 16-lane ASM kernels to initialize the state template.
var absorb13Block = [16]byte{
	0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0x03, 0x03, 0x03,
}

// laneIdxZ holds per-group lane offsets for ZMM batch-16 groupIdx synthesis.
// Four groups, eight qwords per group; q1 entries are discarded by VPUNPCKLQDQ.
// Group j holds offsets [4j, 4j+1, 4j+2, 4j+3] packed as [q0, q1_unused, q0, q1_unused, ...].
var laneIdxZ = [4][8]uint64{
	{0, 0, 1, 0, 2, 0, 3, 0},
	{4, 0, 5, 0, 6, 0, 7, 0},
	{8, 0, 9, 0, 10, 0, 11, 0},
	{12, 0, 13, 0, 14, 0, 15, 0},
}

// ChainAbsorb is the pure-Go reference for one lane. It runs over the
// software AES round so the result does not depend on host AES hardware;
// every kernel tier and the parent package's RoundHW-based closure are
// checked against it.
func ChainAbsorb(key *[16]byte, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	var state [16]byte
	binary.LittleEndian.PutUint64(state[:8], binary.LittleEndian.Uint64(key[:8])^seed0)
	binary.LittleEndian.PutUint64(state[8:], binary.LittleEndian.Uint64(key[8:])^seed1)

	n := len(data)
	full := n &^ 15
	blk := 0
	for off := 0; off < full; off += 16 {
		for i := 0; i < 16; i++ {
			state[i] ^= data[off+i]
		}
		aes.Round((*aes.Block)(&state), (*aes.Block)(&RC[blk&7]))
		blk++
	}
	rem := n - full
	pad := byte(16 - rem)
	for i := 0; i < rem; i++ {
		state[i] ^= data[full+i]
	}
	for i := rem; i < 16; i++ {
		state[i] ^= pad
	}
	aes.Round((*aes.Block)(&state), (*aes.Block)(&RC[blk&7]))

	aes.Round((*aes.Block)(&state), (*aes.Block)(&RC[0]))
	aes.Round((*aes.Block)(&state), (*aes.Block)(&RC[1]))
	return binary.LittleEndian.Uint64(state[:8]), binary.LittleEndian.Uint64(state[8:])
}

// scalarBatch evaluates the four lanes through ChainAbsorb. dataPtrs[i]
// must point at n readable bytes.
func scalarBatch(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, n int, out *[4][2]uint64) {
	for lane := 0; lane < 4; lane++ {
		data := unsafe.Slice(dataPtrs[lane], n)
		out[lane][0], out[lane][1] = ChainAbsorb(key, data, seeds[lane][0], seeds[lane][1])
	}
}
