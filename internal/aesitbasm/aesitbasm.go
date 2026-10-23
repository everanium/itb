// Package aesitbasm holds the assembly kernels of the AES-ITB-128
// primitive for the parent itb package: two families over the four
// fixed per-lane input lengths — 13 bytes (the Interlocked Barrier fill
// shape) and 20 / 36 / 68 bytes (the ITB 128 / 256 / 512-bit nonce buf
// shapes) — and, for package aesitb, the counter-driven noise filler of
// the "aesitb128" DRBG arm ([NoiseFill]; aesitb_noisefill_*.s,
// hand-written; see noisefill.go). The two cascade families:
//
//   - fused ChainHash cascade kernels, one or four lanes per call
//     ([FusedChain13x1] / [FusedChain13x4] and siblings;
//     aesitb_fusedchain128_*x1_*.s / *x4_*.s, emitted by
//     gen_fused_kernels.py): the whole component cascade of
//     itb.Seed128.ChainHash128 with the state kept in registers between
//     rounds — see aesitbasm_fused.go; on the ZMM tier the three
//     nonce-buf shapes also carry an eight-lane kernel
//     ([FusedChain20x8] / [FusedChain36x8] / [FusedChain68x8];
//     aesitb_fusedchain128_*x8_avx512_amd64.s) — see
//     aesitbasm_fused_x8.go;
//   - the batch-16 fused cascade kernel of the Interlocked Barrier fill
//     ([FusedChain13x16]; aesitb_fusedchain128_13x16_*.s, same generator):
//     sixteen lanes at the 13-byte shape with the fill blocks synthesised
//     in-register from a group index base.
//
// The four-lane dispatchers [AESITB128ChainAbsorb13x4] and siblings
// evaluate one chain absorption per lane through the pure-Go
// reference on every build.
//
// Each family runs the same chain absorption: CBC-MAC-style over public
// AES rounds, keyed through the initial state. Per lane, with key = the
// primitive's 16-byte fixed key and (seed0, seed1) the ChainHash128 seed
// pair of that lane:
//
//	state  = key XOR (LE64(seed0) || LE64(seed1))
//	padded = data || PKCS#7 padding to a 16-byte multiple (always >= 1 byte)
//	state  = AESENC(state XOR block_i, RC[i mod 8])   for each block i < b
//	state  = AESENC(state, RC[b mod 8]); state = AESENC(state, RC[(b+1) mod 8])
//	out    = (LE64(state[0:8]), LE64(state[8:16]))
//
// AESENC is one full AES round (SubBytes, ShiftRows, MixColumns,
// AddRoundKey with the round constant); b is the number of padded
// blocks, so the two finalising rounds continue the constant cycle.
// Block counts per shape: 13 → 1, 20 → 2, 36 → 3, 68 → 5; rounds per
// lane = blocks + 2; constants per lane RC[0 … b+1] — 13 → RC[0..2],
// 20 → RC[0..3], 36 → RC[0..4], 68 → RC[0..6].
//
// The construction is bit-exact with the single-lane closure the parent
// package builds around the same key (itb.MakeAESITB128Hash); the
// reference implementations in this package ([ChainAbsorb] for one
// round, [ScalarFusedChain] for the cascade) are pure Go over the
// software AES round, and every assembly tier of both families is pinned
// to them by the in-package parity tests. Kernels read exactly the
// per-lane input length — the tail block is assembled from 4-byte
// (20 / 36 / 68) or 8+4+1-byte (13) loads — because callers hand over
// buffers sized to the shape with no slack.
package aesitbasm

import (
	"encoding/binary"
	"runtime"
	"unsafe"
)

// RC holds the eight AES-ITB round constants, the first eight 128-bit
// words of the hexadecimal fractional expansion of π, each loaded
// big-endian into the AES state (most significant byte = state byte 0),
// which is also the in-register byte order the kernels read with a
// 16-byte load. The table is a copy of the parent package's constant
// set; the parent's parity test pins the two tables equal.
var RC = [8][16]byte{
	{0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44},
	{0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89},
	{0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C, 0x6C},
	{0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09, 0x17},
	{0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5, 0xAC},
	{0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E, 0x96},
	{0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C, 0xF7},
	{0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E, 0x69},
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
// Used by the 16-lane ASM kernels to initialize the state template; the
// kernels fold the per-message interlock-nonce word into bytes 9..12 of
// the template (or of each lane's index word) before the lanes are
// built, so the template itself carries zeros there.
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
// every kernel tier and the parent package's AES128Round-based closure are
// checked against it.
func ChainAbsorb(key *[16]byte, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	var q, b bsState
	var block [16]byte
	bsPackWords1(&q, binary.LittleEndian.Uint64(key[:8])^seed0, binary.LittleEndian.Uint64(key[8:])^seed1)

	n := len(data)
	full := n &^ 15
	numBlocks := full/16 + 1
	for blk := 0; blk < numBlocks; blk++ {
		paddedBlock(&block, nil, data, blk, full)
		bsPack1(&b, &block)
		for k := 0; k < 8; k++ {
			q[k] ^= b[k]
		}
		bsRound(&q, &bsRC[blk&7])
	}
	bsRound(&q, &bsRC[numBlocks&7])
	bsRound(&q, &bsRC[(numBlocks+1)&7])
	out0, out1 := bsUnpackWords1(&q)
	clear(block[:])
	clear(q[:])
	clear(b[:])
	runtime.KeepAlive(&block)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&b)
	return out0, out1
}

// scalarBatch evaluates the four lanes in parallel through the 4-lane
// bitsliced AES round. dataPtrs[i] must point at n readable bytes.
func scalarBatch(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, n int, out *[4][2]uint64) {
	var initBlocks, laneBlocks [4][16]byte
	var q, b bsState
	k0 := binary.LittleEndian.Uint64(key[:8])
	k1 := binary.LittleEndian.Uint64(key[8:])
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(initBlocks[lane][:8], k0^seeds[lane][0])
		binary.LittleEndian.PutUint64(initBlocks[lane][8:], k1^seeds[lane][1])
	}
	bsPack4(&q, &initBlocks[0], &initBlocks[1], &initBlocks[2], &initBlocks[3])

	full := n &^ 15
	numBlocks := full/16 + 1
	for blk := 0; blk < numBlocks; blk++ {
		for lane := 0; lane < 4; lane++ {
			paddedBlock(&laneBlocks[lane], nil, unsafe.Slice(dataPtrs[lane], n), blk, full)
		}
		bsPack4(&b, &laneBlocks[0], &laneBlocks[1], &laneBlocks[2], &laneBlocks[3])
		for k := 0; k < 8; k++ {
			q[k] ^= b[k]
		}
		bsRound(&q, &bsRC[blk&7])
	}
	bsRound(&q, &bsRC[numBlocks&7])
	bsRound(&q, &bsRC[(numBlocks+1)&7])
	bsUnpackWords4(&q, out)
	clear(initBlocks[:])
	clear(laneBlocks[:])
	clear(q[:])
	clear(b[:])
	runtime.KeepAlive(&initBlocks)
	runtime.KeepAlive(&laneBlocks)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&b)
}

// ChainAbsorbBatch evaluates four lanes of ChainAbsorb. When all four lanes
// share the same non-zero byte length, it runs the 4-lane bitsliced path in
// parallel; otherwise it evaluates each lane through ChainAbsorb.
func ChainAbsorbBatch(key *[16]byte, seeds *[4][2]uint64, data *[4][]byte, out *[4][2]uint64) {
	n := len(data[0])
	if n > 0 && len(data[1]) == n && len(data[2]) == n && len(data[3]) == n {
		dataPtrs := [4]*byte{&data[0][0], &data[1][0], &data[2][0], &data[3][0]}
		scalarBatch(key, seeds, &dataPtrs, n, out)
		return
	}
	for lane := 0; lane < 4; lane++ {
		out[lane][0], out[lane][1] = ChainAbsorb(key, data[lane], seeds[lane][0], seeds[lane][1])
	}
}
