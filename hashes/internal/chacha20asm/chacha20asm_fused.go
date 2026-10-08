// Package chacha20asm holds the fused ChainHash cascade kernels of
// ChaCha20 for the parent hashes package: the whole component cascade of
// a seed evaluated in one kernel call at the four per-pixel shapes (13 /
// 20 / 36 / 68 bytes) — four lanes on the AVX-512 EVEX XMM, AVX2 VEX XMM
// and NEON tiers, eight lanes on EVEX YMM registers at the nonce-buf
// shapes and for the batch-16 Interlocked Barrier fill hook, and one
// lane in general-purpose registers as the single-lane arm of every
// tier. Every cascade round rebuilds the eight key words from the fixed
// key, the component group and the previous output and runs the
// HChaCha20 chain over the slot blocks of the data: one ChaCha20
// permutation per block from the constants, the chaining key and the
// block, the eight output words becoming the key of the next block; the
// kernels are emitted by the generator
// (scripts/kernels/chacha20/gen_fused_kernels.py). Register layout: one
// register per state word, one dword lane per pixel, the quarter round
// never crossing lanes, VPROLD for the four ARX rotates on the EVEX
// tier.
package chacha20asm

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

// Fused cascade kernels evaluate the whole ChainHash256 cascade of the
// itb package over the ChaCha20 closure of the parent hashes package in
// one call:
//
//	h = 0
//	for each component group g (4 words):
//	    seed = g ^ h
//	    h = ChaCha20-PRF(fixedKey ⊕ seed, data)
//	out = h
//
// ChaCha20-PRF is the HChaCha20 chain of [HChaCha20Chain]: the per-round
// key is the 32-byte fixed key XOR the seed words, the data is encoded
// as 16-byte slot blocks of 15 data bytes and one tag byte, and every
// block runs one ChaCha20 permutation over [σ | key | block] whose
// output words 0..3 and 12..15 (no feed-forward — the HChaCha20
// convention) are the key of the next block; the last key is the
// 32-byte output. Every 64-bit seed and output word straddles two 32-bit
// key words, low half first. The block words are staged once per call;
// the key words are rebuilt each cascade round from the fixed key, the
// component group and the previous round's output, all of which stay in
// registers or the frame.
//
// x4 kernels run four lanes with distinct data over one shared component
// slice — the shape Seed256.BatchChainHash evaluates — and the x8 kernels
// eight (one dword lane per pixel: XMM at four lanes, YMM at eight); the
// single-lane entry points run the general-purpose-register kernels
// (chacha20_fusedchain256_<shape>x1_gpr_*.s), the single-lane arm of
// every tier. Shapes are the four per-pixel widths 13 / 20 / 36 / 68
// bytes. The generator is scripts/kernels/chacha20/gen_fused_kernels.py.

// Shapes are the per-pixel message lengths the kernels cover: the
// 13-byte Interlocked Barrier fill block and the 20 / 36 / 68-byte
// nonce-buf shapes.
var Shapes = [4]int{13, 20, 36, 68}

// SlotBytes is the number of data bytes one 16-byte slot block carries;
// the sixteenth byte is the tag.
const SlotBytes = 15

// SlotTagFinal is the tag bit of the final slot block; the low four bits
// of the final tag carry the number of data bytes in that block.
const SlotTagFinal = 0x80

// sigma is the "expand 32-byte k" constant of ChaCha20 (RFC 8439 § 2.3).
var sigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

// HChaCha20 runs the ChaCha20 permutation (RFC 8439 § 2.3, twenty rounds)
// over the state [σ | key | in] and returns words 0..3 and 12..15 of the
// permuted state without the feed-forward — the HChaCha20 function of
// the XChaCha20 construction, which is a PRF in the 128-bit input under
// the ChaCha20 block-function PRF assumption. key is the eight key words
// and in the four input words (the counter and nonce words of a ChaCha20
// block), both little-endian; the output words map to key words 0..7 of
// the next block in order.
func HChaCha20(key *[8]uint32, in *[4]uint32) [8]uint32 {
	x0, x1, x2, x3 := sigma[0], sigma[1], sigma[2], sigma[3]
	x4, x5, x6, x7 := key[0], key[1], key[2], key[3]
	x8, x9, x10, x11 := key[4], key[5], key[6], key[7]
	x12, x13, x14, x15 := in[0], in[1], in[2], in[3]
	for i := 0; i < 10; i++ {
		// Column round.
		x0 += x4
		x12 ^= x0
		x12 = bits.RotateLeft32(x12, 16)
		x8 += x12
		x4 ^= x8
		x4 = bits.RotateLeft32(x4, 12)
		x0 += x4
		x12 ^= x0
		x12 = bits.RotateLeft32(x12, 8)
		x8 += x12
		x4 ^= x8
		x4 = bits.RotateLeft32(x4, 7)

		x1 += x5
		x13 ^= x1
		x13 = bits.RotateLeft32(x13, 16)
		x9 += x13
		x5 ^= x9
		x5 = bits.RotateLeft32(x5, 12)
		x1 += x5
		x13 ^= x1
		x13 = bits.RotateLeft32(x13, 8)
		x9 += x13
		x5 ^= x9
		x5 = bits.RotateLeft32(x5, 7)

		x2 += x6
		x14 ^= x2
		x14 = bits.RotateLeft32(x14, 16)
		x10 += x14
		x6 ^= x10
		x6 = bits.RotateLeft32(x6, 12)
		x2 += x6
		x14 ^= x2
		x14 = bits.RotateLeft32(x14, 8)
		x10 += x14
		x6 ^= x10
		x6 = bits.RotateLeft32(x6, 7)

		x3 += x7
		x15 ^= x3
		x15 = bits.RotateLeft32(x15, 16)
		x11 += x15
		x7 ^= x11
		x7 = bits.RotateLeft32(x7, 12)
		x3 += x7
		x15 ^= x3
		x15 = bits.RotateLeft32(x15, 8)
		x11 += x15
		x7 ^= x11
		x7 = bits.RotateLeft32(x7, 7)

		// Diagonal round.
		x0 += x5
		x15 ^= x0
		x15 = bits.RotateLeft32(x15, 16)
		x10 += x15
		x5 ^= x10
		x5 = bits.RotateLeft32(x5, 12)
		x0 += x5
		x15 ^= x0
		x15 = bits.RotateLeft32(x15, 8)
		x10 += x15
		x5 ^= x10
		x5 = bits.RotateLeft32(x5, 7)

		x1 += x6
		x12 ^= x1
		x12 = bits.RotateLeft32(x12, 16)
		x11 += x12
		x6 ^= x11
		x6 = bits.RotateLeft32(x6, 12)
		x1 += x6
		x12 ^= x1
		x12 = bits.RotateLeft32(x12, 8)
		x11 += x12
		x6 ^= x11
		x6 = bits.RotateLeft32(x6, 7)

		x2 += x7
		x13 ^= x2
		x13 = bits.RotateLeft32(x13, 16)
		x8 += x13
		x7 ^= x8
		x7 = bits.RotateLeft32(x7, 12)
		x2 += x7
		x13 ^= x2
		x13 = bits.RotateLeft32(x13, 8)
		x8 += x13
		x7 ^= x8
		x7 = bits.RotateLeft32(x7, 7)

		x3 += x4
		x14 ^= x3
		x14 = bits.RotateLeft32(x14, 16)
		x9 += x14
		x4 ^= x9
		x4 = bits.RotateLeft32(x4, 12)
		x3 += x4
		x14 ^= x3
		x14 = bits.RotateLeft32(x14, 8)
		x9 += x14
		x4 ^= x9
		x4 = bits.RotateLeft32(x4, 7)
	}
	return [8]uint32{x0, x1, x2, x3, x12, x13, x14, x15}
}

// SlotBlocks is the number of 16-byte slot blocks the encoding of n data
// bytes occupies: fifteen data bytes per block, at least one block.
func SlotBlocks(n int) int {
	if n == 0 {
		return 1
	}
	return (n + SlotBytes - 1) / SlotBytes
}

// slotWords encodes slot block j of data as its four little-endian
// words: data[15j .. 15j+15) zero-padded, then the tag byte — 0x00 for
// a block that is not the last, [SlotTagFinal] | r for the last block
// carrying r data bytes.
func slotWords(data []byte, j, blocks int) [4]uint32 {
	var slot [16]byte
	off := j * SlotBytes
	r := copy(slot[:SlotBytes], data[off:])
	if j == blocks-1 {
		slot[15] = SlotTagFinal | byte(r)
	}
	return [4]uint32{
		binary.LittleEndian.Uint32(slot[0:]),
		binary.LittleEndian.Uint32(slot[4:]),
		binary.LittleEndian.Uint32(slot[8:]),
		binary.LittleEndian.Uint32(slot[12:]),
	}
}

// HChaCha20Chain is the ChaCha20 PRF of the parent hashes package over a
// 32-byte key: the HChaCha20 chain over the slot blocks of data. The key
// of block 0 is key; every block's output is the key of the next; the
// output is the last key as four little-endian 64-bit words.
func HChaCha20Chain(key *[32]byte, data []byte) [4]uint64 {
	var k [8]uint32
	for i := range k {
		k[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	blocks := SlotBlocks(len(data))
	for j := 0; j < blocks; j++ {
		in := slotWords(data, j, blocks)
		k = HChaCha20(&k, &in)
	}
	return [4]uint64{
		uint64(k[0]) | uint64(k[1])<<32,
		uint64(k[2]) | uint64(k[3])<<32,
		uint64(k[4]) | uint64(k[5])<<32,
		uint64(k[6]) | uint64(k[7])<<32,
	}
}

// absorb256 is the parent package's ChaCha20 PRF of one (key, seed,
// data) triple: the HChaCha20 chain under fixedKey XOR seed.
func absorb256(fixedKey *[32]byte, seed *[4]uint64, data []byte) [4]uint64 {
	var key [32]byte
	copy(key[:], fixedKey[:])
	for i := range seed {
		off := 8 * i
		binary.LittleEndian.PutUint64(key[off:], binary.LittleEndian.Uint64(key[off:])^seed[i])
	}
	return HChaCha20Chain(&key, data)
}

// ScalarFusedChain256 is the pure-Go reference cascade: one ChaCha20
// PRF evaluation per component group, the previous output folded into the
// group.
func ScalarFusedChain256(fixedKey *[32]byte, components []uint64, data []byte) [4]uint64 {
	var h, seed [4]uint64
	for g := 0; g+4 <= len(components); g += 4 {
		for i := range seed {
			seed[i] = components[g+i] ^ h[i]
		}
		h = absorb256(fixedKey, &seed, data)
	}
	return h
}

// validComponents256 reports whether the cascade can run: at least one
// group and a whole number of groups.
func validComponents256(components []uint64) bool {
	return len(components) >= 4 && len(components)%4 == 0
}

// fillBlock writes the 13-byte Interlocked Barrier fill block of one
// group: [0x03 | LE64(groupIdx) | 4×0x00].
func fillBlock(dst *[13]byte, groupIdx uint64) {
	dst[0] = 0x03
	binary.LittleEndian.PutUint64(dst[1:9], groupIdx)
	dst[9], dst[10], dst[11], dst[12] = 0, 0, 0, 0
}

// fillPtrs4 fills four consecutive blocks starting at groupIdxBase and
// returns their lane pointers, for the arms that run the fill as
// four-lane kernel calls over Go-synthesised blocks; the blocks stay on
// the caller's stack because the kernels are called directly.
func fillPtrs4(blocks *[4][13]byte, groupIdxBase uint64) [4]*byte {
	for i := range blocks {
		fillBlock(&blocks[i], groupIdxBase+uint64(i))
	}
	return [4]*byte{&blocks[0][0], &blocks[1][0], &blocks[2][0], &blocks[3][0]}
}

func scalarFused256X4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, n int, out *[4][4]uint64) {
	for lane := 0; lane < 4; lane++ {
		out[lane] = ScalarFusedChain256(fixedKey, components, lanePtr(dataPtrs[lane], n))
	}
}

func scalarFused256X8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, n int, out *[8][4]uint64) {
	for lane := 0; lane < 8; lane++ {
		out[lane] = ScalarFusedChain256(fixedKey, components, lanePtr(dataPtrs[lane], n))
	}
}

// scalarFill256X8 is the pure-Go reference of the batch-16 fill hook:
// lane i runs the cascade over the fill block of group groupIdxBase+i.
func scalarFill256X8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	var blk [13]byte
	for i := range out {
		fillBlock(&blk, groupIdxBase+uint64(i))
		out[i] = ScalarFusedChain256(fixedKey, components, blk[:])
	}
}

// lanePtr views n bytes at p as a slice for the pure-Go fallbacks.
func lanePtr(p *byte, n int) []byte { return unsafe.Slice(p, n) }

// Half views of the eight-lane argument arrays, for the arms that run
// a wide call as two narrower ones.
func ptrs8Half(p *[8]*byte, h int) *[4]*byte            { return (*[4]*byte)(p[4*h : 4*h+4]) }
func out8x256Half(o *[8][4]uint64, h int) *[4][4]uint64 { return (*[4][4]uint64)(o[4*h : 4*h+4]) }
