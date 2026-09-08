package areionasm

import (
	"encoding/binary"
	"unsafe"

	"github.com/jedisct1/go-aes"
)

// areionasm_fused.go — the fused ChainHash cascade of Areion-SoEM-256 /
// -512 and its pure-Go reference.
//
// The cascade is Seed256.ChainHash256 / Seed512.ChainHash512 over the
// root package's Areion-SoEM chain-absorb closures: per component group
// (four words at width 256, eight at width 512) the SoEM key is the
// fixed key ‖ (group XOR previous round's output), the length-tagged
// message is absorbed in 24- / 56-byte chunks through the SoEM PRF, and
// the last chunk's output is the round's result. The kernels
// (areion_fusedchain{256,512}_<shape>x{4,1}_<tier>_*.s, emitted by
// scripts/kernels/areion/gen_fused_kernels.py) evaluate the whole cascade
// per lane in one call; [ScalarFusedChain256] / [ScalarFusedChain512]
// evaluate it in Go over aes.AreionSoEM256 / aes.AreionSoEM512 and are
// the parity oracle of every kernel and the fallback of every
// dispatcher on hosts or tiers without a kernel.
//
// The dispatchers accept the four per-pixel shapes 13 / 20 / 36 / 68 and
// any component slice of at least one full group; the callers in the
// hashes package guard both. Every arm is bit-exact with the reference.

// AreionRCTable holds the fifteen Areion round constants (the first ten
// are the Areion-256 constants). The amd64 kernels read them through the
// four-lane broadcast table AreionRC4x; the arm64 kernels read this table
// directly.
var AreionRCTable = [15][16]byte{
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
	{0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
	{0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
	{0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
	{0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
	{0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57},
}

// Shapes are the per-pixel message lengths the kernels cover: the
// 13-byte Interlocked Barrier fill block and the 20 / 36 / 68-byte
// nonce-buf shapes.
var Shapes = [4]int{13, 20, 36, 68}

func absorbXOR(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}

// soem256Absorb is the root package's Areion-SoEM-256 chain absorb of
// one (key, data) pair: the 8-byte length tag, data absorbed in 24-byte
// chunks, one SoEM evaluation per chunk.
func soem256Absorb(key *[64]byte, data []byte) [4]uint64 {
	const chunkSize = 24
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		state = aes.AreionSoEM256(key, &state)
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		state = aes.AreionSoEM256(key, &state)
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			absorbXOR(state[8:8+(end-off)], data[off:end])
			state = aes.AreionSoEM256(key, &state)
			off = end
		}
	}
	var out [4]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(state[8*i:])
	}
	return out
}

// soem512Absorb is the width-512 form of [soem256Absorb]: 56-byte chunks
// over a 64-byte state.
func soem512Absorb(key *[128]byte, data []byte) [8]uint64 {
	const chunkSize = 56
	var state [64]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		state = aes.AreionSoEM512(key, &state)
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		state = aes.AreionSoEM512(key, &state)
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			absorbXOR(state[8:8+(end-off)], data[off:end])
			state = aes.AreionSoEM512(key, &state)
			off = end
		}
	}
	var out [8]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(state[8*i:])
	}
	return out
}

// ScalarFusedChain256 is the pure-Go reference of the width-256 cascade:
// Seed256.ChainHash256 over the Areion-SoEM-256 closure keyed by fixedKey,
// with components as the seed's component slice (a multiple of four
// words, at least four). Bit-exact with the root package's single arm
// run through the sequential cascade.
func ScalarFusedChain256(fixedKey *[32]byte, components []uint64, data []byte) [4]uint64 {
	var h [4]uint64
	var key [64]byte
	copy(key[:32], fixedKey[:])
	for g := 0; g+4 <= len(components); g += 4 {
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(key[32+8*i:], components[g+i]^h[i])
		}
		h = soem256Absorb(&key, data)
	}
	return h
}

// ScalarFusedChain512 is the width-512 form of [ScalarFusedChain256]
// (eight words per group).
func ScalarFusedChain512(fixedKey *[64]byte, components []uint64, data []byte) [8]uint64 {
	var h [8]uint64
	var key [128]byte
	copy(key[:64], fixedKey[:])
	for g := 0; g+8 <= len(components); g += 8 {
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(key[64+8*i:], components[g+i]^h[i])
		}
		h = soem512Absorb(&key, data)
	}
	return h
}

// validComponents256 / validComponents512 report whether the cascade can
// run: at least one full group and a whole number of groups.
func validComponents256(components []uint64) bool {
	return len(components) >= 4 && len(components)%4 == 0
}

func validComponents512(components []uint64) bool {
	return len(components) >= 8 && len(components)%8 == 0
}

// fillBlock writes the 13-byte Interlocked Barrier fill block
// [0x03 | LE64(groupIdx) | 4×0x00] of one group.
func fillBlock(dst *[13]byte, groupIdx uint64) {
	dst[0] = 0x03
	binary.LittleEndian.PutUint64(dst[1:9], groupIdx)
	dst[9], dst[10], dst[11], dst[12] = 0, 0, 0, 0
}

// fillPtrs4 fills four consecutive blocks starting at groupIdxBase and
// returns their lane pointers, for the batch-16 arms that run the fill
// as four-lane kernel calls over Go-synthesised blocks; the blocks stay
// on the caller's stack because the kernels are called directly.
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

func scalarFused512X4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, n int, out *[4][8]uint64) {
	for lane := 0; lane < 4; lane++ {
		out[lane] = ScalarFusedChain512(fixedKey, components, lanePtr(dataPtrs[lane], n))
	}
}

// scalarFill256X8 / scalarFill512X4 are the pure-Go references of the
// batch-16 fill hooks: lane i runs the cascade over the fill block of
// group groupIdxBase+i.
func scalarFill256X8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	var blk [13]byte
	for i := range out {
		fillBlock(&blk, groupIdxBase+uint64(i))
		out[i] = ScalarFusedChain256(fixedKey, components, blk[:])
	}
}

func scalarFill512X4(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[4][8]uint64) {
	var blk [13]byte
	for i := range out {
		fillBlock(&blk, groupIdxBase+uint64(i))
		out[i] = ScalarFusedChain512(fixedKey, components, blk[:])
	}
}

// lanePtr views n bytes at p as a slice for the pure-Go fallbacks.
func lanePtr(p *byte, n int) []byte { return unsafe.Slice(p, n) }
