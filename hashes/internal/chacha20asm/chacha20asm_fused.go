package chacha20asm

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/chacha20"
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
// The per-round ChaCha20 key is the 32-byte fixed key XOR the seed words,
// the nonce is zero, and the 32-byte state [LE64(len(data)) | 24-byte
// data window] absorbs the data 24 bytes at a time — each window XORed
// into the state, then the state XORed with the next 32 bytes of
// keystream. The keystream does not depend on the state, so the absorb
// is one XOR of the folded data windows with the keystream halves the
// shape consumes: the low half of block 0 at 13 / 20 bytes, both halves
// of block 0 at 36 bytes, both halves of block 0 and the low half of
// block 1 at 68 bytes. Every 64-bit seed and output word straddles two
// 32-bit key words, low half first. The data words are staged once per
// call; the key words are rebuilt each cascade round from the fixed key,
// the component group and the previous round's output, all of which
// stay in registers or the frame.
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

// absorb256 is the parent package's ChaCha20 PRF of one (key, seed,
// data) triple.
func absorb256(fixedKey *[32]byte, seed *[4]uint64, data []byte) [4]uint64 {
	var key [32]byte
	copy(key[:], fixedKey[:])
	for i := range seed {
		off := 8 * i
		binary.LittleEndian.PutUint64(key[off:], binary.LittleEndian.Uint64(key[off:])^seed[i])
	}
	var nonce [12]byte
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	const window = 24
	if len(data) <= window {
		copy(state[8:8+len(data)], data)
		c.XORKeyStream(state[:], state[:])
	} else {
		copy(state[8:8+window], data[:window])
		c.XORKeyStream(state[:], state[:])
		for off := window; off < len(data); off += window {
			end := off + window
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			c.XORKeyStream(state[:], state[:])
		}
	}
	var out [4]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(state[8*i:])
	}
	return out
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
