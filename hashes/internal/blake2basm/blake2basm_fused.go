package blake2basm

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

// Fused cascade kernels evaluate the whole ChainHash256 / ChainHash512
// cascade of the itb package over the BLAKE2b prefix-MAC closures of the
// parent hashes package in one call:
//
//	h = 0
//	for each component group g (4 words at width 256, 8 at width 512):
//	    seed = g ^ h
//	    h = BLAKE2b-W(fixedKey ‖ (data ⊕ seed))
//	out = h
//
// The hash input is the fixed key (32 bytes at width 256, 64 at 512)
// followed by data zero-padded to at least the seed-injection width (32
// / 64 bytes), with the seed words XORed over the bytes after the key.
// Every shape is one BLAKE2b compression except width 512 at the
// 68-byte shape, whose 132-byte input spans two blocks. The message
// words carrying data are round-invariant and staged once per call; the
// seed-injected words are rebuilt each cascade round from the staged
// data words, the component group and the previous round's output, all
// of which stay in registers or the frame.
//
// x4 kernels run four lanes with distinct data over one shared component
// slice — the shape Seed{256,512}.BatchChainHash evaluates — and the x8
// kernels eight; the single-lane entry points run the general-purpose-
// register kernels (blake2b_fusedchain{256,512}_<shape>x1_gpr_*.s), the
// single-lane arm of every tier. Shapes are the four per-pixel widths
// 13 / 20 / 36 / 68 bytes.

// Shapes are the per-pixel message lengths the kernels cover: the
// 13-byte Interlocked Barrier fill block and the 20 / 36 / 68-byte
// nonce-buf shapes.
var Shapes = [4]int{13, 20, 36, 68}

// absorb256 is the parent package's BLAKE2b-256 prefix-MAC of one
// (key, seed, data) triple.
func absorb256(key *[32]byte, seed *[4]uint64, data []byte) [4]uint64 {
	const keyLen, inject = 32, 32
	payload := len(data)
	if payload < inject {
		payload = inject
	}
	var stack [keyLen + 128]byte
	var buf []byte
	if keyLen+payload <= len(stack) {
		buf = stack[:keyLen+payload]
	} else {
		buf = make([]byte, keyLen+payload)
	}
	copy(buf[:keyLen], key[:])
	copy(buf[keyLen:], data)
	for i := range seed {
		off := keyLen + 8*i
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
	d := blake2b.Sum256(buf)
	var out [4]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(d[8*i:])
	}
	return out
}

// absorb512 is the width-512 form of [absorb256].
func absorb512(key *[64]byte, seed *[8]uint64, data []byte) [8]uint64 {
	const keyLen, inject = 64, 64
	payload := len(data)
	if payload < inject {
		payload = inject
	}
	var stack [keyLen + 128]byte
	var buf []byte
	if keyLen+payload <= len(stack) {
		buf = stack[:keyLen+payload]
	} else {
		buf = make([]byte, keyLen+payload)
	}
	copy(buf[:keyLen], key[:])
	copy(buf[keyLen:], data)
	for i := range seed {
		off := keyLen + 8*i
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
	d := blake2b.Sum512(buf)
	var out [8]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(d[8*i:])
	}
	return out
}

// ScalarFusedChain256 is the pure-Go reference cascade of width 256:
// one BLAKE2b-256 prefix-MAC per component group, the previous output
// folded into the group.
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

// ScalarFusedChain512 is the width-512 form of [ScalarFusedChain256]
// (eight words per group).
func ScalarFusedChain512(fixedKey *[64]byte, components []uint64, data []byte) [8]uint64 {
	var h, seed [8]uint64
	for g := 0; g+8 <= len(components); g += 8 {
		for i := range seed {
			seed[i] = components[g+i] ^ h[i]
		}
		h = absorb512(fixedKey, &seed, data)
	}
	return h
}

// validComponents256 / validComponents512 report whether the cascade can
// run: at least one group and a whole number of groups.
func validComponents256(components []uint64) bool {
	return len(components) >= 4 && len(components)%4 == 0
}

func validComponents512(components []uint64) bool {
	return len(components) >= 8 && len(components)%8 == 0
}

// fillBlock writes the 13-byte Interlocked Barrier fill block of one
// group: [0x03 | LE64(groupIdx) | 4×0x00].
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

// Eight-lane per-pixel and batch-32 fill references. The eight-lane
// dispatchers (Fused{256,512}Chain{20,36,68}x8) and the width-512
// batch-32 fill hook (Fused512Fill13x8) are pinned to these the way the
// four-lane and batch-16 arms are pinned to the functions above; each is
// by construction two half-width evaluations over the same components.

func scalarFused256X8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, n int, out *[8][4]uint64) {
	for lane := 0; lane < 8; lane++ {
		out[lane] = ScalarFusedChain256(fixedKey, components, lanePtr(dataPtrs[lane], n))
	}
}

func scalarFused512X8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, n int, out *[8][8]uint64) {
	for lane := 0; lane < 8; lane++ {
		out[lane] = ScalarFusedChain512(fixedKey, components, lanePtr(dataPtrs[lane], n))
	}
}

// scalarFill512X8 is the pure-Go reference of the width-512 batch-32
// fill hook: lane i (0..7) runs the cascade over the fill block of
// group groupIdxBase+i.
func scalarFill512X8(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[8][8]uint64) {
	var blk [13]byte
	for i := range out {
		fillBlock(&blk, groupIdxBase+uint64(i))
		out[i] = ScalarFusedChain512(fixedKey, components, blk[:])
	}
}

// Half views of the eight-lane argument arrays, for the arms that run
// a wide call as two narrower ones.
func ptrs8Half(p *[8]*byte, h int) *[4]*byte            { return (*[4]*byte)(p[4*h : 4*h+4]) }
func out8x256Half(o *[8][4]uint64, h int) *[4][4]uint64 { return (*[4][4]uint64)(o[4*h : 4*h+4]) }
func out8x512Half(o *[8][8]uint64, h int) *[4][8]uint64 { return (*[4][8]uint64)(o[4*h : 4*h+4]) }
