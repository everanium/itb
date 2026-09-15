// Package blake3asm holds the fused ChainHash cascade kernels of BLAKE3
// for the parent hashes package: the whole component cascade of a seed
// evaluated in one kernel call at the four per-pixel shapes (13 / 20 /
// 36 / 68 bytes) — four lanes on the AVX-512 EVEX XMM, AVX2 VEX XMM and
// NEON tiers, eight lanes on EVEX YMM registers at the nonce-buf shapes
// and for the batch-16 Interlocked Barrier fill hook, and one lane in
// general-purpose registers as the single-lane arm of every tier. The
// keyed mode places the fixed key in the chaining value: the
// initialisation vector, the block lengths and the flag set
// (CHUNK_START / CHUNK_END / ROOT / KEYED_HASH) are folded into
// per-kernel read-only tables by the generator
// (scripts/kernels/blake3/gen_fused_kernels.py). Register layout after
// github.com/saucecontrol/Blake2Fast (MIT), Blake3Scalar.g.cs: one
// register per state word, one dword lane per pixel, VPRORD for the
// four ARX rotates on the EVEX tier, the seven-round message schedule
// unrolled.
package blake3asm

import (
	"encoding/binary"
	"unsafe"

	"github.com/zeebo/blake3"
)

// Fused cascade kernels evaluate the whole ChainHash256 cascade of the
// itb package over the keyed BLAKE3 closure of the parent hashes package
// in one call:
//
//	h = 0
//	for each component group g (4 words):
//	    seed = g ^ h
//	    h = BLAKE3-keyed(fixedKey, data ⊕ seed)
//	out = h
//
// The hash input is data zero-padded to at least the 32-byte
// seed-injection width, with the seed words XORed over the first 32
// bytes, hashed by BLAKE3 in keyed mode with the 32-byte fixed key as the
// initial chaining value. The input is one chunk: the 13-, 20- and
// 36-byte shapes are one compression; the 68-byte shape spans two
// blocks, the second chaining on the first's output. The output is the
// first 32 bytes of the root output. Every 64-bit seed and output word
// straddles two 32-bit message words, low half first. The message words
// carrying data are round-invariant and staged once per call; the
// seed-injected words are rebuilt each cascade round from the staged
// data words, the component group and the previous round's output, all
// of which stay in registers or the frame.
//
// x4 kernels run four lanes with distinct data over one shared component
// slice — the shape Seed256.BatchChainHash evaluates — and the x8 kernels
// eight (one dword lane per pixel: XMM at four lanes, YMM at eight); the
// single-lane entry points run the general-purpose-register kernels
// (blake3_fusedchain256_<shape>x1_gpr_*.s), the single-lane arm of every
// tier. Shapes are the four per-pixel widths 13 / 20 / 36 / 68 bytes.
// The generator is scripts/kernels/blake3/gen_fused_kernels.py.

// Shapes are the per-pixel message lengths the kernels cover: the
// 13-byte Interlocked Barrier fill block and the 20 / 36 / 68-byte
// nonce-buf shapes.
var Shapes = [4]int{13, 20, 36, 68}

// absorb256 is the parent package's keyed BLAKE3 hash of one (key,
// seed, data) triple.
func absorb256(key *[32]byte, seed *[4]uint64, data []byte) [4]uint64 {
	const inject = 32
	payload := len(data)
	if payload < inject {
		payload = inject
	}
	var stack [128]byte
	var buf []byte
	if payload <= len(stack) {
		buf = stack[:payload]
	} else {
		buf = make([]byte, payload)
	}
	copy(buf, data)
	for i := range seed {
		off := 8 * i
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	h.Write(buf)
	var d [32]byte
	h.Sum(d[:0])
	var out [4]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(d[8*i:])
	}
	return out
}

// ScalarFusedChain256 is the pure-Go reference cascade: one keyed
// BLAKE3 hash per component group, the previous output folded into the
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
