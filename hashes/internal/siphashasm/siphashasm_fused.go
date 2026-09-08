package siphashasm

import (
	"encoding/binary"
	"unsafe"
)

// Fused cascade kernels evaluate the whole ChainHash128 cascade of the
// itb package in one call:
//
//	(lo, hi) = ChainAbsorb(data, c[0], c[1])
//	(lo, hi) = ChainAbsorb(data, c[2i] ^ lo, c[2i+1] ^ hi)   i = 1 .. pairs-1
//
// SipHash is keyed by the seed pair alone, so every round re-keys the
// state from the previous round's output XOR the component pair and
// re-absorbs the message words; the words are round-invariant and are
// packed once per call, and the (lo, hi) carry never leaves the
// registers. The kernels return the output of the last pair.
//
// x4 kernels run four lanes with distinct data over one shared component
// slice — the shape Seed128.BatchChainHash128 evaluates; x1 kernels serve
// the single-lane ChainHash128 path. components must hold at least two
// words and an even count (Seed128 guarantees both); shapes are the four
// per-pixel widths 13 / 20 / 36 / 68 bytes.

// ScalarFusedChain is the pure-Go reference cascade over ChainAbsorb.
func ScalarFusedChain(components []uint64, data []byte) (uint64, uint64) {
	lo, hi := ChainAbsorb(data, components[0], components[1])
	for i := 2; i+1 < len(components); i += 2 {
		lo, hi = ChainAbsorb(data, components[i]^lo, components[i+1]^hi)
	}
	return lo, hi
}

func scalarFusedBatch(components []uint64, dataPtrs *[4]*byte, n int, out *[4][2]uint64) {
	for lane := 0; lane < 4; lane++ {
		out[lane][0], out[lane][1] = ScalarFusedChain(components, unsafe.Slice(dataPtrs[lane], n))
	}
}

func scalarFusedSingle(components []uint64, data *byte, n int, out *[2]uint64) {
	out[0], out[1] = ScalarFusedChain(components, unsafe.Slice(data, n))
}

// validComponents reports whether the cascade can run: at least one pair
// and an even word count.
func validComponents(components []uint64) bool {
	return len(components) >= 2 && len(components)%2 == 0
}

// fillBlocks16 synthesises the sixteen 13-byte Interlocked Barrier fill
// blocks [0x03 | LE64(groupIdxBase+i) | 4×0x00] for lanes 0..15.
func fillBlocks16(groupIdxBase uint64) [16][13]byte {
	var blocks [16][13]byte
	for i := range blocks {
		blocks[i][0] = 0x03
		binary.LittleEndian.PutUint64(blocks[i][1:9], groupIdxBase+uint64(i))
	}
	return blocks
}

// scalarFusedX16 is the pure-Go reference of the batch-16 fused cascade
// at the Interlocked Barrier fill shape: lane i (0..15) runs
// ScalarFusedChain over its fill block with the shared components. out
// receives the 16 rank pairs in lane order. With one component pair the
// cascade is the plain chain-absorb of each fill block under that pair.
func scalarFusedX16(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	blocks := fillBlocks16(groupIdxBase)
	for i := range blocks {
		out[i][0], out[i][1] = ScalarFusedChain(components, blocks[i][:])
	}
}

// x16Quarter returns the lane pointers of quarter q (lanes 4q..4q+3) of
// the sixteen fill blocks. The tiers without a sixteen-lane kernel run
// the batch-16 fill as four four-lane kernel calls over Go-synthesised
// blocks; the kernels are called directly (not through a function value)
// so the blocks and the pointer array stay on the caller's stack.
func x16Quarter(blocks *[16][13]byte, q int) [4]*byte {
	return [4]*byte{&blocks[4*q][0], &blocks[4*q+1][0], &blocks[4*q+2][0], &blocks[4*q+3][0]}
}

// x16Out returns quarter q (lanes 4q..4q+3) of a batch-16 output as the
// four-lane output array of one kernel call.
func x16Out(out *[16][2]uint64, q int) *[4][2]uint64 {
	return (*[4][2]uint64)(out[4*q : 4*q+4])
}
