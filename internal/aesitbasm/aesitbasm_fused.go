package aesitbasm

import (
	"encoding/binary"
	"unsafe"
)

// Fused cascade kernels evaluate the whole ChainHash128 cascade of the
// parent package in one call:
//
//	(lo, hi) = ChainAbsorb(key, data, c[0], c[1])
//	(lo, hi) = ChainAbsorb(key, data, c[2i] ^ lo, c[2i+1] ^ hi)   i = 1 .. pairs-1
//
// Because ChainAbsorb folds (seed0, seed1) into key as the initial state
// and returns its final 16-byte state as (lo, hi), the cascade collapses
// to a register-resident loop: state = 0; per pair, state ^= key ^ pair,
// absorb the (round-invariant, staged once) padded data blocks, apply the
// two finaliser rounds, and carry the state into the next pair. The
// kernels return the state of the last pair as (lo, hi).
//
// x4 kernels run four lanes with distinct data over one shared component
// slice — the shape Seed128.BatchChainHash128 evaluates; x1 kernels serve
// the single-lane ChainHash128 path. components must hold at least two
// words and an even count (Seed128 guarantees both); shapes are the same
// 13 / 20 / 36 / 68 the per-round kernels cover.

// ScalarFusedChain is the pure-Go reference cascade over ChainAbsorb.
func ScalarFusedChain(key *[16]byte, components []uint64, data []byte) (uint64, uint64) {
	lo, hi := ChainAbsorb(key, data, components[0], components[1])
	for i := 2; i+1 < len(components); i += 2 {
		lo, hi = ChainAbsorb(key, data, components[i]^lo, components[i+1]^hi)
	}
	return lo, hi
}

func scalarFusedBatch(key *[16]byte, components []uint64, dataPtrs *[4]*byte, n int, out *[4][2]uint64) {
	for lane := 0; lane < 4; lane++ {
		out[lane][0], out[lane][1] = ScalarFusedChain(key, components, unsafe.Slice(dataPtrs[lane], n))
	}
}

func scalarFusedSingle(key *[16]byte, components []uint64, data *byte, n int, out *[2]uint64) {
	out[0], out[1] = ScalarFusedChain(key, components, unsafe.Slice(data, n))
}

// validComponents reports whether the cascade can run: at least one pair
// and an even word count.
func validComponents(components []uint64) bool {
	return len(components) >= 2 && len(components)%2 == 0
}

// scalarFusedX16 is the pure-Go reference of the batch-16 fused cascade
// at the Interlocked Barrier fill shape: lane i (0..15) runs
// ScalarFusedChain over the 13-byte fill block
// [0x03 | LE64(groupIdxBase+i) | 4×0x00] with the shared components.
// out receives the 16 rank pairs in lane order. With one component pair
// the cascade is the plain chain-absorb of each fill block under that
// pair.
func scalarFusedX16(key *[16]byte, components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	for i := 0; i < 16; i++ {
		var buf [13]byte
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], groupIdxBase+uint64(i))
		out[i][0], out[i][1] = ScalarFusedChain(key, components, buf[:])
	}
}
