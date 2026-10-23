package aesitbasm

import (
	"encoding/binary"
	"runtime"
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
// words and an even count (Seed128 guarantees both); shapes are the four
// AES-ITB-128 per-pixel widths 13 / 20 / 36 / 68 bytes.

// ScalarFusedChain is the pure-Go reference cascade over ChainAbsorb.
func ScalarFusedChain(key *[16]byte, components []uint64, data []byte) (uint64, uint64) {
	n := len(data)
	full := n &^ 15
	numBlocks := full/16 + 1
	if numBlocks > 8 {
		lo, hi := ChainAbsorb(key, data, components[0], components[1])
		for i := 2; i+1 < len(components); i += 2 {
			lo, hi = ChainAbsorb(key, data, components[i]^lo, components[i+1]^hi)
		}
		return lo, hi
	}

	var bsBlocks [8]bsState
	var blkBuf [16]byte
	for blk := 0; blk < numBlocks; blk++ {
		var k *[16]byte
		if blk == 0 {
			k = key
		}
		paddedBlock(&blkBuf, k, data, blk, full)
		bsPack1(&bsBlocks[blk], &blkBuf)
	}
	clear(blkBuf[:])
	runtime.KeepAlive(&blkBuf)

	var q, bsPair bsState
	for i := 0; i+1 < len(components); i += 2 {
		bsPackWords1(&bsPair, components[i], components[i+1])
		for k := 0; k < 8; k++ {
			q[k] ^= bsPair[k] ^ bsBlocks[0][k]
		}
		bsRound(&q, &bsRC[0])
		for blk := 1; blk < numBlocks; blk++ {
			for k := 0; k < 8; k++ {
				q[k] ^= bsBlocks[blk][k]
			}
			bsRound(&q, &bsRC[blk&7])
		}
		bsRound(&q, &bsRC[numBlocks&7])
		bsRound(&q, &bsRC[(numBlocks+1)&7])
	}
	lo, hi := bsUnpackWords1(&q)
	clear(bsBlocks[:])
	clear(q[:])
	clear(bsPair[:])
	runtime.KeepAlive(&bsBlocks)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&bsPair)
	return lo, hi
}

func scalarFusedBatch(key *[16]byte, components []uint64, dataPtrs *[4]*byte, n int, out *[4][2]uint64) {
	full := n &^ 15
	numBlocks := full/16 + 1
	if numBlocks > 8 {
		for lane := 0; lane < 4; lane++ {
			out[lane][0], out[lane][1] = ScalarFusedChain(key, components, unsafe.Slice(dataPtrs[lane], n))
		}
		return
	}

	var bsBlocks [8]bsState
	var laneBlocks [4][16]byte
	for blk := 0; blk < numBlocks; blk++ {
		var k *[16]byte
		if blk == 0 {
			k = key
		}
		for lane := 0; lane < 4; lane++ {
			paddedBlock(&laneBlocks[lane], k, unsafe.Slice(dataPtrs[lane], n), blk, full)
		}
		bsPack4(&bsBlocks[blk], &laneBlocks[0], &laneBlocks[1], &laneBlocks[2], &laneBlocks[3])
	}
	clear(laneBlocks[:])
	runtime.KeepAlive(&laneBlocks)

	var q, bsPair bsState
	for i := 0; i+1 < len(components); i += 2 {
		bsPackBroadcastWords(&bsPair, components[i], components[i+1])
		for k := 0; k < 8; k++ {
			q[k] ^= bsPair[k] ^ bsBlocks[0][k]
		}
		bsRound(&q, &bsRC[0])
		for blk := 1; blk < numBlocks; blk++ {
			for k := 0; k < 8; k++ {
				q[k] ^= bsBlocks[blk][k]
			}
			bsRound(&q, &bsRC[blk&7])
		}
		bsRound(&q, &bsRC[numBlocks&7])
		bsRound(&q, &bsRC[(numBlocks+1)&7])
	}
	bsUnpackWords4(&q, out)
	clear(bsBlocks[:])
	clear(q[:])
	clear(bsPair[:])
	runtime.KeepAlive(&bsBlocks)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&bsPair)
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
// [0x03 | LE64(groupIdxBase+i) | LE32(v)] with the shared components,
// v being the per-message interlock-nonce fold the caller supplies.
// out receives the 16 rank pairs in lane order. With one component pair
// the cascade is the plain chain-absorb of each fill block under that
// pair.
func scalarFusedX16(key *[16]byte, components []uint64, groupIdxBase uint64, v uint32, out *[16][2]uint64) {
	var bufs [4][13]byte
	dataPtrs := [4]*byte{&bufs[0][0], &bufs[1][0], &bufs[2][0], &bufs[3][0]}
	for g := 0; g < 4; g++ {
		base := groupIdxBase + uint64(4*g)
		for lane := 0; lane < 4; lane++ {
			bufs[lane][0] = 0x03
			binary.LittleEndian.PutUint64(bufs[lane][1:9], base+uint64(lane))
			binary.LittleEndian.PutUint32(bufs[lane][9:13], v)
		}
		scalarFusedBatch(key, components, &dataPtrs, 13, (*[4][2]uint64)(out[4*g:4*g+4]))
	}
	clear(bufs[:])
	runtime.KeepAlive(&bufs)
}
