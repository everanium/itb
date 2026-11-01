package aescmacasm

import (
	"encoding/binary"
	"runtime"
	"unsafe"

	"github.com/everanium/areion"
)

// Fused cascade kernels evaluate the whole ChainHash128 cascade of the
// itb package in one call:
//
//	(lo, hi) = ChainAbsorb(s, data, c[0], c[1])
//	(lo, hi) = ChainAbsorb(s, data, c[2i] ^ lo, c[2i+1] ^ hi)   i = 1 .. pairs-1
//
// Because ChainAbsorb folds (seed0, seed1) and the length tag into the
// initial state and returns its final 16-byte state as (lo, hi), the
// cascade collapses to a register-resident loop: state = 0; per pair,
// state ^= pair, then for every zero-padded data block state ^= block
// and state = AES_K(state), carrying the state into the next pair. The
// data blocks are round-invariant and are staged once with the first
// round key folded in (block 0 also carries the length tag), so every
// AES-128 permutation in the kernels starts at round 1. The kernels
// return the state of the last pair as (lo, hi).
//
// x4 kernels run four lanes with distinct data over one shared component
// slice — the shape Seed128.BatchChainHash128 evaluates; x1 kernels serve
// the single-lane ChainHash128 path. components must hold at least two
// words and an even count (Seed128 guarantees both); shapes are the four
// per-pixel widths 13 / 20 / 36 / 68 bytes.

// ScalarFusedChain is the pure-Go reference cascade over ChainAbsorb.
func ScalarFusedChain(s *Schedule, components []uint64, data []byte) (uint64, uint64) {
	lo, hi := ChainAbsorb(s, data, components[0], components[1])
	for i := 2; i+1 < len(components); i += 2 {
		lo, hi = ChainAbsorb(s, data, components[i]^lo, components[i+1]^hi)
	}
	return lo, hi
}

func scalarFusedBatch(s *Schedule, components []uint64, dataPtrs *[4]*byte, n int, out *[4][2]uint64) {
	if len(components) < 2 {
		*out = [4][2]uint64{}
		return
	}
	var lanes [4][]byte
	if n > 0 {
		for lane := 0; lane < 4; lane++ {
			if dataPtrs[lane] != nil {
				lanes[lane] = unsafe.Slice(dataPtrs[lane], n)
			}
		}
	}
	lenTag := uint64(n)
	first := n
	if first > 16 {
		first = 16
	}
	var states areion.Block4
	var prev0, prev1 [4]uint64
	for idx := 0; idx+1 < len(components); idx += 2 {
		c0, c1 := components[idx], components[idx+1]
		for lane := 0; lane < 4; lane++ {
			lOff := lane * 16
			s0 := prev0[lane] ^ c0 ^ lenTag
			s1 := prev1[lane] ^ c1 ^ lenTag
			binary.LittleEndian.PutUint64(states[lOff:lOff+8], s0)
			binary.LittleEndian.PutUint64(states[lOff+8:lOff+16], s1)
			d := lanes[lane]
			for i := 0; i < first; i++ {
				states[lOff+i] ^= d[i]
			}
		}
		areion.AES128Encrypt4Blocks(&s.rk, &states, &states)
		for off := 16; off < n; off += 16 {
			end := off + 16
			if end > n {
				end = n
			}
			chunkLen := end - off
			for lane := 0; lane < 4; lane++ {
				lOff := lane * 16
				d := lanes[lane][off:end]
				for i := 0; i < chunkLen; i++ {
					states[lOff+i] ^= d[i]
				}
			}
			areion.AES128Encrypt4Blocks(&s.rk, &states, &states)
		}
		for lane := 0; lane < 4; lane++ {
			lOff := lane * 16
			prev0[lane] = binary.LittleEndian.Uint64(states[lOff : lOff+8])
			prev1[lane] = binary.LittleEndian.Uint64(states[lOff+8 : lOff+16])
		}
	}
	for lane := 0; lane < 4; lane++ {
		out[lane][0] = prev0[lane]
		out[lane][1] = prev1[lane]
	}
	clear(states[:])
	clear(prev0[:])
	clear(prev1[:])
	runtime.KeepAlive(&states)
	runtime.KeepAlive(&prev0)
	runtime.KeepAlive(&prev1)
}

func scalarFusedSingle(s *Schedule, components []uint64, data *byte, n int, out *[2]uint64) {
	out[0], out[1] = ScalarFusedChain(s, components, unsafe.Slice(data, n))
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
func scalarFusedX16(s *Schedule, components []uint64, groupIdxBase uint64, v uint32, out *[16][2]uint64) {
	var bufs [4][13]byte
	dataPtrs := [4]*byte{&bufs[0][0], &bufs[1][0], &bufs[2][0], &bufs[3][0]}
	for g := 0; g < 4; g++ {
		base := groupIdxBase + uint64(4*g)
		for lane := 0; lane < 4; lane++ {
			bufs[lane][0] = 0x03
			binary.LittleEndian.PutUint64(bufs[lane][1:9], base+uint64(lane))
			binary.LittleEndian.PutUint32(bufs[lane][9:13], v)
		}
		scalarFusedBatch(s, components, &dataPtrs, 13, (*[4][2]uint64)(out[4*g:4*g+4]))
	}
	clear(bufs[:])
	runtime.KeepAlive(&bufs)
}
