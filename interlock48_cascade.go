package itb

import (
	"encoding/binary"

	"github.com/everanium/itb/internal/forcetier"
)

// Interlocked Barrier cascade fill — the batched PRF builders of the
// 48-bit overlay at every hash width.
//
// Every builder runs the whole ChainHash cascade of its lockSeed on
// every hot-loop call over the prepended component slice
//
//	lockComps = [K[0], …, K[w-1], c[0], c[1], …, c[n-1]]
//
// where K = deriveInterLockSeed(nonce) is the nonce-bound ChainHash
// output of the lockSeed under the 0x04 domain tag (w = width / 64
// words) and c is the lockSeed's Components. Round 1 of the cascade is
// therefore the derived-key call and rounds 2 .. 1 + keyBits / width
// feed the state forward through the session components, so a group's
// rank material depends on the interlock nonce and on every component
// word of the lockSeed on every call. Inner seeds never rotate, so
// lockComps is built once per builder call.
//
// The cascade is the wire at every width and for every primitive; no
// hook on the lockSeed selects it. The optional hooks the seed carries
// (FusedChain / BatchFusedChain / InterlockFillX16) only decide which
// arm evaluates the cascade — the fused kernel, the batched kernel, or
// the sequential Hash / BatchHash loop — and every arm is bit-exact
// with the sequential loop by contract, so a seed with and without its
// hooks produces the same lane bytes. ITB_FORCE_INTERLOCK_PRF_FILL_SEQ
// and ITB_FORCE_CHAINHASH_SEQ likewise choose an arm, never a wire.
//
// The fill closures share one fill block per group,
// [0x03 | LE64(groupIdx) | 4×0x00] (13 bytes): fill / fillRanks
// evaluate the single-lane cascade ([Seed128.chainHash128With] and the
// wider counterparts), fillRanksX4 the four-lane cascade
// ([Seed128.batchChainHash128With] and counterparts) and
// fillRanksSuper the batch-16 hook, so a group takes the same value
// whichever closure the worker split hands it to.

// buildLockBatchPRF48_128 is the batched 128-bit-width builder. One
// cascade per group yields 1 mask triple from the (lo, hi) output pair
// (each 48-bit chunk consumes two 64-bit lanes for its 128-bit rank, so
// a 128-bit hash width supplies material for exactly one chunk per
// call). The cascade runs 1 + keyBits / 128 rounds per group (5 / 9 /
// 17 at 512 / 1024 / 2048-bit keys).
//
// The closure captures the lockSeed's ChainHash-derived keying material
// and the lockSeed's hash arms — the overlay's PRF keying is fully
// isolated from the noiseSeed slot's material.
func buildLockBatchPRF48_128(lockSeed *Seed128, nonce []byte) lockBatchPRF48 {
	lockLo, lockHi := lockSeed.deriveInterLockSeed(nonce)
	lockComps := make([]uint64, 2+len(lockSeed.Components))
	lockComps[0], lockComps[1] = lockLo, lockHi
	copy(lockComps[2:], lockSeed.Components)
	bp := lockBatchPRF48{
		factor: lockBatchFactor48_128,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			lo, hi := lockSeed.chainHash128With(lockComps, buf)
			var prf [8]uint64
			prf[0], prf[1] = lo, hi
			fillLockMasksTriple48(&prf, lockBatchFactor48_128, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			prf[0], prf[1] = lockSeed.chainHash128With(lockComps, buf)
		},
	}
	if lockSeed.BatchHash != nil {
		bp.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := lockSeed.batchChainHash128With(lockComps, &s.data)
			for i := 0; i < 4; i++ {
				prf[2*i] = out[i][0]
				prf[2*i+1] = out[i][1]
			}
		}
	}
	if bh16 := lockSeed.InterlockFillX16(); bh16 != nil && !forcetier.InterlockPRFFillSeq() {
		bp.fillRanksSuper = func(s *lockFillScratch48, groupIdxBase uint64, prf []uint64) {
			bh16(lockComps, groupIdxBase, &s.out16)
			for i := 0; i < 16; i++ {
				prf[2*i] = s.out16[i][0]
				prf[2*i+1] = s.out16[i][1]
			}
		}
	}
	return bp
}

// buildLockBatchPRF48_256 is the 256-bit counterpart of
// [buildLockBatchPRF48_128]. One cascade per group yields 2 mask triples
// from out[0..3]; the cascade runs 1 + keyBits / 256 rounds per group
// (3 / 5 / 9 at 512 / 1024 / 2048-bit keys). The batch-16 hook, when
// armed, fills 8 groups (16 chunks) per call.
func buildLockBatchPRF48_256(lockSeed *Seed256, nonce []byte) lockBatchPRF48 {
	lockKey := lockSeed.deriveInterLockSeed(nonce)
	lockComps := make([]uint64, 4+len(lockSeed.Components))
	copy(lockComps[:4], lockKey[:])
	copy(lockComps[4:], lockSeed.Components)
	bp := lockBatchPRF48{
		factor: lockBatchFactor48_256,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := lockSeed.chainHash256With(lockComps, buf)
			var prf [8]uint64
			copy(prf[:4], out[:])
			fillLockMasksTriple48(&prf, lockBatchFactor48_256, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := lockSeed.chainHash256With(lockComps, buf)
			copy(prf[:4], out[:])
		},
	}
	if lockSeed.BatchHash != nil {
		bp.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := lockSeed.batchChainHash256With(lockComps, &s.data)
			for i := 0; i < 4; i++ {
				copy(prf[4*i:4*i+4], out[i][:])
			}
		}
	}
	if bh16 := lockSeed.InterlockFillX16(); bh16 != nil && !forcetier.InterlockPRFFillSeq() {
		bp.fillRanksSuper = func(s *lockFillScratch48, groupIdxBase uint64, prf []uint64) {
			bh16(lockComps, groupIdxBase, &s.out16x256)
			for i := 0; i < 8; i++ {
				copy(prf[4*i:4*i+4], s.out16x256[i][:])
			}
		}
	}
	if bh32 := lockSeed.InterlockFillX32(); bh32 != nil && !forcetier.InterlockPRFFillSeq() && !forcetier.InterlockPRFFillNarrow() {
		bp.fillRanksSuper32 = func(s *lockFillScratch48, groupIdxBase uint64, prf []uint64) {
			bh32(lockComps, groupIdxBase, &s.out32x256)
			for i := 0; i < 16; i++ {
				copy(prf[4*i:4*i+4], s.out32x256[i][:])
			}
		}
	}
	return bp
}

// buildLockBatchPRF48_512 is the 512-bit counterpart of
// [buildLockBatchPRF48_128]. One cascade per group yields 4 mask triples
// from out[0..7]; the cascade runs 1 + keyBits / 512 rounds per group
// (2 / 3 / 5 at 512 / 1024 / 2048-bit keys). The batch-16 hook, when
// armed, fills 4 groups (16 chunks) per call; the batch-32 hook 8 groups
// (32 chunks).
func buildLockBatchPRF48_512(lockSeed *Seed512, nonce []byte) lockBatchPRF48 {
	lockKey := lockSeed.deriveInterLockSeed(nonce)
	lockComps := make([]uint64, 8+len(lockSeed.Components))
	copy(lockComps[:8], lockKey[:])
	copy(lockComps[8:], lockSeed.Components)
	bp := lockBatchPRF48{
		factor: lockBatchFactor48_512,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := lockSeed.chainHash512With(lockComps, buf)
			fillLockMasksTriple48(&out, lockBatchFactor48_512, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			out := lockSeed.chainHash512With(lockComps, buf)
			copy(prf[:8], out[:])
		},
	}
	if lockSeed.BatchHash != nil {
		bp.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := lockSeed.batchChainHash512With(lockComps, &s.data)
			for i := 0; i < 4; i++ {
				copy(prf[8*i:8*i+8], out[i][:])
			}
		}
	}
	if bh16 := lockSeed.InterlockFillX16(); bh16 != nil && !forcetier.InterlockPRFFillSeq() {
		bp.fillRanksSuper = func(s *lockFillScratch48, groupIdxBase uint64, prf []uint64) {
			bh16(lockComps, groupIdxBase, &s.out16x512)
			for i := 0; i < 4; i++ {
				copy(prf[8*i:8*i+8], s.out16x512[i][:])
			}
		}
	}
	if bh32 := lockSeed.InterlockFillX32(); bh32 != nil && !forcetier.InterlockPRFFillSeq() && !forcetier.InterlockPRFFillNarrow() {
		bp.fillRanksSuper32 = func(s *lockFillScratch48, groupIdxBase uint64, prf []uint64) {
			bh32(lockComps, groupIdxBase, &s.out32x512)
			for i := 0; i < 8; i++ {
				copy(prf[8*i:8*i+8], s.out32x512[i][:])
			}
		}
	}
	return bp
}
