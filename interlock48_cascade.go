package itb

import (
	"encoding/binary"

	"github.com/everanium/itb/internal/forcetier"
)

// buildLockBatchPRF48_128Cascade is the cascade-fill variant of
// [buildLockBatchPRF48_128], selected when the lockSeed carries the
// batch-16 hook ([Seed128.InterlockFillX16] non-nil — the aesitb128
// primitive). Every hot-loop call runs the whole ChainHash cascade over
// the prepended component slice
//
//	lockComps = [lockLo, lockHi, c[0], c[1], …, c[n-1]]
//
// where (lockLo, lockHi) is the nonce-bound pair of
// [Seed128.deriveInterLockSeed] and c is the lockSeed's Components, so
// round 1 is the derived-pair call of the plain builder and rounds
// 2 .. 1 + n/2 feed the state forward through the session components
// (5 / 9 / 17 rounds at 512 / 1024 / 2048-bit keys). Inner seeds never
// rotate, so lockComps is built once per builder call.
//
// The four fill closures evaluate the same cascade on the same fill
// blocks [0x03 | LE64(groupIdx) | 4×0x00]: fill / fillRanks through the
// single-lane cascade (the seed's FusedChain hook or the sequential Hash
// loop), fillRanksX4 through the four-lane cascade (BatchFusedChain or
// the sequential BatchHash loop) and fillRanksSuper through the hook
// itself, so a group takes the same value whichever closure the worker
// split hands it to. The cascade selection depends on hook presence
// only; ITB_FORCE_INTERLOCK_PRF_FILL_SEQ and ITB_FORCE_CHAINHASH_SEQ
// choose which arm evaluates the cascade, never which wire is produced.
func buildLockBatchPRF48_128Cascade(lockSeed *Seed128, nonce []byte) lockBatchPRF48 {
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
