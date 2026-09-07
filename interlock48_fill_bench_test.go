package itb

import (
	"encoding/binary"
	"testing"
)

// BenchmarkLockFillX4 times the 256-bit x4 interlock PRF fill closure
// (lockBatchPRF48.fillRanksX4) as built by buildLockBatchPRF48_256 over
// an Areion-SoEM-256 lockSeed — one call fills four groups through the
// seed's batched arm — against in-benchmark closures that produce the
// identical fill blocks with alternative store shapes and pass the lane
// seeds as a per-call literal. All variants drive the same kernel under
// the same dispatch flags (ITB_FORCE_HASH_TIER selects the tier), so
// the difference is the Go-side store shape ahead of the call alone.
// Outputs are checked equal before timing.
//
// Areion-SoEM-256 is the primitive under measurement because it carries
// no cascade fill (unlike aesitb128, whose shipping fill routes through
// the cascade branch and would make a raw single-round store-shape
// comparison structurally inapplicable).
func BenchmarkLockFillX4(b *testing.B) {
	h, bh, _ := MakeAreionSoEM256Hash()
	seed, err := NewSeed256(512, h)
	if err != nil {
		b.Fatal(err)
	}
	seed.BatchHash = bh
	nonce := make([]byte, 64)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	bp := buildLockBatchPRF48_256(seed, nonce)
	if bp.fillRanksX4 == nil {
		b.Fatal("fillRanksX4 not attached")
	}
	lockKey := seed.deriveInterLockSeed(nonce)
	stable := [4][4]uint64{lockKey, lockKey, lockKey, lockKey}
	fillBytes := func(s *lockFillScratch48, groupIdx uint64) {
		for i := range s.bufs {
			s.bufs[i][0] = 0x03
			binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
			s.data[i] = s.bufs[i][:]
		}
	}
	fillSplit := func(s *lockFillScratch48, groupIdx uint64) {
		for i := range s.bufs {
			gi := groupIdx + uint64(i)
			binary.LittleEndian.PutUint64(s.bufs[i][0:8], 0x03|gi<<8)
			binary.LittleEndian.PutUint32(s.bufs[i][8:12], uint32(gi>>56))
			s.data[i] = s.bufs[i][:]
		}
	}
	store := func(prf []uint64, out [4][4]uint64) {
		for i := 0; i < 4; i++ {
			copy(prf[4*i:4*i+4], out[i][:])
		}
	}
	byteLiteral := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
		fillBytes(s, groupIdx)
		store(prf, bh(&s.data, [4][4]uint64{lockKey, lockKey, lockKey, lockKey}))
	}
	byteStable := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
		fillBytes(s, groupIdx)
		store(prf, bh(&s.data, stable))
	}
	splitLiteral := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
		fillSplit(s, groupIdx)
		store(prf, bh(&s.data, [4][4]uint64{lockKey, lockKey, lockKey, lockKey}))
	}
	variants := []struct {
		name string
		fn   func(*lockFillScratch48, uint64, []uint64)
	}{
		{"shipped", bp.fillRanksX4},
		{"byteStore/literalSeeds", byteLiteral},
		{"byteStore/stableSeeds", byteStable},
		{"splitStore/literalSeeds", splitLiteral},
	}

	var sA, sB lockFillScratch48
	pA := make([]uint64, 16)
	pB := make([]uint64, 16)
	for _, v := range variants[1:] {
		for g := uint64(0); g < 64; g += 4 {
			bp.fillRanksX4(&sA, g, pA)
			v.fn(&sB, g, pB)
			for i := range pA {
				if pA[i] != pB[i] {
					b.Fatalf("%s disagrees with the shipped fill at group %d", v.name, g)
				}
			}
			if sA.bufs != sB.bufs {
				b.Fatalf("%s scratch disagrees with the shipped fill at group %d", v.name, g)
			}
		}
	}

	for _, v := range variants {
		b.Run(v.name, func(b *testing.B) {
			var s lockFillScratch48
			prf := make([]uint64, 16)
			b.SetBytes(4 * 13)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v.fn(&s, uint64(4*i), prf)
			}
		})
	}
}
