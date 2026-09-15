package itb

import (
	"encoding/binary"
	"testing"
)

// BenchmarkLockFillX4 times the 256-bit x4 interlock PRF fill closure
// (lockBatchPRF48.fillRanksX4) as built by buildLockBatchPRF48_256 over
// an Areion-SoEM-256 lockSeed — one call fills four groups through the
// seed's batched arm — alongside in-benchmark closures that exercise
// alternative Go-side store shapes ahead of the same underlying
// BatchHash primitive. The shipped closure runs the ChainHash cascade
// (1 + keyBits/256 rounds per group; 3 rounds at NewSeed256(512, ...)),
// while the alternative closures call the primitive's BatchHash for a
// single round, so their output does NOT match the shipped closure's
// cascade output — the benchmark isolates Go-side store-shape cost
// only; the cascade cost is common to every arm of the shipped fill.
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
