package itb

import (
	"encoding/binary"
	"testing"
)

// BenchmarkLockFillX4 times the 128-bit x4 interlock PRF fill closure
// (lockBatchPRF48.fillRanksX4) as built by buildLockBatchPRF48_128 over
// an AES-ITB-128 lockSeed — one call fills four groups through the
// seed's batched arm — against an in-benchmark closure that produces
// the identical fill blocks with a 1-byte store at offset 0 plus an
// 8-byte store at offset 1 and passes the lane seeds as a per-call
// literal. Both variants drive the same kernel under the same dispatch
// flags (ITB_FORCE_HASH_TIER selects the tier), so the difference is
// the Go-side store shape ahead of the call alone. Outputs are checked
// equal before timing.
func BenchmarkLockFillX4(b *testing.B) {
	var key [16]byte
	for i := range key {
		key[i] = byte(0x11 * i)
	}
	h, bh, _ := MakeAESITB128Hash(key)
	seed, err := NewSeed128(512, h)
	if err != nil {
		b.Fatal(err)
	}
	seed.BatchHash = bh
	nonce := make([]byte, 64)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	bp := buildLockBatchPRF48_128(seed, nonce)
	if bp.fillRanksX4 == nil {
		b.Fatal("fillRanksX4 not attached")
	}
	lockLo, lockHi := seed.deriveInterLockSeed(nonce)
	stable := [4][2]uint64{{lockLo, lockHi}, {lockLo, lockHi}, {lockLo, lockHi}, {lockLo, lockHi}}
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
	store := func(prf []uint64, out [4][2]uint64) {
		for i := 0; i < 4; i++ {
			prf[2*i] = out[i][0]
			prf[2*i+1] = out[i][1]
		}
	}
	byteLiteral := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
		fillBytes(s, groupIdx)
		store(prf, bh(&s.data, [4][2]uint64{{lockLo, lockHi}, {lockLo, lockHi}, {lockLo, lockHi}, {lockLo, lockHi}}))
	}
	byteStable := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
		fillBytes(s, groupIdx)
		store(prf, bh(&s.data, stable))
	}
	splitLiteral := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
		fillSplit(s, groupIdx)
		store(prf, bh(&s.data, [4][2]uint64{{lockLo, lockHi}, {lockLo, lockHi}, {lockLo, lockHi}, {lockLo, lockHi}}))
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
	var pA, pB [8]uint64
	for _, v := range variants[1:] {
		for g := uint64(0); g < 64; g += 4 {
			bp.fillRanksX4(&sA, g, pA[:])
			v.fn(&sB, g, pB[:])
			if pA != pB || sA.bufs != sB.bufs {
				b.Fatalf("%s disagrees with the shipped fill at group %d", v.name, g)
			}
		}
	}

	for _, v := range variants {
		b.Run(v.name, func(b *testing.B) {
			var s lockFillScratch48
			var prf [8]uint64
			b.SetBytes(4 * 13)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v.fn(&s, uint64(4*i), prf[:])
			}
		})
	}
}
