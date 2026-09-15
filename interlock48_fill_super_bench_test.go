package itb

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/everanium/itb/internal/aesitbasm"
)

// BenchmarkLockFillSuper16 times the 128-bit batch-16 interlock PRF fill
// closure (lockBatchPRF48.fillRanksSuper) as built by
// buildLockBatchPRF48_128 over an AES-ITB-128 lockSeed carrying the
// batch-16 hook — one call fills sixteen groups through the seed's
// batch-16 kernel and copies the sixteen rank pairs into the prf
// staging with 8-byte loads immediately after the kernel returns. The
// sweep covers the 512-, 1024- and 2048-bit key sizes (5 / 9 / 17
// cascade rounds respectively) so the per-call fill cost is timed at
// every shipped cascade depth. The kernel tier is selected by
// ITB_FORCE_INTERLOCK_PRF_FILL_TIER (avx512 / vaesavx2 / vex / aesni),
// so the same closure times every tier's store shape against the
// closure's read-back. Output is checked against the sequential
// fillRanks path before timing.
func BenchmarkLockFillSuper16(b *testing.B) {
	for _, bits := range []int{512, 1024, 2048} {
		b.Run(fmt.Sprintf("%dbit", bits), func(b *testing.B) {
			benchLockFillSuper16(b, bits)
		})
	}
}

func benchLockFillSuper16(b *testing.B, bits int) {
	var key [16]byte
	for i := range key {
		key[i] = byte(0x11 * i)
	}
	h, bh, _ := MakeAESITB128Hash(key)
	seed, err := NewSeed128(bits, h)
	if err != nil {
		b.Fatal(err)
	}
	seed.BatchHash = bh
	seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		aesitbasm.FusedChain13x16(&key, components, groupIdxBase, out)
	})
	nonce := make([]byte, 64)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	bp := buildLockBatchPRF48_128(seed, nonce)
	if bp.fillRanksSuper == nil {
		b.Fatal("fillRanksSuper not attached")
	}

	var s lockFillScratch48
	var got [32]uint64
	var want [2]uint64
	buf := make([]byte, 13)
	for g := uint64(0); g < 64; g += 16 {
		bp.fillRanksSuper(&s, g, got[:])
		for i := uint64(0); i < 16; i++ {
			bp.fillRanks(buf, g+i, want[:])
			if got[2*i] != want[0] || got[2*i+1] != want[1] {
				b.Fatalf("batch-16 fill disagrees with the sequential fill at group %d", g+i)
			}
		}
	}

	var prf [32]uint64
	b.SetBytes(16 * 13)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp.fillRanksSuper(&s, uint64(16*i), prf[:])
	}
}

// BenchmarkLockFillX4Wide times the 256- and 512-bit x4 interlock PRF
// fill closures (lockBatchPRF48.fillRanksX4 as built by
// buildLockBatchPRF48_256 / _512 over Areion-SoEM lockSeeds) alongside
// in-benchmark closures that drive the same batched arm with the lane
// seeds passed as a per-call literal. The shipped closures capture the
// seeds as a stable array; the literal variant rebuilds the [4][N]uint64
// argument with narrower stores immediately ahead of the call, which
// the by-value copy into the callee frame then reads with wider loads.
// The shipped closure runs the ChainHash cascade (1 + keyBits/width
// rounds per group) while the literal variant calls BatchHash once, so
// their outputs do NOT match — the benchmark isolates Go-side store-
// shape cost only; the cascade cost is common to every arm of the
// shipped fill.
func BenchmarkLockFillX4Wide(b *testing.B) {
	nonce := make([]byte, 64)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	b.Run("256", func(b *testing.B) {
		h, bh, _ := MakeAreionSoEM256Hash()
		seed, err := NewSeed256(512, h)
		if err != nil {
			b.Fatal(err)
		}
		seed.BatchHash = bh
		bp := buildLockBatchPRF48_256(seed, nonce)
		if bp.fillRanksX4 == nil {
			b.Fatal("fillRanksX4 not attached")
		}
		lockKey := seed.deriveInterLockSeed(nonce)
		literal := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := bh(&s.data, [4][4]uint64{lockKey, lockKey, lockKey, lockKey})
			for i := 0; i < 4; i++ {
				copy(prf[4*i:4*i+4], out[i][:])
			}
		}
		benchLockFillX4Wide(b, 16, bp.fillRanksX4, literal)
	})
	b.Run("512", func(b *testing.B) {
		h, bh, _ := MakeAreionSoEM512Hash()
		seed, err := NewSeed512(512, h)
		if err != nil {
			b.Fatal(err)
		}
		seed.BatchHash = bh
		bp := buildLockBatchPRF48_512(seed, nonce)
		if bp.fillRanksX4 == nil {
			b.Fatal("fillRanksX4 not attached")
		}
		lockKey := seed.deriveInterLockSeed(nonce)
		literal := func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
			for i := range s.bufs {
				s.bufs[i][0] = 0x03
				binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
				s.data[i] = s.bufs[i][:]
			}
			out := bh(&s.data, [4][8]uint64{lockKey, lockKey, lockKey, lockKey})
			for i := 0; i < 4; i++ {
				copy(prf[8*i:8*i+8], out[i][:])
			}
		}
		benchLockFillX4Wide(b, 32, bp.fillRanksX4, literal)
	})
}

// benchLockFillX4Wide times the two closures over 64 groups; words is
// the number of rank words one call writes.
func benchLockFillX4Wide(b *testing.B, words int, shipped, literal func(*lockFillScratch48, uint64, []uint64)) {
	for _, v := range []struct {
		name string
		fn   func(*lockFillScratch48, uint64, []uint64)
	}{{"stableSeeds", shipped}, {"literalSeeds", literal}} {
		b.Run(v.name, func(b *testing.B) {
			var s lockFillScratch48
			prf := make([]uint64, words)
			b.SetBytes(4 * 13)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v.fn(&s, uint64(4*i), prf)
			}
		})
	}
}
