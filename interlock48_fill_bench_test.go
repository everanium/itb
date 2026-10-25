package itb

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/areionasm"
)

// Timings of the interlock PRF fill closures a lockBatchPRF48 carries.
// Each benchmark drives the shipped closure and, alongside it, closures
// that reach the same underlying primitive through a different Go-side
// store shape, so the cost of the staging is separated from the cost of
// the primitive itself.

// The fillRanksX4 closure — four groups per call through the lockSeed's
// batched arm.

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
	fold := interlockNonceFold(nonce)
	fillBytes := func(s *lockFillScratch48, groupIdx uint64) {
		for i := range s.bufs {
			s.bufs[i][0] = 0x03
			binary.LittleEndian.PutUint64(s.bufs[i][1:9], groupIdx+uint64(i))
			copy(s.bufs[i][9:13], fold[:])
			s.data[i] = s.bufs[i][:]
		}
	}
	fillSplit := func(s *lockFillScratch48, groupIdx uint64) {
		for i := range s.bufs {
			gi := groupIdx + uint64(i)
			binary.LittleEndian.PutUint64(s.bufs[i][0:8], 0x03|gi<<8)
			binary.LittleEndian.PutUint32(s.bufs[i][8:12], uint32(gi>>56)|binary.LittleEndian.Uint32(fold[:])<<8)
			s.bufs[i][12] = fold[3]
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
	fold := interlockNonceFold(nonce)
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
				copy(s.bufs[i][9:13], fold[:])
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
				copy(s.bufs[i][9:13], fold[:])
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

// The fillRanksSuper closure — sixteen groups per call through the
// lockSeed's batch-16 kernel.

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
	seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, v uint32, out *[16][2]uint64) {
		aesitbasm.FusedChain13x16(&key, components, groupIdxBase, v, out)
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

func makeAreion512BenchSeed(tb testing.TB, bits int) *Seed512 {
	tb.Helper()
	var key [64]byte
	for i := range key {
		key[i] = byte(0x33*i + 1)
	}
	h, bh := MakeAreionSoEM512HashWithKey(key)
	seed, err := NewSeed512(bits, h)
	if err != nil {
		tb.Fatal(err)
	}
	seed.BatchHash = bh
	seed.FusedChain = func(components []uint64, data []byte) ([8]uint64, bool) {
		var out [8]uint64
		if len(data) != 13 {
			return out, false
		}
		areionasm.Fused512Chain13x1(&key, components, &data[0], &out)
		return out, true
	}
	seed.BatchFusedChain = func(components []uint64, data *[4][]byte) ([4][8]uint64, bool) {
		var out [4][8]uint64
		for i := range data {
			if len(data[i]) != 13 {
				return out, false
			}
		}
		ptrs := [4]*byte{&data[0][0], &data[1][0], &data[2][0], &data[3][0]}
		areionasm.Fused512Chain13x4(&key, components, &ptrs, &out)
		return out, true
	}
	seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, v uint32, out *[4][8]uint64) {
		areionasm.Fused512Fill13x4(&key, components, groupIdxBase, v, out)
	})
	seed.SetInterlockBatch32(func(components []uint64, groupIdxBase uint64, v uint32, out *[8][8]uint64) {
		areionasm.Fused512Fill13x8(&key, components, groupIdxBase, v, out)
	})
	return seed
}

func makeBlake2b512BenchSeed(tb testing.TB, bits int) *Seed512 {
	tb.Helper()
	var key [64]byte
	for i := range key {
		key[i] = byte(0x55*i + 3)
	}
	eval := func(data []byte, s [8]uint64) [8]uint64 {
		var stack [128]byte
		payloadLen := len(data)
		if payloadLen < 64 {
			payloadLen = 64
		}
		need := 64 + payloadLen
		var buf []byte
		if need <= len(stack) {
			buf = stack[:need]
		} else {
			buf = make([]byte, need)
		}
		copy(buf[:64], key[:])
		copy(buf[64:64+len(data)], data)
		for i := 0; i < 8; i++ {
			off := 64 + 8*i
			binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^s[i])
		}
		digest := blake2b.Sum512(buf)
		var out [8]uint64
		for i := 0; i < 8; i++ {
			out[i] = binary.LittleEndian.Uint64(digest[8*i:])
		}
		return out
	}
	bh := func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64 {
		var out [4][8]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = eval(data[lane], seeds[lane])
		}
		return out
	}
	seed, err := NewSeed512(bits, eval)
	if err != nil {
		tb.Fatal(err)
	}
	seed.BatchHash = bh
	return seed
}

// BenchmarkLockFillSuper512 times the 512-bit interlock PRF fill ladder
// over 8 groups per iteration (one 168-bit superblock = 64 rank words =
// 8 × 13-byte fill blocks) across the 512-, 1024-, and 2048-bit key
// sizes for Areion512 (super32, super16x2, x4x2, seqx8) and BLAKE2b512
// (x4x2, seqx8).
func BenchmarkLockFillSuper512(b *testing.B) {
	nonce := make([]byte, 64)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	b.Run("Areion512", func(b *testing.B) {
		for _, bits := range []int{512, 1024, 2048} {
			b.Run(fmt.Sprintf("%dbit", bits), func(b *testing.B) {
				seed := makeAreion512BenchSeed(b, bits)
				bp := buildLockBatchPRF48_512(seed, nonce)
				defer bp.wipe()
				if bp.fillRanksSuper32 == nil || bp.fillRanksSuper == nil || bp.fillRanksX4 == nil {
					b.Fatal("Areion512 fill hooks not attached")
				}

				// Verify all rungs agree with sequential fillRanks before timing.
				var checkScratch lockFillScratch48
				var got32, got16, gotX4 [64]uint64
				var want [8]uint64
				var checkBuf [13]byte
				bp.fillRanksSuper32(&checkScratch, 0, got32[:])
				bp.fillRanksSuper(&checkScratch, 0, got16[0:32])
				bp.fillRanksSuper(&checkScratch, 4, got16[32:64])
				bp.fillRanksX4(&checkScratch, 0, gotX4[0:32])
				bp.fillRanksX4(&checkScratch, 4, gotX4[32:64])
				for j := uint64(0); j < 8; j++ {
					bp.fillRanks(checkBuf[:], j, want[:])
					for w := 0; w < 8; w++ {
						idx := int(8*j) + w
						if got32[idx] != want[w] || got16[idx] != want[w] || gotX4[idx] != want[w] {
							b.Fatalf("Areion512 %dbit group %d word %d fill rung mismatch", bits, j, w)
						}
					}
				}

				b.Run("super32", func(b *testing.B) {
					var s lockFillScratch48
					var prf [64]uint64
					b.SetBytes(8 * 13)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						bp.fillRanksSuper32(&s, uint64(8*i), prf[:64])
					}
				})
				b.Run("super16x2", func(b *testing.B) {
					var s lockFillScratch48
					var prf [64]uint64
					b.SetBytes(8 * 13)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						g := uint64(8 * i)
						bp.fillRanksSuper(&s, g, prf[0:32])
						bp.fillRanksSuper(&s, g+4, prf[32:64])
					}
				})
				b.Run("x4x2", func(b *testing.B) {
					var s lockFillScratch48
					var prf [64]uint64
					b.SetBytes(8 * 13)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						g := uint64(8 * i)
						bp.fillRanksX4(&s, g, prf[0:32])
						bp.fillRanksX4(&s, g+4, prf[32:64])
					}
				})
				b.Run("seqx8", func(b *testing.B) {
					var buf [13]byte
					var prf [64]uint64
					b.SetBytes(8 * 13)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						g := uint64(8 * i)
						for j := uint64(0); j < 8; j++ {
							bp.fillRanks(buf[:], g+j, prf[8*j:8*j+8])
						}
					}
				})
			})
		}
	})
	b.Run("BLAKE2b512", func(b *testing.B) {
		for _, bits := range []int{512, 1024, 2048} {
			b.Run(fmt.Sprintf("%dbit", bits), func(b *testing.B) {
				seed := makeBlake2b512BenchSeed(b, bits)
				bp := buildLockBatchPRF48_512(seed, nonce)
				defer bp.wipe()
				if bp.fillRanksX4 == nil {
					b.Fatal("BLAKE2b512 fillRanksX4 not attached")
				}
				b.Run("x4x2", func(b *testing.B) {
					var s lockFillScratch48
					var prf [64]uint64
					b.SetBytes(8 * 13)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						g := uint64(8 * i)
						bp.fillRanksX4(&s, g, prf[0:32])
						bp.fillRanksX4(&s, g+4, prf[32:64])
					}
				})
				b.Run("seqx8", func(b *testing.B) {
					var buf [13]byte
					var prf [64]uint64
					b.SetBytes(8 * 13)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						g := uint64(8 * i)
						for j := uint64(0); j < 8; j++ {
							bp.fillRanks(buf[:], g+j, prf[8*j:8*j+8])
						}
					}
				})
			})
		}
	})
}
