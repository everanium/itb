package itb

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/everanium/itb/internal/interlock"
	"github.com/everanium/itb/internal/poolstats"
)

func uint192ToBigInt(v [3]uint64) *big.Int {
	var buf [24]byte
	binary.BigEndian.PutUint64(buf[0:8], v[2])
	binary.BigEndian.PutUint64(buf[8:16], v[1])
	binary.BigEndian.PutUint64(buf[16:24], v[0])
	return new(big.Int).SetBytes(buf[:])
}

func bigIntToUint192(x *big.Int) [3]uint64 {
	var buf [24]byte
	x.FillBytes(buf[:])
	return [3]uint64{
		binary.BigEndian.Uint64(buf[16:24]),
		binary.BigEndian.Uint64(buf[8:16]),
		binary.BigEndian.Uint64(buf[0:8]),
	}
}

func addUint192(a, b [3]uint64) [3]uint64 {
	s0, c0 := bits.Add64(a[0], b[0], 0)
	s1, c1 := bits.Add64(a[1], b[1], c0)
	s2, _ := bits.Add64(a[2], b[2], c1)
	return [3]uint64{s0, s1, s2}
}

func subUint192One(a [3]uint64) [3]uint64 {
	d0, b0 := bits.Sub64(a[0], 1, 0)
	d1, b1 := bits.Sub64(a[1], 0, b0)
	d2, _ := bits.Sub64(a[2], 0, b1)
	return [3]uint64{d0, d1, d2}
}

func popcount192(m [3]uint64) int {
	return bits.OnesCount64(m[0]) + bits.OnesCount64(m[1]) + bits.OnesCount64(m[2])
}

// splitRank168Big is the big-integer reference implementation of the
// Two-Step Exact-B reduction using [math/big], kept for test parity.
func splitRank168Big(r [8]uint64) (idx0 [3]uint64, idx1 [2]uint64) {
	var rBE [64]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(rBE[8*(7-i):8*(8-i)], r[i])
	}
	rInt := new(big.Int).SetBytes(rBE[:])

	var bBE [16]byte
	binary.BigEndian.PutUint64(bBE[0:8], interlockB168_1)
	binary.BigEndian.PutUint64(bBE[8:16], interlockB168_0)
	bInt := new(big.Int).SetBytes(bBE[:])

	var aBE [24]byte
	binary.BigEndian.PutUint64(aBE[0:8], interlockA168_2)
	binary.BigEndian.PutUint64(aBE[8:16], interlockA168_1)
	binary.BigEndian.PutUint64(aBE[16:24], interlockA168_0)
	aInt := new(big.Int).SetBytes(aBE[:])

	qInt := new(big.Int)
	idx1Int := new(big.Int)
	qInt.DivMod(rInt, bInt, idx1Int)

	idx0Int := new(big.Int).Mod(qInt, aInt)

	var idx1BE [16]byte
	idx1Int.FillBytes(idx1BE[:])
	idx1[1] = binary.BigEndian.Uint64(idx1BE[0:8])
	idx1[0] = binary.BigEndian.Uint64(idx1BE[8:16])

	var idx0BE [24]byte
	idx0Int.FillBytes(idx0BE[:])
	idx0[2] = binary.BigEndian.Uint64(idx0BE[0:8])
	idx0[1] = binary.BigEndian.Uint64(idx0BE[8:16])
	idx0[0] = binary.BigEndian.Uint64(idx0BE[16:24])
	return
}

// TestSplitRank168RecipVsBigInt verifies both step-level Barrett reciprocal
// reductions (divmodStepB168 and modStepA168) at exact multiples and maximum
// dividends, and the full 512-bit two-step splitRank168 against splitRank168Big
// across 10 edge cases and 10,000 random 512-bit digests.
func TestSplitRank168RecipVsBigInt(t *testing.T) {
	b168Big := uint192ToBigInt([3]uint64{interlockB168_0, interlockB168_1, 0})
	a168Big := uint192ToBigInt([3]uint64{interlockA168_0, interlockA168_1, interlockA168_2})
	b168MaxDiv := new(big.Int).Lsh(b168Big, 64)
	a168MaxDiv := new(big.Int).Lsh(a168Big, 64)
	zeroBig := big.NewInt(0)

	qTests := []uint64{
		1,
		2,
		3,
		(1 << 32) - 1,
		1 << 63,
		^uint64(0) - 1,
		^uint64(0),
	}
	deltas := []int64{-1, 0, 1}

	for _, qTest := range qTests {
		qBig := new(big.Int).SetUint64(qTest)
		for _, delta := range deltas {
			dBig := big.NewInt(delta)

			// Step-level divmodStepB168 check: X_b = qTest * B168 + delta
			xb := new(big.Int).Mul(qBig, b168Big)
			xb.Add(xb, dBig)
			if xb.Cmp(zeroBig) >= 0 && xb.Cmp(b168MaxDiv) < 0 {
				var xbBuf [24]byte
				xb.FillBytes(xbBuf[:])
				r1In := binary.BigEndian.Uint64(xbBuf[0:8])
				r0In := binary.BigEndian.Uint64(xbBuf[8:16])
				wIn := binary.BigEndian.Uint64(xbBuf[16:24])

				qGot, remGot0, remGot1 := divmodStepB168(r0In, r1In, wIn)
				qWant, rWant := new(big.Int).QuoRem(xb, b168Big, new(big.Int))
				rGotBig := uint192ToBigInt([3]uint64{remGot0, remGot1, 0})
				if qGot != qWant.Uint64() || rGotBig.Cmp(rWant) != 0 {
					t.Fatalf("divmodStepB168(q=%#x, delta=%d): got q=%#x r=%s, want q=%#x r=%s",
						qTest, delta, qGot, rGotBig.Text(16), qWant.Uint64(), rWant.Text(16))
				}
			}

			// Step-level modStepA168 check: X_a = qTest * A168 + delta
			xa := new(big.Int).Mul(qBig, a168Big)
			xa.Add(xa, dBig)
			if xa.Cmp(zeroBig) >= 0 && xa.Cmp(a168MaxDiv) < 0 {
				var xaBuf [32]byte
				xa.FillBytes(xaBuf[:])
				r2In := binary.BigEndian.Uint64(xaBuf[0:8])
				r1In := binary.BigEndian.Uint64(xaBuf[8:16])
				r0In := binary.BigEndian.Uint64(xaBuf[16:24])
				wIn := binary.BigEndian.Uint64(xaBuf[24:32])

				aGot0, aGot1, aGot2 := modStepA168(r0In, r1In, r2In, wIn)
				rWant := new(big.Int).Mod(xa, a168Big)
				rGotBig := uint192ToBigInt([3]uint64{aGot0, aGot1, aGot2})
				if rGotBig.Cmp(rWant) != 0 {
					t.Fatalf("modStepA168(q=%#x, delta=%d): got r=%s, want r=%s",
						qTest, delta, rGotBig.Text(16), rWant.Text(16))
				}
			}
		}
	}

	// Maximum possible step dividends: r = B168 - 1 (or A168 - 1), w = 2^64 - 1.
	qbMax, rb0, rb1 := divmodStepB168(interlockB168_0-1, interlockB168_1, ^uint64(0))
	if qbMax != ^uint64(0) || rb0 != interlockB168_0-1 || rb1 != interlockB168_1 {
		t.Fatalf("divmodStepB168 max dividend: got q=%#x r=(%#x,%#x)", qbMax, rb0, rb1)
	}
	ra0, ra1, ra2 := modStepA168(interlockA168_0-1, interlockA168_1, interlockA168_2, ^uint64(0))
	if ra0 != interlockA168_0-1 || ra1 != interlockA168_1 || ra2 != interlockA168_2 {
		t.Fatalf("modStepA168 max dividend: got r=(%#x,%#x,%#x)", ra0, ra1, ra2)
	}

	// 10 512-bit edge cases + 10,000 random 512-bit vectors.
	const max64 = ^uint64(0)
	edgeCases := [][8]uint64{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{max64, max64, max64, max64, max64, max64, max64, max64},
		{1, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 1},
		{interlockB168_0, interlockB168_1, 0, 0, 0, 0, 0, 0},
		{interlockB168_0 - 1, interlockB168_1, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, interlockB168_0, interlockB168_1, 0},
		{0, 0, 0, 0, 0, interlockB168_0 - 1, interlockB168_1, 0},
		{interlockA168_0, interlockA168_1, interlockA168_2, 0, 0, 0, 0, 0},
		{interlockA168_0 - 1, interlockA168_1, interlockA168_2, 0, 0, 0, 0, 0},
	}
	for tcIdx, words := range edgeCases {
		got0, got1 := splitRank168(words)
		want0, want1 := splitRank168Big(words)
		if got0 != want0 || got1 != want1 {
			t.Fatalf("edge case %d: got (%x, %x), want (%x, %x)", tcIdx, got0, got1, want0, want1)
		}
	}

	rng := mathrand.New(mathrand.NewSource(0x16801))
	for i := 0; i < 10000; i++ {
		var words [8]uint64
		for j := range words {
			words[j] = rng.Uint64()
		}
		got0, got1 := splitRank168(words)
		want0, want1 := splitRank168Big(words)
		if got0 != want0 || got1 != want1 {
			t.Fatalf("random vector %d: got (%x, %x), want (%x, %x)", i, got0, got1, want0, want1)
		}
	}
}

// TestBinomialC168Constants checks C(168, 56) == A168, C(112, 56) == B168,
// and Pascal's identity across all 0 <= n <= 168 and 0 <= k <= 56.
func TestBinomialC168Constants(t *testing.T) {
	wantA := [3]uint64{interlockA168_0, interlockA168_1, interlockA168_2}
	if binomialC168[168][56] != wantA {
		t.Fatalf("C(168, 56) = %x, want %x", binomialC168[168][56], wantA)
	}
	wantB := [3]uint64{interlockB168_0, interlockB168_1, 0}
	if binomialC168[112][56] != wantB {
		t.Fatalf("C(112, 56) = %x, want %x", binomialC168[112][56], wantB)
	}
	for n := 1; n <= 168; n++ {
		maxK := 56
		if n < maxK {
			maxK = n
		}
		for k := 1; k <= maxK; k++ {
			got := binomialC168[n][k]
			want := addUint192(binomialC168[n-1][k-1], binomialC168[n-1][k])
			if got != want {
				t.Fatalf("Pascal mismatch at C(%d, %d): got %x, want %x", n, k, got, want)
			}
		}
	}
}

// TestUnrank168KernelVsReference verifies all 18 boundary rank pairs
// (including all 4 extreme z-tuples, p=134 rem[2]==1,
// p=67 rem[1]==1, and p=63 max-rem), 1,000 random 512-bit rank vectors,
// and short-superblock counts 1..7 across AVX-512, AVX2, NEON, and pure-Go.
func TestUnrank168KernelVsReference(t *testing.T) {
	idx0Z64_8_40 := subUint192One(binomialC168[128][56])
	var idx0Z48_64_0 [3]uint64
	for i := 0; i < 40; i++ {
		idx0Z48_64_0 = addUint192(idx0Z48_64_0, binomialC168[128+i][17+i])
	}
	var idxP67Rem1 [3]uint64
	for i := 0; i < 22; i++ {
		idxP67Rem1 = addUint192(idxP67Rem1, binomialC168[68+i][35+i])
	}
	idxP67Rem1 = addUint192(idxP67Rem1, subUint192One(binomialC168[68][34]))

	var idxP63Max [3]uint64
	for i := 0; i < 24; i++ {
		idxP63Max = addUint192(idxP63Max, binomialC168[64+i][33+i])
	}
	idxP63Max = addUint192(idxP63Max, subUint192One(binomialC168[64][32]))

	a168 := [3]uint64{interlockA168_0, interlockA168_1, interlockA168_2}
	b168 := [3]uint64{interlockB168_0, interlockB168_1, 0}
	a168Minus1 := subUint192One(a168)
	b168Minus1 := subUint192One(b168)

	a168Big := uint192ToBigInt(a168)
	b168Big := uint192ToBigInt(b168)
	a168Half := bigIntToUint192(new(big.Int).Rsh(a168Big, 1))
	b168Half := bigIntToUint192(new(big.Int).Rsh(b168Big, 1))
	b168Third := bigIntToUint192(new(big.Int).Quo(b168Big, big.NewInt(3)))

	extremeRanks := [][2][3]uint64{
		{{0, 0, 0}, {0, 0, 0}},
		{a168Minus1, b168Minus1},
		{a168Minus1, {0, 0, 0}},
		{{0, 0, 0}, b168Minus1},
		{a168Half, b168Half},
		{{1, 0, 0}, {1, 0, 0}},
		{idx0Z64_8_40, b168Minus1},
		{idx0Z48_64_0, b168Third},
		{{0, 0, 1}, b168Half},
		{subUint192One(binomialC168[135][56]), b168Minus1},
		{binomialC168[135][56], {0, 0, 0}},
		{subUint192One(binomialC168[134][56]), b168Half},
		{binomialC168[134][56], {1, 0, 0}},
		{{0, 1, 0}, {^uint64(0), 0, 0}},
		{idxP67Rem1, idxP67Rem1},
		{idxP63Max, idxP63Max},
		{subUint192One(binomialC168[68][56]), subUint192One(binomialC168[68][56])},
		{subUint192One(binomialC168[64][56]), subUint192One(binomialC168[64][56])},
	}

	seenZ := make(map[[3]int]bool)
	domain := [3]uint64{^uint64(0), ^uint64(0), 0x0000_00FF_FFFF_FFFF}

	for i, pair := range extremeRanks {
		idx0 := pair[0]
		idx1 := [2]uint64{pair[1][0], pair[1][1]}
		m0, m1, m2 := rankToMaskTriple168FromSplit(idx0, idx1)
		if popcount192(m0) != 56 || popcount192(m1) != 56 || popcount192(m2) != 56 {
			t.Fatalf("extreme rank %d: popcounts (%d, %d, %d), want (56, 56, 56)",
				i, popcount192(m0), popcount192(m1), popcount192(m2))
		}
		for w := 0; w < 3; w++ {
			if (m0[w]&m1[w]) != 0 || (m0[w]&m2[w]) != 0 || (m1[w]&m2[w]) != 0 {
				t.Fatalf("extreme rank %d word %d: masks not disjoint", i, w)
			}
			if (m0[w] | m1[w] | m2[w]) != domain[w] {
				t.Fatalf("extreme rank %d word %d: union %#x != domain %#x", i, w, m0[w]|m1[w]|m2[w], domain[w])
			}
		}
		zTuple := [3]int{
			64 - bits.OnesCount64(m0[0]),
			64 - bits.OnesCount64(m0[1]),
			40 - bits.OnesCount64(m0[2]),
		}
		seenZ[zTuple] = true
	}

	for _, wantZ := range [][3]int{{8, 64, 40}, {64, 48, 0}, {64, 8, 40}, {48, 64, 0}} {
		if !seenZ[wantZ] {
			t.Fatalf("missing expected extreme z-tuple %v", wantZ)
		}
	}

	// Verify hardware kernels on the 18 extreme ranks + 1000 random ranks + short superblocks 1..7.
	type kernelCase struct {
		name string
		ok   bool
		fn   func(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64)
	}
	kernels := []kernelCase{
		{"AVX512", interlock.HasAVX512RankMask, interlock.RankToMaskTripleUnrank168},
		{"AVX2", interlock.HasBMI2 && (interlock.HasAVX2RankMask || interlock.HasAVX512RankMask), interlock.RankToMaskTripleUnrank168AVX2},
		{"NEON", interlock.HasNEONInterlock, interlock.RankToMaskTripleUnrank168NEON},
	}
	for _, kc := range kernels {
		if !kc.ok {
			continue
		}
		for base := 0; base < len(extremeRanks); base += 8 {
			var idx0Batch [3][8]uint64
			var idx1Batch [2][8]uint64
			for j := 0; j < 8; j++ {
				srcIdx := base + j
				if srcIdx >= len(extremeRanks) {
					srcIdx = len(extremeRanks) - 1
				}
				idx0Batch[0][j] = extremeRanks[srcIdx][0][0]
				idx0Batch[1][j] = extremeRanks[srcIdx][0][1]
				idx0Batch[2][j] = extremeRanks[srcIdx][0][2]
				idx1Batch[0][j] = extremeRanks[srcIdx][1][0]
				idx1Batch[1][j] = extremeRanks[srcIdx][1][1]
			}
			var out [3][3][8]uint64
			kc.fn(&idx0Batch, &idx1Batch, &out)
			for j := 0; j < 8; j++ {
				i0 := [3]uint64{idx0Batch[0][j], idx0Batch[1][j], idx0Batch[2][j]}
				i1 := [2]uint64{idx1Batch[0][j], idx1Batch[1][j]}
				m0Ref, m1Ref, m2Ref := rankToMaskTriple168FromSplit(i0, i1)
				m0Got := [3]uint64{out[0][0][j], out[0][1][j], out[0][2][j]}
				m1Got := [3]uint64{out[1][0][j], out[1][1][j], out[1][2][j]}
				m2Got := [3]uint64{out[2][0][j], out[2][1][j], out[2][2][j]}
				if m0Got != m0Ref || m1Got != m1Ref || m2Got != m2Ref {
					t.Fatalf("kernel=%s extreme batch base=%d lane=%d: kernel != ref", kc.name, base, j)
				}
			}
		}
	}

	rng := mathrand.New(mathrand.NewSource(0x16802))
	for batch := 0; batch < 125; batch++ {
		var prf [64]uint64
		for i := range prf {
			prf[i] = rng.Uint64()
		}
		var masksKernel [8][3][3]uint64
		fillLockMasksTriple168Super(&prf, 8, &masksKernel)
		for j := 0; j < 8; j++ {
			var words [8]uint64
			copy(words[:], prf[8*j:8*(j+1)])
			m0Ref, m1Ref, m2Ref := rankToMaskTriple168(words)
			if masksKernel[j][0] != m0Ref || masksKernel[j][1] != m1Ref || masksKernel[j][2] != m2Ref {
				t.Fatalf("random batch %d lane %d: fillLockMasksTriple168Super != rankToMaskTriple168", batch, j)
			}
		}
	}

	// Short-superblock counts 1..7.
	var prf [64]uint64
	for i := range prf {
		prf[i] = uint64(i+1) * 0x9E3779B97F4A7C15
	}
	for count := 1; count <= 7; count++ {
		var masks [8][3][3]uint64
		fillLockMasksTriple168Super(&prf, count, &masks)
		for j := 0; j < count; j++ {
			var words [8]uint64
			copy(words[:], prf[8*j:8*(j+1)])
			m0Ref, m1Ref, m2Ref := rankToMaskTriple168(words)
			if masks[j][0] != m0Ref || masks[j][1] != m1Ref || masks[j][2] != m2Ref {
				t.Fatalf("count=%d lane=%d: short superblock mismatch", count, j)
			}
		}
	}
}

// TestChunk168LockRoundTripAndParity verifies chunk168lock / unchunk168lock,
// softPEXT168 / softPDEP168, interlock.Chunk168Lock / Unchunk168Lock, and
// chunk168lockBatch / unchunk168lockBatch across batch lengths 1..19.
func TestChunk168LockRoundTripAndParity(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0x16803))
	for n := 1; n <= 19; n++ {
		src := make([]byte, 21*n)
		for i := range src {
			src[i] = byte(rng.Intn(256))
		}
		var masks [superChunks168 * 3][3][3]uint64
		for k := 0; k < n; k++ {
			var words [8]uint64
			for j := range words {
				words[j] = rng.Uint64()
			}
			m0, m1, m2 := rankToMaskTriple168(words)
			masks[k] = [3][3]uint64{m0, m1, m2}

			x := readChunk168(src, 21*k)
			// Compare softPEXT168 vs chunk168lock vs interlock.Chunk168Lock.
			s0 := softPEXT168(x, m0)
			s1 := softPEXT168(x, m1)
			s2 := softPEXT168(x, m2)
			l0, l1, l2 := chunk168lock(x, m0, m1, m2)
			if l0 != s0 || l1 != s1 || l2 != s2 {
				t.Fatalf("chunk=%d: chunk168lock (%#x,%#x,%#x) != softPEXT168 (%#x,%#x,%#x)",
					k, l0, l1, l2, s0, s1, s2)
			}
			if interlock.HasBMI2 {
				var cBuf [21]byte
				writeChunk168(cBuf[:], 0, x)
				var outBuf [3][7]byte
				interlock.Chunk168Lock(&cBuf, m0, m1, m2, &outBuf)
				kl0 := readLane56(outBuf[0][:], 0)
				kl1 := readLane56(outBuf[1][:], 0)
				kl2 := readLane56(outBuf[2][:], 0)
				if kl0 != s0 || kl1 != s1 || kl2 != s2 {
					t.Fatalf("chunk=%d: Chunk168Lock != softPEXT168", k)
				}
			}

			// Compare softPDEP168 vs unchunk168lock vs interlock.Unchunk168Lock.
			u0 := softPDEP168(s0, m0)
			u1 := softPDEP168(s1, m1)
			u2 := softPDEP168(s2, m2)
			wantX := [3]uint64{u0[0] | u1[0] | u2[0], u0[1] | u1[1] | u2[1], u0[2] | u1[2] | u2[2]}
			if wantX != x {
				t.Fatalf("chunk=%d: softPDEP168 round-trip %x != %x", k, wantX, x)
			}
			gotX := unchunk168lock(l0, l1, l2, m0, m1, m2)
			if gotX != x {
				t.Fatalf("chunk=%d: unchunk168lock round-trip %x != %x", k, gotX, x)
			}
		}

		p0 := make([]byte, 7*n)
		p1 := make([]byte, 7*n)
		p2 := make([]byte, 7*n)
		if !chunk168lockBatch(framedSrc168{body: src}, n, 0, n, masks[:n], p0, p1, p2) {
			for k := 0; k < n; k++ {
				x := readChunk168(src, 21*k)
				l0, l1, l2 := chunk168lock(x, masks[k][0], masks[k][1], masks[k][2])
				writeLane56(p0, 7*k, l0)
				writeLane56(p1, 7*k, l1)
				writeLane56(p2, 7*k, l2)
			}
		}

		for k := 0; k < n; k++ {
			x := readChunk168(src, 21*k)
			w0, w1, w2 := chunk168lock(x, masks[k][0], masks[k][1], masks[k][2])
			if readLane56(p0, 7*k) != w0 || readLane56(p1, 7*k) != w1 || readLane56(p2, 7*k) != w2 {
				t.Fatalf("batch n=%d k=%d: chunk168lockBatch lane mismatch", n, k)
			}
		}

		dst := make([]byte, 21*n)
		if !unchunk168lockBatch(dst, n, 0, n, masks[:n], p0, p1, p2) {
			for k := 0; k < n; k++ {
				l0 := readLane56(p0, 7*k)
				l1 := readLane56(p1, 7*k)
				l2 := readLane56(p2, 7*k)
				x := unchunk168lock(l0, l1, l2, masks[k][0], masks[k][1], masks[k][2])
				writeChunk168(dst, 21*k, x)
			}
		}
		if !bytes.Equal(dst, src) {
			t.Fatalf("batch n=%d: unchunk168lockBatch round-trip mismatch", n)
		}
	}
}

// TestSplitAndInterleave168AllLengths tests splitForTriple168LockedInto and
// interleaveForTriple168LockedCfg / interleaveForTriple168LockedCfgInto across
// message lengths, both 512-bit seeds (Areion512 and testHash512), worker
// counts, all 4 cascade fill tiers, the in-place caller staging fast path,
// and wrong-seed plausible decryption with unequal lane lengths.
func TestSplitAndInterleave168AllLengths(t *testing.T) {
	// Include lengths corresponding to chunk counts M = 0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 25, 100, 196.
	lengths := []int{0, 1, 2, 16, 17, 18, 20, 21, 22, 37, 38, 39, 41, 42, 43, 63, 143, 164, 185, 311, 332, 353, 512, 2096, 4096}
	rng := mathrand.New(mathrand.NewSource(0x16804))

	comps := make([]uint64, 16)
	for i := range comps {
		comps[i] = rng.Uint64() | 1
	}
	var key64 [64]byte
	for i := range key64 {
		key64[i] = byte(rng.Intn(256))
	}

	makeAreionSeed := func() *Seed512 {
		h, bh := MakeAreionSoEM512HashWithKey(key64)
		s, err := SeedFromComponents512(h, comps...)
		if err != nil {
			t.Fatal(err)
		}
		s.BatchHash = bh
		return s
	}
	makeGeneric512Seed := func() *Seed512 {
		s, err := SeedFromComponents512(testHash512, comps...)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	ilNonce := make([]byte, 16)
	for i := range ilNonce {
		ilNonce[i] = byte(i + 1)
	}

	for _, primName := range []string{"areion512", "generic512"} {
		t.Run(primName, func(t *testing.T) {
			var seed *Seed512
			if primName == "areion512" {
				seed = makeAreionSeed()
			} else {
				seed = makeGeneric512Seed()
			}

			for _, L := range lengths {
				msg := make([]byte, L)
				for i := range msg {
					msg[i] = byte(rng.Intn(256))
				}
				laneLen := tripleLaneLen168(L)
				var ref1, ref2, ref3 []byte

				for _, workers := range []int{1, 2, 4, 8} {
					cfg := &Config{
						NonceBits:   DefaultNonceBits,
						BarrierFill: DefaultBarrierFill,
						MaxWorkers:  workers,
						Interlock:   Interlock168,
					}
					r1 := make([]byte, laneLen)
					r2 := make([]byte, laneLen)
					r3 := make([]byte, laneLen)

					bpEnc := buildLockBatchPRF48_512(seed, ilNonce)
					splitForTriple168LockedInto(cfg, msg, bpEnc, r1, r2, r3)

					if workers == 1 {
						ref1 = append([]byte(nil), r1...)
						ref2 = append([]byte(nil), r2...)
						ref3 = append([]byte(nil), r3...)
					} else if !bytes.Equal(r1, ref1) || !bytes.Equal(r2, ref2) || !bytes.Equal(r3, ref3) {
						t.Fatalf("prim=%s workers=%d len=%d: lane output differs from MaxWorkers=1", primName, workers, L)
					}

					bpDec := buildLockBatchPRF48_512(seed, ilNonce)
					got := interleaveForTriple168LockedCfg(cfg, r1, r2, r3, bpDec)
					if !bytes.Equal(got, msg) {
						t.Fatalf("prim=%s workers=%d len=%d: round-trip mismatch", primName, workers, L)
					}

					// In-place caller staging fast path: len(dst)==1 && cap(dst) >= M*21.
					M := len(r1) / 7
					staging := make([]byte, 1, M*21+16)
					bpFast := buildLockBatchPRF48_512(seed, ilNonce)
					gotFast := interleaveForTriple168LockedCfgInto(cfg, staging, r1, r2, r3, bpFast)
					if !bytes.Equal(gotFast, msg) {
						t.Fatalf("prim=%s workers=%d len=%d: fast-path round-trip mismatch", primName, workers, L)
					}
				}
			}

			// Verify all 4 cascade fill tiers produce identical lane bytes on L=512 (M=25 > 8).
			msg512 := make([]byte, 512)
			for i := range msg512 {
				msg512[i] = byte(i*37 + 11)
			}
			laneLen := tripleLaneLen168(len(msg512))
			var refR1, refR2, refR3 []byte
			for tier := 0; tier < 4; tier++ {
				bp := buildLockBatchPRF48_512(seed, ilNonce)
				switch tier {
				case 1:
					bp.fillRanksSuper32 = nil
				case 2:
					bp.fillRanksSuper32 = nil
					bp.fillRanksSuper = nil
				case 3:
					bp.fillRanksSuper32 = nil
					bp.fillRanksSuper = nil
					bp.fillRanksX4 = nil
				}
				r1 := make([]byte, laneLen)
				r2 := make([]byte, laneLen)
				r3 := make([]byte, laneLen)
				cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: 1, Interlock: Interlock168}
				splitForTriple168LockedInto(cfg, msg512, bp, r1, r2, r3)
				if tier == 0 {
					refR1, refR2, refR3 = r1, r2, r3
				} else if !bytes.Equal(r1, refR1) || !bytes.Equal(r2, refR2) || !bytes.Equal(r3, refR3) {
					t.Fatalf("prim=%s tier=%d: lane output differs from tier 0", primName, tier)
				}
			}

			// Plausible decryption with unequal / non-multiple-of-7 lane lengths must not panic.
			cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: 2, Interlock: Interlock168}
			bpPlaus := buildLockBatchPRF48_512(seed, ilNonce)
			_ = interleaveForTriple168LockedCfg(cfg, []byte{1, 2, 3}, []byte{4, 5, 6, 7, 8, 9, 10, 11}, []byte{12}, bpPlaus)
		})
	}
}

// TestEncryptDecrypt3x512Interlock168 tests end-to-end single-message,
// byte-slice streaming, and io.Reader/io.Writer streaming encryption and
// decryption under Config{Interlock: "168"}, Blob512 persistence, and
// rejection of Interlock: "168" on 128-bit and 256-bit entry points.
func TestEncryptDecrypt3x512Interlock168(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0x16805))
	makeSeed512 := func() ([64]byte, *Seed512) {
		var k [64]byte
		for i := range k {
			k[i] = byte(rng.Intn(256))
		}
		comps := make([]uint64, 16)
		for i := range comps {
			comps[i] = rng.Uint64() | 1
		}
		h, bh := MakeAreionSoEM512HashWithKey(k)
		s, err := SeedFromComponents512(h, comps...)
		if err != nil {
			t.Fatal(err)
		}
		s.BatchHash = bh
		return k, s
	}

	keyN, ns := makeSeed512()
	keyL, ls := makeSeed512()
	keyD1, ds1 := makeSeed512()
	keyD2, ds2 := makeSeed512()
	keyD3, ds3 := makeSeed512()
	keyS1, ss1 := makeSeed512()
	keyS2, ss2 := makeSeed512()
	keyS3, ss3 := makeSeed512()

	macSecret := make([]byte, 32)
	if _, err := rand.Read(macSecret); err != nil {
		t.Fatal(err)
	}
	macFunc := func(msg []byte) []byte {
		h := hmac.New(sha256.New, macSecret)
		h.Write(msg)
		return h.Sum(nil)
	}

	cfg := &Config{
		NonceBits:   DefaultNonceBits,
		BarrierFill: DefaultBarrierFill,
		MaxWorkers:  2,
		Interlock:   Interlock168,
	}

	for _, msgLen := range []int{1, 21, 100, 1024} {
		msg := make([]byte, msgLen)
		for i := range msg {
			msg[i] = byte(rng.Intn(256))
		}

		// 1. Unauthenticated single-message Encrypt3x512Cfg / Decrypt3x512Cfg.
		ct, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg)
		if err != nil {
			t.Fatalf("Encrypt3x512Cfg(len=%d): %v", msgLen, err)
		}
		pt, err := Decrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
		if err != nil {
			t.Fatalf("Decrypt3x512Cfg(len=%d): %v", msgLen, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("Encrypt3x512Cfg(len=%d): round-trip mismatch", msgLen)
		}

		// 2. Authenticated single-message EncryptAuthenticated3x512Cfg / DecryptAuthenticated3x512Cfg.
		act, err := EncryptAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg, macFunc)
		if err != nil {
			t.Fatalf("EncryptAuthenticated3x512Cfg(len=%d): %v", msgLen, err)
		}
		apt, err := DecryptAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, act, macFunc)
		if err != nil {
			t.Fatalf("DecryptAuthenticated3x512Cfg(len=%d): %v", msgLen, err)
		}
		if !bytes.Equal(apt, msg) {
			t.Fatalf("EncryptAuthenticated3x512Cfg(len=%d): round-trip mismatch", msgLen)
		}

		// 3. Unauthenticated byte-slice stream EncryptStream3x512Cfg / DecryptStream3x512Cfg.
		var sct bytes.Buffer
		if err := EncryptStream3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg, 256, func(chunk []byte) error {
			_, err := sct.Write(chunk)
			return err
		}); err != nil {
			t.Fatalf("EncryptStream3x512Cfg(len=%d): %v", msgLen, err)
		}
		var spt bytes.Buffer
		if err := DecryptStream3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, sct.Bytes(), func(chunk []byte) error {
			_, err := spt.Write(chunk)
			return err
		}); err != nil {
			t.Fatalf("DecryptStream3x512Cfg(len=%d): %v", msgLen, err)
		}
		if !bytes.Equal(spt.Bytes(), msg) {
			t.Fatalf("EncryptStream3x512Cfg(len=%d): round-trip mismatch", msgLen)
		}

		// 4. Authenticated byte-slice stream EncryptStreamAuth3x512Cfg / DecryptStreamAuth3x512Cfg.
		var asct bytes.Buffer
		if err := EncryptStreamAuth3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg, 256, macFunc, func(chunk []byte) error {
			_, err := asct.Write(chunk)
			return err
		}); err != nil {
			t.Fatalf("EncryptStreamAuth3x512Cfg(len=%d): %v", msgLen, err)
		}
		var aspt bytes.Buffer
		if err := DecryptStreamAuth3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, asct.Bytes(), macFunc, func(chunk []byte) error {
			_, err := aspt.Write(chunk)
			return err
		}); err != nil {
			t.Fatalf("DecryptStreamAuth3x512Cfg(len=%d): %v", msgLen, err)
		}
		if !bytes.Equal(aspt.Bytes(), msg) {
			t.Fatalf("EncryptStreamAuth3x512Cfg(len=%d): round-trip mismatch", msgLen)
		}

		// 5. io.Reader / io.Writer streaming EncryptStream3xCfg / DecryptStream3xCfg.
		var wireBuf bytes.Buffer
		if err := EncryptStream3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(msg), &wireBuf, 256); err != nil {
			t.Fatalf("EncryptStream3xCfg(len=%d): %v", msgLen, err)
		}
		var outBuf bytes.Buffer
		if err := DecryptStream3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(wireBuf.Bytes()), &outBuf); err != nil {
			t.Fatalf("DecryptStream3xCfg(len=%d): %v", msgLen, err)
		}
		if !bytes.Equal(outBuf.Bytes(), msg) {
			t.Fatalf("EncryptStream3xCfg(len=%d): round-trip mismatch", msgLen)
		}

		// 6. io.Reader / io.Writer authenticated streaming EncryptStreamAuth3xCfg / DecryptStreamAuth3xCfg.
		wireBuf.Reset()
		outBuf.Reset()
		if err := EncryptStreamAuth3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(msg), &wireBuf, macFunc, 256); err != nil {
			t.Fatalf("EncryptStreamAuth3xCfg(len=%d): %v", msgLen, err)
		}
		if err := DecryptStreamAuth3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(wireBuf.Bytes()), &outBuf, macFunc); err != nil {
			t.Fatalf("DecryptStreamAuth3xCfg(len=%d): %v", msgLen, err)
		}
		if !bytes.Equal(outBuf.Bytes(), msg) {
			t.Fatalf("EncryptStreamAuth3xCfg(len=%d): round-trip mismatch", msgLen)
		}
	}

	// Blob512 export / import round-trip preserving Config.Interlock == "168".
	var b512 Blob512
	rawBlob, err := b512.Export3Cfg(
		cfg,
		keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
		ns, ds1, ds2, ds3, ss1, ss2, ss3,
		Blob512Opts{KeyL: keyL, LS: ls},
	)
	if err != nil {
		t.Fatalf("Blob512.Export3Cfg: %v", err)
	}
	var imp512 Blob512
	var impCfg Config
	if err := imp512.Import3Cfg(rawBlob, &impCfg); err != nil {
		t.Fatalf("Blob512.Import3Cfg: %v", err)
	}
	if impCfg.Interlock != Interlock168 {
		t.Fatalf("Blob512.Import3Cfg: got Interlock=%q, want %q", impCfg.Interlock, Interlock168)
	}

	// Verify 128-bit and 256-bit entry points reject Config{Interlock: "168"}.
	makeS128 := func(base uint64) *Seed128 {
		return &Seed128{Components: []uint64{base, base + 1, base + 2, base + 3}, Hash: sipHash128}
	}
	makeS256 := func(base uint64) *Seed256 {
		return &Seed256{Components: []uint64{base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7}, Hash: testHash256}
	}
	s128 := [8]*Seed128{makeS128(10), makeS128(20), makeS128(30), makeS128(40), makeS128(50), makeS128(60), makeS128(70), makeS128(80)}
	s256 := [8]*Seed256{makeS256(10), makeS256(20), makeS256(30), makeS256(40), makeS256(50), makeS256(60), makeS256(70), makeS256(80)}
	if _, err := Encrypt3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], []byte("x")); err == nil {
		t.Fatal("Encrypt3x128Cfg accepted Interlock=168")
	}
	if _, err := Encrypt3x256Cfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], []byte("x")); err == nil {
		t.Fatal("Encrypt3x256Cfg accepted Interlock=168")
	}
	if _, err := EncryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], []byte("x"), macFunc); err == nil {
		t.Fatal("EncryptAuthenticated3x128Cfg accepted Interlock=168")
	}
	if _, err := EncryptAuthenticated3x256Cfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], []byte("x"), macFunc); err == nil {
		t.Fatal("EncryptAuthenticated3x256Cfg accepted Interlock=168")
	}
	if err := EncryptStream3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], []byte("x"), 256, func([]byte) error { return nil }); err == nil {
		t.Fatal("EncryptStream3x128Cfg accepted Interlock=168")
	}
	if err := EncryptStream3x256Cfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], []byte("x"), 256, func([]byte) error { return nil }); err == nil {
		t.Fatal("EncryptStream3x256Cfg accepted Interlock=168")
	}
	if err := EncryptStream3xCfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], bytes.NewReader([]byte("x")), new(bytes.Buffer), 256); err == nil {
		t.Fatal("EncryptStream3xCfg(128) accepted Interlock=168")
	}
	if err := EncryptStream3xCfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], bytes.NewReader([]byte("x")), new(bytes.Buffer), 256); err == nil {
		t.Fatal("EncryptStream3xCfg(256) accepted Interlock=168")
	}
	var b128 Blob128
	var k16 [16]byte
	if _, err := b128.Export3Cfg(cfg, k16[:], k16[:], k16[:], k16[:], k16[:], k16[:], k16[:], s128[0], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7]); err == nil {
		t.Fatal("Blob128.Export3Cfg accepted Interlock=168")
	}
	var b256 Blob256
	var k32 [32]byte
	if _, err := b256.Export3Cfg(cfg, k32, k32, k32, k32, k32, k32, k32, s256[0], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7]); err == nil {
		t.Fatal("Blob256.Export3Cfg accepted Interlock=168")
	}
}

// TestInterlock168StackZeroization verifies that splitForTriple168LockedInto,
// interleaveForTriple168LockedCfg, and wipeInterlockWorker168 scrub all
// intermediate 512-bit rank words and combinadic mask state from the stack.
func TestInterlock168StackZeroization(t *testing.T) {
	ws := new(interlockWorkerScratch168)
	ws.buf[0] = 0x03
	for i := range ws.prf {
		ws.prf[i] = uint64(i) + 1
	}
	ws.scratch.out32x512[7][7] = 9
	ws.masks[0][0][0] = 1
	ws.idx0_8[0][0] = 2
	ws.idx1_8[0][0] = 3
	ws.out8[0][0][0] = 4
	wipeInterlockWorker168(ws)
	if ws.buf != ([13]byte{}) || ws.scratch.out32x512 != ([8][8]uint64{}) ||
		ws.prf != ([superChunks168 * 8]uint64{}) ||
		ws.masks != ([superChunks168][3][3]uint64{}) ||
		ws.idx0_8 != ([3][8]uint64{}) ||
		ws.idx1_8 != ([2][8]uint64{}) ||
		ws.out8 != ([3][3][8]uint64{}) {
		t.Fatal("wipeInterlockWorker168 did not zero worker scratch")
	}

	rng := mathrand.New(mathrand.NewSource(0x168168))
	s512 := &Seed512{
		Components: make([]uint64, 16),
		Hash: func(data []byte, s [8]uint64) [8]uint64 {
			d := uint64(binary.LittleEndian.Uint64(data[:8]))
			var out [8]uint64
			for j := 0; j < 8; j++ {
				out[j] = (s[j] ^ d ^ 0xA5A5A5A55A5A5A5A) * (0x9E3779B97F4A7C15 + uint64(j)*2)
			}
			return simInterlockHash512DeepStack(out)
		},
	}
	for i := range s512.Components {
		s512.Components[i] = rng.Uint64() | 1
	}
	ilNonce := make([]byte, 32)
	for i := range ilNonce {
		ilNonce[i] = byte(rng.Intn(256))
	}

	plain := make([]byte, 9*21) // 9 chunks of 168 bits
	for i := range plain {
		plain[i] = byte(rng.Intn(256))
	}
	laneLen := tripleLaneLen168(len(plain))
	r1 := make([]byte, laneLen)
	r2 := make([]byte, laneLen)
	r3 := make([]byte, laneLen)
	src := framedSrc168{body: plain}
	M := src.chunkCount()

	bpRef := buildLockBatchPRF48_512(s512, ilNonce)
	secrets := make(map[uint64]string)
	for i, w := range s512.Components {
		if w != 0 {
			secrets[w] = fmt.Sprintf("seedComp[%d]", i)
		}
	}
	for g := 0; g < M; g++ {
		var rankWords [8]uint64
		var buf [13]byte
		bpRef.fillRanks(buf[:], uint64(g), rankWords[:])
		for i, w := range rankWords {
			if w != 0 {
				secrets[w] = fmt.Sprintf("rankWords168[g=%d,i=%d]", g, i)
			}
		}
		idx0, idx1 := splitRank168(rankWords)
		for i, w := range idx0 {
			if w != 0 {
				secrets[w] = fmt.Sprintf("idx0[g=%d,i=%d]", g, i)
			}
		}
		for i, w := range idx1 {
			if w != 0 {
				secrets[w] = fmt.Sprintf("idx1[g=%d,i=%d]", g, i)
			}
		}
		m0, m1, m2 := rankToMaskTriple168(rankWords)
		for i, m := range [3][3]uint64{m0, m1, m2} {
			for j, w := range m {
				if w != 0 {
					secrets[w] = fmt.Sprintf("mask[g=%d,l=%d,w=%d]", g, i, j)
				}
			}
		}
	}
	bpRef.wipe()

	// Negative control: calling splitTriple168WorkerBody directly without wipePixelCallStack leaves rankWords on the stack.
	bpNeg := buildLockBatchPRF48_512(s512, ilNonce)
	resNeg := pxStackResidue(func() {
		splitTriple168WorkerBody(0, M, M, src, r1, r2, r3, bpNeg)
	})
	bpNeg.wipe()
	if pxResidueHits(resNeg, secrets) == 0 {
		t.Fatal("negative control failed: pxStackResidue did not detect unwiped rankWords in splitTriple168WorkerBody")
	}

	for _, workers := range []int{1, 4} {
		cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: workers, Interlock: Interlock168}
		bpSplit := buildLockBatchPRF48_512(s512, ilNonce)
		resSplit := pxStackResidue(func() {
			splitForTriple168LockedInto(cfg, plain, bpSplit, r1, r2, r3)
		})
		bpSplit.wipe()
		assertNoPixelSecretResidue(t, fmt.Sprintf("splitForTriple168LockedInto/W=%d", workers), resSplit, secrets)

		bpJoin := buildLockBatchPRF48_512(s512, ilNonce)
		resJoin := pxStackResidue(func() {
			out := interleaveForTriple168LockedCfg(cfg, r1, r2, r3, bpJoin)
			clear(out)
		})
		assertNoPixelSecretResidue(t, fmt.Sprintf("interleaveForTriple168LockedCfg/W=%d", workers), resJoin, secrets)
	}
}

func TestInterlock168ZeroAllocs(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(16842))
	var r [8]uint64
	for i := range r {
		r[i] = rng.Uint64() | 1
	}
	var prf [64]uint64
	for i := range prf {
		prf[i] = rng.Uint64() | 1
	}
	var masks [superChunks168][3][3]uint64
	var ws interlockWorkerScratch168
	fillLockMasksTriple168SuperWS(&ws, &prf, 8, &masks)

	srcBytes := make([]byte, 21*8)
	dstBytes := make([]byte, 21*8)
	p0 := make([]byte, 7*8)
	p1 := make([]byte, 7*8)
	p2 := make([]byte, 7*8)
	fSrc := framedSrc168{body: srcBytes}
	x := [3]uint64{1, 2, 3}
	m0, m1, m2 := masks[0][0], masks[0][1], masks[0][2]

	if a := testing.AllocsPerRun(100, func() {
		_, _ = splitRank168(r)
	}); a != 0 {
		t.Fatalf("splitRank168 allocs = %v, want 0", a)
	}
	if a := testing.AllocsPerRun(100, func() {
		_, _, _ = rankToMaskTriple168(r)
	}); a != 0 {
		t.Fatalf("rankToMaskTriple168 allocs = %v, want 0", a)
	}
	if a := testing.AllocsPerRun(100, func() {
		fillLockMasksTriple168SuperWS(&ws, &prf, 8, &masks)
	}); a != 0 {
		t.Fatalf("fillLockMasksTriple168SuperWS allocs = %v, want 0", a)
	}
	if a := testing.AllocsPerRun(100, func() {
		l0, l1, l2 := chunk168lock(x, m0, m1, m2)
		_ = unchunk168lock(l0, l1, l2, m0, m1, m2)
	}); a != 0 {
		t.Fatalf("chunk168lock/unchunk168lock allocs = %v, want 0", a)
	}
	if a := testing.AllocsPerRun(100, func() {
		chunk168lockBatch(fSrc, 8, 0, 8, masks[:], p0, p1, p2)
		unchunk168lockBatch(dstBytes, 8, 0, 8, masks[:], p0, p1, p2)
	}); a != 0 {
		t.Fatalf("chunk168lockBatch/unchunk168lockBatch allocs = %v, want 0", a)
	}
	wipeInterlockWorker168(&ws)

	// Verify steady-state bufferPool zero-regrow for 168-bit Interlock encrypt/decrypt.
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)
	runtime.GC()
	runtime.GC()
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)

	var s512 [8]*Seed512
	for idx := range s512 {
		var k [64]byte
		for j := range k {
			k[j] = byte(rng.Intn(256))
		}
		comps := make([]uint64, 16)
		for j := range comps {
			comps[j] = rng.Uint64() | 1
		}
		h, bh := MakeAreionSoEM512HashWithKey(k)
		seed, err := SeedFromComponents512(h, comps...)
		if err != nil {
			t.Fatal(err)
		}
		seed.BatchHash = bh
		s512[idx] = seed
	}
	cfg := &Config{MaxWorkers: 1, Interlock: Interlock168}
	var macKey [32]byte
	macFn := func(msg []byte) []byte {
		mac := hmac.New(sha256.New, macKey[:])
		mac.Write(msg)
		return mac.Sum(nil)
	}
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	for i := 0; i < 2; i++ {
		wire, err := EncryptAuthenticated3x512Cfg(cfg, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], payload, macFn)
		if err != nil {
			t.Fatalf("warmup encrypt: %v", err)
		}
		plain, err := DecryptAuthenticated3x512Cfg(cfg, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], wire, macFn)
		if err != nil {
			t.Fatalf("warmup decrypt: %v", err)
		}
		if len(plain) != len(payload) {
			t.Fatalf("plain len = %d, want %d", len(plain), len(payload))
		}
	}

	before := poolstats.Take()
	for i := 0; i < 5; i++ {
		wire, err := EncryptAuthenticated3x512Cfg(cfg, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], payload, macFn)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		plain, err := DecryptAuthenticated3x512Cfg(cfg, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], wire, macFn)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if len(plain) != len(payload) {
			t.Fatalf("plain len = %d, want %d", len(plain), len(payload))
		}
	}
	after := poolstats.Take()
	regrowExisting := int64(after.BufRegrow-before.BufRegrow) - int64(after.BufNew-before.BufNew)
	if regrowExisting > 0 {
		t.Fatalf("pooled buffer regrew %d times in steady state (BufRegrow %d -> %d, BufNew %d -> %d)",
			regrowExisting, before.BufRegrow, after.BufRegrow, before.BufNew, after.BufNew)
	}
}

var (
	hostAVX512_168 = interlock.HasAVX512RankMask
	hostAVX2_168   = interlock.HasBMI2 && (interlock.HasAVX2RankMask || interlock.HasAVX512RankMask)
	hostBMI2_168   = interlock.HasBMI2
	hostBatch168   = interlock.HasChunk168Batch
	hostNEON168    = interlock.HasNEONInterlock
	hostSVE2168    = interlock.HasSVE2Interlock
)

type interlock168Tier struct {
	name   string
	avx512 bool
	avx2   bool
	bmi2   bool
	batch  bool
	neon   bool
	sve2   bool
}

func runnableInterlock168Tiers() []interlock168Tier {
	tiers := []interlock168Tier{{name: "scalar"}}
	if hostAVX2_168 {
		tiers = append(tiers, interlock168Tier{name: "avx2", avx2: true, bmi2: true, batch: false})
	}
	if hostAVX512_168 {
		tiers = append(tiers, interlock168Tier{name: "avx512", avx512: true, bmi2: true, batch: true})
	}
	if hostNEON168 {
		tiers = append(tiers, interlock168Tier{name: "neon", batch: true, neon: true})
	}
	if hostSVE2168 {
		tiers = append(tiers, interlock168Tier{name: "sve2", batch: true, neon: true, sve2: true})
	}
	return tiers
}

func setInterlock168Tier(tb testing.TB, tier interlock168Tier) {
	tb.Helper()
	saved512 := interlock.HasAVX512RankMask
	saved2 := interlock.HasAVX2RankMask
	savedBMI2 := interlock.HasBMI2
	savedBatch := interlock.HasChunk168Batch
	savedNEON := interlock.HasNEONInterlock
	savedSVE2 := interlock.HasSVE2Interlock
	interlock.HasAVX512RankMask = tier.avx512
	interlock.HasAVX2RankMask = tier.avx2
	interlock.HasBMI2 = tier.bmi2
	interlock.HasChunk168Batch = tier.batch
	interlock.HasNEONInterlock = tier.neon
	interlock.HasSVE2Interlock = tier.sve2
	tb.Cleanup(func() {
		interlock.HasAVX512RankMask = saved512
		interlock.HasAVX2RankMask = saved2
		interlock.HasBMI2 = savedBMI2
		interlock.HasChunk168Batch = savedBatch
		interlock.HasNEONInterlock = savedNEON
		interlock.HasSVE2Interlock = savedSVE2
	})
}

func tierTestRank168(i int) [8]uint64 {
	switch i {
	case 0:
		return [8]uint64{}
	case 1:
		const m = ^uint64(0)
		return [8]uint64{m, m, m, m, m, m, m, m}
	}
	var out [8]uint64
	for j := range out {
		out[j] = uint64(i*8+j+1) * 0x9E3779B97F4A7C15
	}
	return out
}

// TestChunk168LockTierParity verifies that the BMI2 PEXTQ/PDEPQ per-chunk
// and batched kernels and the pure-Go softPEXT168/softPDEP168 fallback
// produce identical lane splits and round-trip every 168-bit input under
// identical mask triples.
func TestChunk168LockTierParity(t *testing.T) {
	if !interlock.HasBMI2 && !interlock.HasChunk168Batch {
		t.Skip("host lacks hardware chunk168 kernels; scalar arm is the only runnable path")
	}
	srcBatch := make([]byte, 21*superChunks168)
	var masksBatch [superChunks168][3][3]uint64
	for i := 0; i < 16; i++ {
		r := tierTestRank168(i)
		m0, m1, m2 := rankToMaskTriple168(r)
		x := [3]uint64{
			uint64(i)*0xD1B54A32D192ED03 + 0x0123456789ABCDEF,
			uint64(i)*0x9E3779B97F4A7C15 + 0xFEDCBA9876543210,
			(uint64(i)*0xC2B2AE3D27D4EB4F + 0x1122334455) & domain168_2,
		}
		if i < superChunks168 {
			writeChunk168(srcBatch, 21*i, x)
			masksBatch[i] = [3][3]uint64{m0, m1, m2}
		}

		setInterlock168Tier(t, interlock168Tier{name: "scalar"})
		wantL0, wantL1, wantL2 := chunk168lock(x, m0, m1, m2)
		if got := unchunk168lock(wantL0, wantL1, wantL2, m0, m1, m2); got != x {
			t.Fatalf("rank %d: scalar roundtrip: got %#x, want %#x", i, got, x)
		}

		for _, tier := range runnableInterlock168Tiers() {
			if tier.name == "scalar" {
				continue
			}
			setInterlock168Tier(t, tier)
			gotL0, gotL1, gotL2 := chunk168lock(x, m0, m1, m2)
			if gotL0 != wantL0 || gotL1 != wantL1 || gotL2 != wantL2 {
				t.Fatalf("rank %d tier %s: lanes (%#x,%#x,%#x) diverge from scalar (%#x,%#x,%#x)",
					i, tier.name, gotL0, gotL1, gotL2, wantL0, wantL1, wantL2)
			}
			if got := unchunk168lock(gotL0, gotL1, gotL2, m0, m1, m2); got != x {
				t.Fatalf("rank %d tier %s: roundtrip: got %#x, want %#x", i, tier.name, got, x)
			}
		}
	}

	// Verify batched chunk apply against scalar per-chunk reference.
	wantP0 := make([]byte, 7*superChunks168)
	wantP1 := make([]byte, 7*superChunks168)
	wantP2 := make([]byte, 7*superChunks168)
	setInterlock168Tier(t, interlock168Tier{name: "scalar"})
	for k := 0; k < superChunks168; k++ {
		x := readChunk168(srcBatch, 21*k)
		l0, l1, l2 := chunk168lock(x, masksBatch[k][0], masksBatch[k][1], masksBatch[k][2])
		writeLane56(wantP0, 7*k, l0)
		writeLane56(wantP1, 7*k, l1)
		writeLane56(wantP2, 7*k, l2)
	}
	for _, tier := range runnableInterlock168Tiers() {
		if !tier.batch {
			continue
		}
		setInterlock168Tier(t, tier)
		gotP0 := make([]byte, 7*superChunks168)
		gotP1 := make([]byte, 7*superChunks168)
		gotP2 := make([]byte, 7*superChunks168)
		if !chunk168lockBatch(framedSrc168{body: srcBatch}, superChunks168, 0, superChunks168, masksBatch[:], gotP0, gotP1, gotP2) {
			t.Fatalf("tier %s: chunk168lockBatch returned false", tier.name)
		}
		if !bytes.Equal(gotP0, wantP0) || !bytes.Equal(gotP1, wantP1) || !bytes.Equal(gotP2, wantP2) {
			t.Fatalf("tier %s: chunk168lockBatch lanes diverge from scalar reference", tier.name)
		}
		gotBack := make([]byte, 21*superChunks168)
		if !unchunk168lockBatch(gotBack, superChunks168, 0, superChunks168, masksBatch[:], gotP0, gotP1, gotP2) {
			t.Fatalf("tier %s: unchunk168lockBatch returned false", tier.name)
		}
		if !bytes.Equal(gotBack, srcBatch) {
			t.Fatalf("tier %s: unchunk168lockBatch roundtrip mismatch", tier.name)
		}
	}
}

// TestFillLockMasksTriple168SuperTierParity verifies the superblock-wide
// 168-bit mask derivation across every runnable dispatch arm at every chunk
// count 1..superChunks168, including short-superblock tails.
func TestFillLockMasksTriple168SuperTierParity(t *testing.T) {
	var prf [8 * superChunks168]uint64
	for j := 0; j < superChunks168; j++ {
		r := tierTestRank168(j)
		copy(prf[8*j:8*(j+1)], r[:])
	}
	for count := 1; count <= superChunks168; count++ {
		setInterlock168Tier(t, interlock168Tier{name: "scalar"})
		var want [superChunks168][3][3]uint64
		fillLockMasksTriple168Super(&prf, count, &want)
		for j := 0; j < count; j++ {
			m0, m1, m2 := rankToMaskTriple168(*(*[8]uint64)(prf[8*j : 8*j+8]))
			if want[j] != [3][3]uint64{m0, m1, m2} {
				t.Fatalf("count %d chunk %d: scalar super batch diverges from rankToMaskTriple168", count, j)
			}
		}
		for _, tier := range runnableInterlock168Tiers() {
			if tier.name == "scalar" || tier.name == "sve2" {
				continue
			}
			tier := tier
			t.Run(fmt.Sprintf("count=%d/%s", count, tier.name), func(t *testing.T) {
				setInterlock168Tier(t, tier)
				var got [superChunks168][3][3]uint64
				fillLockMasksTriple168Super(&prf, count, &got)
				if got != want {
					t.Fatalf("count %d: %s arm diverges from scalar reference:\n got %#x\nwant %#x",
						count, tier.name, got, want)
				}
			})
		}
	}
}

// TestInterlock168ArmsAgreeAndGolden runs the 168-bit superblock split and
// interleave under every runnable dispatch tier and pins every tier's lane
// bytes to the scalar tier and to fixed SHA-256 golden digests across sizes
// straddling the 21-byte chunk and 8-chunk superblock boundaries.
func TestInterlock168ArmsAgreeAndGolden(t *testing.T) {
	ls512, err := SeedFromComponents512(testHash512, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	bp := buildLockBatchPRF48_512(ls512, superTestNonce)
	defer bp.wipe()

	golden := map[int]string{
		168:  "d800594976e58d5192ea28acbcb0404c9667a6970ca0b419b00193bb5dae1d6c",
		1000: "1dedb68f3e9c6cfbe64676d03d10bd78a5b665fcb879dec259b73361189b5ce4",
	}
	sizes := []int{1, 21, 41, 42, 43, 143, 167, 168, 169, 189, 336, 357, 1000}

	ref := make(map[int][3][]byte, len(sizes))
	func() {
		setInterlock168Tier(t, interlock168Tier{name: "scalar"})
		for _, sz := range sizes {
			src := framedSrc168{body: superTestFixedData(sz)}
			M := src.chunkCount()
			p0, p1, p2 := make([]byte, 7*M), make([]byte, 7*M), make([]byte, 7*M)
			splitTriple168LockedBatchInto(src, p0, p1, p2, bp, nil)
			ref[sz] = [3][]byte{p0, p1, p2}
		}
	}()

	for _, tier := range runnableInterlock168Tiers() {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			setInterlock168Tier(t, tier)
			for _, sz := range sizes {
				framed := superTestFixedData(sz)
				src := framedSrc168{body: framed}
				M := src.chunkCount()
				p0, p1, p2 := make([]byte, 7*M), make([]byte, 7*M), make([]byte, 7*M)
				splitTriple168LockedBatchInto(src, p0, p1, p2, bp, nil)
				r := ref[sz]
				if !bytes.Equal(p0, r[0]) || !bytes.Equal(p1, r[1]) || !bytes.Equal(p2, r[2]) {
					t.Fatalf("size=%d: tier %s lane bytes diverge from scalar tier", sz, tier.name)
				}
				if want, ok := golden[sz]; ok {
					h := sha256.New()
					h.Write(p0)
					h.Write(p1)
					h.Write(p2)
					if got := hex.EncodeToString(h.Sum(nil)); got != want {
						t.Fatalf("size=%d: tier %s golden digest %s, want %s", sz, tier.name, got, want)
					}
				}
				out := interleaveTriple168LockedBatch(p0, p1, p2, bp, nil)
				if !bytes.Equal(out[:sz], framed) {
					t.Fatalf("size=%d: tier %s does not round-trip", sz, tier.name)
				}
			}
		})
	}
}

// BenchmarkSplitRank168 measures the Barrett reciprocal splitRank168
// reduction against the big.Int reference on 8 512-bit ranks per iteration.
func BenchmarkSplitRank168(b *testing.B) {
	rng := mathrand.New(mathrand.NewSource(16850))
	var ranks [8][8]uint64
	for j := range ranks {
		for w := range ranks[j] {
			ranks[j][w] = rng.Uint64()
		}
	}
	var sink uint64
	b.Run("reciprocal", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				i0, i1 := splitRank168(ranks[j])
				sink += i0[0] + i1[0]
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/rank")
	})
	b.Run("bigint", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				i0, i1 := splitRank168Big(ranks[j])
				sink += i0[0] + i1[0]
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/rank")
	})
	_ = sink
}

// BenchmarkRankToMaskTriple168 measures the superblock mask derivation
// (splitRank168 + 8-lane unrank) across all runnable tiers.
func BenchmarkRankToMaskTriple168(b *testing.B) {
	rng := mathrand.New(mathrand.NewSource(168))
	var prf [64]uint64
	for i := range prf {
		prf[i] = rng.Uint64()
	}
	for _, tier := range runnableInterlock168Tiers() {
		if tier.name == "sve2" {
			continue
		}
		tier := tier
		b.Run(tier.name, func(b *testing.B) {
			setInterlock168Tier(b, tier)
			var ws interlockWorkerScratch168
			var masks [superChunks168][3][3]uint64
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fillLockMasksTriple168SuperWS(&ws, &prf, 8, &masks)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/triple")
			wipeInterlockWorker168(&ws)
		})
	}
}

// BenchmarkChunk168Lock measures forward 168-bit chunk splitting over an
// 8-chunk superblock across the batched, per-chunk BMI2, and scalar softPEXT168
// paths.
func BenchmarkChunk168Lock(b *testing.B) {
	src := make([]byte, 21*8)
	for i := range src {
		src[i] = byte(i*37 + 11)
	}
	p0 := make([]byte, 7*8)
	p1 := make([]byte, 7*8)
	p2 := make([]byte, 7*8)
	var masks [8][3][3]uint64
	for k := 0; k < 8; k++ {
		r := tierTestRank168(k + 2)
		m0, m1, m2 := rankToMaskTriple168(r)
		masks[k] = [3][3]uint64{m0, m1, m2}
	}
	fSrc := framedSrc168{body: src}
	if hostBatch168 {
		b.Run("batch", func(b *testing.B) {
			b.SetBytes(8 * 21)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				chunk168lockBatch(fSrc, 8, 0, 8, masks[:], p0, p1, p2)
			}
		})
	}
	if hostBMI2_168 {
		b.Run("perchunk-bmi2", func(b *testing.B) {
			setInterlock168Tier(b, interlock168Tier{name: "bmi2", bmi2: true})
			b.SetBytes(8 * 21)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for k := 0; k < 8; k++ {
					x := readChunk168(src, 21*k)
					l0, l1, l2 := chunk168lock(x, masks[k][0], masks[k][1], masks[k][2])
					writeLane56(p0, 7*k, l0)
					writeLane56(p1, 7*k, l1)
					writeLane56(p2, 7*k, l2)
				}
			}
		})
	}
	b.Run("scalar-soft", func(b *testing.B) {
		setInterlock168Tier(b, interlock168Tier{name: "scalar"})
		b.SetBytes(8 * 21)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for k := 0; k < 8; k++ {
				x := readChunk168(src, 21*k)
				l0, l1, l2 := chunk168lock(x, masks[k][0], masks[k][1], masks[k][2])
				writeLane56(p0, 7*k, l0)
				writeLane56(p1, 7*k, l1)
				writeLane56(p2, 7*k, l2)
			}
		}
	})
}

// BenchmarkUnchunk168Lock is the inverse counterpart of BenchmarkChunk168Lock.
func BenchmarkUnchunk168Lock(b *testing.B) {
	src := make([]byte, 21*8)
	for i := range src {
		src[i] = byte(i*37 + 11)
	}
	p0 := make([]byte, 7*8)
	p1 := make([]byte, 7*8)
	p2 := make([]byte, 7*8)
	dst := make([]byte, 21*8)
	var masks [8][3][3]uint64
	for k := 0; k < 8; k++ {
		r := tierTestRank168(k + 2)
		m0, m1, m2 := rankToMaskTriple168(r)
		masks[k] = [3][3]uint64{m0, m1, m2}
		x := readChunk168(src, 21*k)
		l0, l1, l2 := chunk168lock(x, m0, m1, m2)
		writeLane56(p0, 7*k, l0)
		writeLane56(p1, 7*k, l1)
		writeLane56(p2, 7*k, l2)
	}
	if hostBatch168 {
		b.Run("batch", func(b *testing.B) {
			b.SetBytes(8 * 21)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				unchunk168lockBatch(dst, 8, 0, 8, masks[:], p0, p1, p2)
			}
		})
	}
	if hostBMI2_168 {
		b.Run("perchunk-bmi2", func(b *testing.B) {
			setInterlock168Tier(b, interlock168Tier{name: "bmi2", bmi2: true})
			b.SetBytes(8 * 21)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for k := 0; k < 8; k++ {
					l0 := readLane56(p0, 7*k)
					l1 := readLane56(p1, 7*k)
					l2 := readLane56(p2, 7*k)
					x := unchunk168lock(l0, l1, l2, masks[k][0], masks[k][1], masks[k][2])
					writeChunk168(dst, 21*k, x)
				}
			}
		})
	}
	b.Run("scalar-soft", func(b *testing.B) {
		setInterlock168Tier(b, interlock168Tier{name: "scalar"})
		b.SetBytes(8 * 21)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for k := 0; k < 8; k++ {
				l0 := readLane56(p0, 7*k)
				l1 := readLane56(p1, 7*k)
				l2 := readLane56(p2, 7*k)
				x := unchunk168lock(l0, l1, l2, masks[k][0], masks[k][1], masks[k][2])
				writeChunk168(dst, 21*k, x)
			}
		}
	})
}

// BenchmarkSplitForTriple168 measures end-to-end 168-bit interlock splitting
// across {Areion512, BLAKE2b512} × {4KB, 64KB, 1MB} × {W1, WMax}.
func BenchmarkSplitForTriple168(b *testing.B) {
	prims := []struct {
		name string
		make func(testing.TB, int) *Seed512
	}{
		{"Areion512", makeAreion512BenchSeed},
		{"BLAKE2b512", makeBlake2b512BenchSeed},
	}
	sizes := []struct {
		name string
		n    int
	}{
		{"4KB", 4096},
		{"64KB", 65536},
		{"1MB", 1 << 20},
	}
	workers := []struct {
		name string
		w    int
	}{
		{"W1", 1},
		{"WMax", runtime.NumCPU()},
	}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	for _, prim := range prims {
		prim := prim
		b.Run(prim.name, func(b *testing.B) {
			seed := prim.make(b, 512)
			bp := buildLockBatchPRF48_512(seed, nonce)
			defer bp.wipe()
			for _, sz := range sizes {
				sz := sz
				b.Run(sz.name, func(b *testing.B) {
					msg := make([]byte, sz.n)
					for i := range msg {
						msg[i] = byte(i)
					}
					laneLen := tripleLaneLen168(sz.n)
					r1 := make([]byte, laneLen)
					r2 := make([]byte, laneLen)
					r3 := make([]byte, laneLen)
					for _, wk := range workers {
						wk := wk
						b.Run(wk.name, func(b *testing.B) {
							cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: wk.w, Interlock: Interlock168}
							b.SetBytes(int64(sz.n))
							b.ReportAllocs()
							b.ResetTimer()
							for i := 0; i < b.N; i++ {
								splitForTriple168LockedInto(cfg, msg, bp, r1, r2, r3)
							}
						})
					}
				})
			}
		})
	}
}

// BenchmarkInterleaveForTriple168 measures end-to-end 168-bit interlock
// interleaving across {Areion512, BLAKE2b512} × {4KB, 64KB, 1MB} × {W1, WMax}
// using the zero-alloc caller staging buffer.
func BenchmarkInterleaveForTriple168(b *testing.B) {
	prims := []struct {
		name string
		make func(testing.TB, int) *Seed512
	}{
		{"Areion512", makeAreion512BenchSeed},
		{"BLAKE2b512", makeBlake2b512BenchSeed},
	}
	sizes := []struct {
		name string
		n    int
	}{
		{"4KB", 4096},
		{"64KB", 65536},
		{"1MB", 1 << 20},
	}
	workers := []struct {
		name string
		w    int
	}{
		{"W1", 1},
		{"WMax", runtime.NumCPU()},
	}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	for _, prim := range prims {
		prim := prim
		b.Run(prim.name, func(b *testing.B) {
			seed := prim.make(b, 512)
			bp := buildLockBatchPRF48_512(seed, nonce)
			defer bp.wipe()
			bpNoWipe := bp
			bpNoWipe.lockComps = nil
			for _, sz := range sizes {
				sz := sz
				b.Run(sz.name, func(b *testing.B) {
					msg := make([]byte, sz.n)
					for i := range msg {
						msg[i] = byte(i)
					}
					laneLen := tripleLaneLen168(sz.n)
					r1 := make([]byte, laneLen)
					r2 := make([]byte, laneLen)
					r3 := make([]byte, laneLen)
					cfg1 := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: 1, Interlock: Interlock168}
					splitForTriple168LockedInto(cfg1, msg, bp, r1, r2, r3)
					M := laneLen / 7
					staging := make([]byte, 1, M*21+16)
					for _, wk := range workers {
						wk := wk
						b.Run(wk.name, func(b *testing.B) {
							cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: wk.w, Interlock: Interlock168}
							b.SetBytes(int64(sz.n))
							b.ReportAllocs()
							b.ResetTimer()
							for i := 0; i < b.N; i++ {
								_ = interleaveForTriple168LockedCfgInto(cfg, staging, r1, r2, r3, bpNoWipe)
							}
						})
					}
				})
			}
		})
	}
}

// BenchmarkSplitForTriple168_Tiers compares all runnable 168-bit interlock
// tiers on a 4 KiB payload with Areion512 and MaxWorkers=1.
func BenchmarkSplitForTriple168_Tiers(b *testing.B) {
	seed := makeAreion512BenchSeed(b, 512)
	nonce := make([]byte, 16)
	msg := make([]byte, 4096)
	laneLen := tripleLaneLen168(len(msg))
	r1 := make([]byte, laneLen)
	r2 := make([]byte, laneLen)
	r3 := make([]byte, laneLen)
	cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: 1, Interlock: Interlock168}
	bp := buildLockBatchPRF48_512(seed, nonce)
	defer bp.wipe()
	for _, tier := range runnableInterlock168Tiers() {
		tier := tier
		b.Run(tier.name, func(b *testing.B) {
			setInterlock168Tier(b, tier)
			b.SetBytes(4096)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				splitForTriple168LockedInto(cfg, msg, bp, r1, r2, r3)
			}
		})
	}
}

// BenchmarkInterleaveForTriple168_Tiers compares all runnable 168-bit
// interlock tiers on a 4 KiB payload with Areion512 and MaxWorkers=1.
func BenchmarkInterleaveForTriple168_Tiers(b *testing.B) {
	seed := makeAreion512BenchSeed(b, 512)
	nonce := make([]byte, 16)
	msg := make([]byte, 4096)
	laneLen := tripleLaneLen168(len(msg))
	r1 := make([]byte, laneLen)
	r2 := make([]byte, laneLen)
	r3 := make([]byte, laneLen)
	cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: 1, Interlock: Interlock168}
	bp := buildLockBatchPRF48_512(seed, nonce)
	defer bp.wipe()
	bpNoWipe := bp
	bpNoWipe.lockComps = nil
	splitForTriple168LockedInto(cfg, msg, bp, r1, r2, r3)
	M := laneLen / 7
	staging := make([]byte, 1, M*21+16)
	for _, tier := range runnableInterlock168Tiers() {
		tier := tier
		b.Run(tier.name, func(b *testing.B) {
			setInterlock168Tier(b, tier)
			b.SetBytes(4096)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = interleaveForTriple168LockedCfgInto(cfg, staging, r1, r2, r3, bpNoWipe)
			}
		})
	}
}

func BenchmarkSplitForTriple168_4KB(b *testing.B) {
	s := makeAreion512BenchSeed(b, 512)
	nonce := make([]byte, 16)
	msg := make([]byte, 4096)
	laneLen := tripleLaneLen168(len(msg))
	r1 := make([]byte, laneLen)
	r2 := make([]byte, laneLen)
	r3 := make([]byte, laneLen)
	cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: 1, Interlock: Interlock168}
	bp := buildLockBatchPRF48_512(s, nonce)
	defer bp.wipe()
	b.SetBytes(4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		splitForTriple168LockedInto(cfg, msg, bp, r1, r2, r3)
	}
}
