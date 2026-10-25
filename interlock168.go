package itb

import (
	"encoding/binary"
	"math/bits"
	"runtime"
	"sync"

	"github.com/everanium/itb/internal/interlock"
)

// binomialC168 holds the 3-limb little-endian binomial coefficients C(n, k)
// for 0 <= n <= 168 and 0 <= k <= 56. Since C(168, 56) < 2^151, every entry
// fits in 3 uint64 limbs (192 bits).
var binomialC168 [169][57][3]uint64

func init() {
	for n := 0; n <= 168; n++ {
		binomialC168[n][0] = [3]uint64{1, 0, 0}
		if n <= 56 {
			binomialC168[n][n] = [3]uint64{1, 0, 0}
		}
		maxK := n - 1
		if maxK > 56 {
			maxK = 56
		}
		for k := 1; k <= maxK; k++ {
			a := binomialC168[n-1][k-1]
			b := binomialC168[n-1][k]
			s0, c0 := bits.Add64(a[0], b[0], 0)
			s1, c1 := bits.Add64(a[1], b[1], c0)
			s2, _ := bits.Add64(a[2], b[2], c1)
			binomialC168[n][k] = [3]uint64{s0, s1, s2}
		}
	}
}

func leq3(a, b [3]uint64) bool {
	_, br0 := bits.Sub64(b[0], a[0], 0)
	_, br1 := bits.Sub64(b[1], a[1], br0)
	_, br2 := bits.Sub64(b[2], a[2], br1)
	return br2 == 0
}

func sub3(a, b [3]uint64) [3]uint64 {
	d0, br0 := bits.Sub64(a[0], b[0], 0)
	d1, br1 := bits.Sub64(a[1], b[1], br0)
	d2, _ := bits.Sub64(a[2], b[2], br1)
	return [3]uint64{d0, d1, d2}
}

// unrankCombination168 maps a 3-limb combinadic rank in [0, C(n, k)) to the
// corresponding 168-bit bitmask of weight k in the low n bits of a [3]uint64.
func unrankCombination168(rank [3]uint64, k, n int) [3]uint64 {
	var mask [3]uint64
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && leq3(binomialC168[c+1][k], rank) {
			c++
		}
		mask[c/64] |= uint64(1) << uint(c%64)
		rank = sub3(rank, binomialC168[c][k])
		k--
	}
	return mask
}

const domain168_2 uint64 = (uint64(1) << 40) - 1

// rankToMaskTriple168 derives a balanced 168-bit mask triple (m0, m1, m2)
// from a 512-bit rank digest (8 little-endian uint64 words). Each mask has
// popcount 56, is pairwise disjoint, and their bitwise OR covers the low 168
// bits of [3]uint64.
func rankToMaskTriple168(r [8]uint64) (m0, m1, m2 [3]uint64) {
	idx0, idx1 := splitRank168(r)
	m0, m1, m2 = rankToMaskTriple168FromSplit(idx0, idx1)
	r = [8]uint64{}
	idx0 = [3]uint64{}
	idx1 = [2]uint64{}
	runtime.KeepAlive(&r)
	runtime.KeepAlive(&idx0)
	runtime.KeepAlive(&idx1)
	return m0, m1, m2
}

// rankToMaskTriple168FromSplit derives a balanced 168-bit mask triple (m0, m1, m2)
// directly from pre-split combinadic indices idx0 < A168 and idx1 < B168.
func rankToMaskTriple168FromSplit(idx0 [3]uint64, idx1 [2]uint64) (m0, m1, m2 [3]uint64) {
	m0 = unrankCombination168(idx0, 56, 168)
	m1Local := unrankCombination168([3]uint64{idx1[0], idx1[1], 0}, 56, 112)

	var remaining [3]uint64
	remaining[0] = ^m0[0]
	remaining[1] = ^m0[1]
	remaining[2] = (^m0[2]) & domain168_2

	posIdx := 0
	for bit := 0; bit < 168; bit++ {
		w := bit / 64
		b := uint(bit % 64)
		if (remaining[w]>>b)&1 != 0 {
			lw := posIdx / 64
			lb := uint(posIdx % 64)
			if (m1Local[lw]>>lb)&1 != 0 {
				m1[w] |= uint64(1) << b
			}
			posIdx++
		}
	}
	m2[0] = remaining[0] & ^m1[0]
	m2[1] = remaining[1] & ^m1[1]
	m2[2] = remaining[2] & ^m1[2]
	m1Local = [3]uint64{}
	remaining = [3]uint64{}
	runtime.KeepAlive(&m1Local)
	runtime.KeepAlive(&remaining)
	return m0, m1, m2
}

// softPEXT168 compresses the 56 bits of x selected by the weight-56 168-bit
// mask into the low 56 bits of a uint64.
//
// Constant-time: executes a fixed 56-iteration loop across the 3-word mask as
// a single 168-bit register, selecting the lowest non-zero word via arithmetic
// masks and clearing its lowest set bit each step. Every call executes an
// identical 56-step instruction trace regardless of how the 56 set bits are
// distributed across words 0, 1, and 2.
func softPEXT168(x, mask [3]uint64) uint64 {
	m0, m1, m2 := mask[0], mask[1], mask[2]
	var out uint64
	for i := uint(0); i < 56; i++ {
		nz0 := (m0 | -m0) >> 63
		nz1 := (m1 | -m1) >> 63
		sel0 := -nz0
		sel1 := -(^nz0 & nz1)
		sel2 := -(^nz0 & ^nz1 & 1)

		mw := (m0 & sel0) | (m1 & sel1) | (m2 & sel2)
		xw := (x[0] & sel0) | (x[1] & sel1) | (x[2] & sel2)
		lsb := mw & -mw

		masked := xw & lsb
		bit := (masked | -masked) >> 63
		out |= bit << i

		m0 ^= lsb & sel0
		m1 ^= lsb & sel1
		m2 ^= lsb & sel2
	}
	return out
}

// softPDEP168 deposits the low 56 bits of v into the positions selected by
// the weight-56 168-bit mask. Inverse of [softPEXT168] under a matching mask.
//
// Constant-time: uses the same fixed 56-iteration word-selection schedule as
// [softPEXT168], independent of per-word popcounts.
func softPDEP168(v uint64, mask [3]uint64) [3]uint64 {
	m0, m1, m2 := mask[0], mask[1], mask[2]
	var out [3]uint64
	for i := uint(0); i < 56; i++ {
		nz0 := (m0 | -m0) >> 63
		nz1 := (m1 | -m1) >> 63
		sel0 := -nz0
		sel1 := -(^nz0 & nz1)
		sel2 := -(^nz0 & ^nz1 & 1)

		mw := (m0 & sel0) | (m1 & sel1) | (m2 & sel2)
		lsb := mw & -mw

		bitMask := -((v >> i) & 1)
		deposit := lsb & bitMask
		out[0] |= deposit & sel0
		out[1] |= deposit & sel1
		out[2] |= deposit & sel2

		m0 ^= lsb & sel0
		m1 ^= lsb & sel1
		m2 ^= lsb & sel2
	}
	return out
}

// chunk168lock splits a 168-bit chunk x into three 56-bit lane values under
// the balanced mask triple (m0, m1, m2). On amd64 with BMI2 it dispatches to
// [interlock.Chunk168Lock]; otherwise it uses [softPEXT168].
func chunk168lock(x, m0, m1, m2 [3]uint64) (l0, l1, l2 uint64) {
	if interlock.HasBMI2 {
		var src [21]byte
		writeChunk168(src[:], 0, x)
		var out [3][7]byte
		interlock.Chunk168Lock(&src, m0, m1, m2, &out)
		l0 = readLane56(out[0][:], 0)
		l1 = readLane56(out[1][:], 0)
		l2 = readLane56(out[2][:], 0)
		clear(src[:])
		clear(out[0][:])
		clear(out[1][:])
		clear(out[2][:])
		runtime.KeepAlive(&src)
		runtime.KeepAlive(&out)
		return l0, l1, l2
	}
	return softPEXT168(x, m0), softPEXT168(x, m1), softPEXT168(x, m2)
}

// unchunk168lock reconstructs a 168-bit chunk from three 56-bit lane values
// under the balanced mask triple (m0, m1, m2). Inverse of [chunk168lock].
func unchunk168lock(l0, l1, l2 uint64, m0, m1, m2 [3]uint64) [3]uint64 {
	if interlock.HasBMI2 {
		var b0, b1, b2 [7]byte
		writeLane56(b0[:], 0, l0)
		writeLane56(b1[:], 0, l1)
		writeLane56(b2[:], 0, l2)
		var dst [21]byte
		interlock.Unchunk168Lock(&b0, &b1, &b2, m0, m1, m2, &dst)
		x := readChunk168(dst[:], 0)
		clear(b0[:])
		clear(b1[:])
		clear(b2[:])
		clear(dst[:])
		runtime.KeepAlive(&b0)
		runtime.KeepAlive(&b1)
		runtime.KeepAlive(&b2)
		runtime.KeepAlive(&dst)
		return x
	}
	d0 := softPDEP168(l0, m0)
	d1 := softPDEP168(l1, m1)
	d2 := softPDEP168(l2, m2)
	out := [3]uint64{
		d0[0] | d1[0] | d2[0],
		d0[1] | d1[1] | d2[1],
		d0[2] | d1[2] | d2[2],
	}
	d0 = [3]uint64{}
	d1 = [3]uint64{}
	d2 = [3]uint64{}
	runtime.KeepAlive(&d0)
	runtime.KeepAlive(&d1)
	runtime.KeepAlive(&d2)
	return out
}

// readChunk168 packs 21 little-endian bytes starting at padded[base] into a
// 168-bit [3]uint64 (low 64 bits in [0], middle 64 bits in [1], top 40 bits in [2]).
func readChunk168(padded []byte, base int) [3]uint64 {
	w0 := binary.LittleEndian.Uint64(padded[base : base+8])
	w1 := binary.LittleEndian.Uint64(padded[base+8 : base+16])
	w2 := uint64(binary.LittleEndian.Uint32(padded[base+16:base+20])) |
		uint64(padded[base+20])<<32
	return [3]uint64{w0, w1, w2}
}

// writeChunk168 emits the low 168 bits of x as 21 little-endian bytes at
// result[base : base+21].
func writeChunk168(result []byte, base int, x [3]uint64) {
	binary.LittleEndian.PutUint64(result[base:base+8], x[0])
	binary.LittleEndian.PutUint64(result[base+8:base+16], x[1])
	binary.LittleEndian.PutUint32(result[base+16:base+20], uint32(x[2]))
	result[base+20] = byte(x[2] >> 32)
}

// readLane56 reads 7 little-endian bytes at p[base : base+7] into the low
// 56 bits of a uint64.
func readLane56(p []byte, base int) uint64 {
	return uint64(binary.LittleEndian.Uint32(p[base:base+4])) |
		uint64(p[base+4])<<32 |
		uint64(p[base+5])<<40 |
		uint64(p[base+6])<<48
}

// writeLane56 writes the low 56 bits of l as 7 little-endian bytes at
// p[base : base+7].
func writeLane56(p []byte, base int, l uint64) {
	binary.LittleEndian.PutUint32(p[base:base+4], uint32(l))
	p[base+4] = byte(l >> 32)
	p[base+5] = byte(l >> 40)
	p[base+6] = byte(l >> 48)
}

// framedSrc168 is a copy-free view of the chunk stream head || body ||
// zero padding consumed by the 168-bit split kernel.
type framedSrc168 struct {
	head []byte
	body []byte
}

// chunkCount returns M, the number of 21-byte (168-bit) chunks in the padded stream.
func (s framedSrc168) chunkCount() int {
	return (len(s.head) + len(s.body) + 20) / 21
}

// chunk returns chunk k of the stream in the [readChunk168] convention.
func (s framedSrc168) chunk(k int) [3]uint64 {
	base := 21*k - len(s.head)
	if base >= 0 && base+21 <= len(s.body) {
		return readChunk168(s.body, base)
	}
	var buf [21]byte
	for i := 0; i < 21; i++ {
		o := 21*k + i
		if o < len(s.head) {
			buf[i] = s.head[o]
		} else if o -= len(s.head); o < len(s.body) {
			buf[i] = s.body[o]
		}
	}
	out := readChunk168(buf[:], 0)
	clear(buf[:])
	runtime.KeepAlive(&buf)
	return out
}

// tripleLaneLen168 returns the per-lane byte length (7*M) the 168-bit split
// produces for an L-byte plaintext once the 4-byte length prefix is framed in
// front of it.
func tripleLaneLen168(L int) int {
	return 7 * ((L + 4 + 20) / 21)
}

// superChunks168 is the number of 168-bit chunks whose mask triples are
// derived per batch-kernel invocation (8 chunks = 8 512-bit PRF digests).
const superChunks168 = 8

// interlockWorkerScratch168 groups the per-worker buffers of the 168-bit
// split / interleave kernels. Allocated once per worker and wiped once at
// worker exit via [wipeInterlockWorker168].
type interlockWorkerScratch168 struct {
	buf     [13]byte
	scratch lockFillScratch48
	prf     [64]uint64
	masks   [superChunks168][3][3]uint64
	idx0_8  [3][8]uint64
	idx1_8  [2][8]uint64
	out8    [3][3][8]uint64
}

func wipeInterlockWorker168(ws *interlockWorkerScratch168) {
	*ws = interlockWorkerScratch168{}
	runtime.KeepAlive(ws)
}

// fillLockMasksTriple168Super fills masks[0..count-1] from count 512-bit
// ranks packed into prf (8 uint64 words per chunk). count must be <= 8.
func fillLockMasksTriple168Super(prf *[64]uint64, count int, masks *[superChunks168][3][3]uint64) {
	var ws interlockWorkerScratch168
	fillLockMasksTriple168SuperWS(&ws, prf, count, masks)
	wipeInterlockWorker168(&ws)
}

// fillLockMasksTriple168SuperWS is the worker-scratch counterpart of
// [fillLockMasksTriple168Super].
func fillLockMasksTriple168SuperWS(ws *interlockWorkerScratch168, prf *[64]uint64, count int, masks *[superChunks168][3][3]uint64) {
	if interlock.HasAVX512RankMask || interlock.HasAVX2RankMask || interlock.HasNEONInterlock {
		var i0 [3]uint64
		var i1 [2]uint64
		for j := 0; j < count; j++ {
			i0, i1 = splitRank168(*(*[8]uint64)(prf[8*j : 8*j+8]))
			ws.idx0_8[0][j] = i0[0]
			ws.idx0_8[1][j] = i0[1]
			ws.idx0_8[2][j] = i0[2]
			ws.idx1_8[0][j] = i1[0]
			ws.idx1_8[1][j] = i1[1]
		}
		i0 = [3]uint64{}
		i1 = [2]uint64{}
		runtime.KeepAlive(&i0)
		runtime.KeepAlive(&i1)
		for j := count; j < 8; j++ {
			ws.idx0_8[0][j] = 0
			ws.idx0_8[1][j] = 0
			ws.idx0_8[2][j] = 0
			ws.idx1_8[0][j] = 0
			ws.idx1_8[1][j] = 0
		}
		switch {
		case interlock.HasAVX512RankMask:
			interlock.RankToMaskTripleUnrank168(&ws.idx0_8, &ws.idx1_8, &ws.out8)
		case interlock.HasAVX2RankMask:
			interlock.RankToMaskTripleUnrank168AVX2(&ws.idx0_8, &ws.idx1_8, &ws.out8)
		default:
			interlock.RankToMaskTripleUnrank168NEON(&ws.idx0_8, &ws.idx1_8, &ws.out8)
		}
		for j := 0; j < count; j++ {
			for m := 0; m < 3; m++ {
				for w := 0; w < 3; w++ {
					masks[j][m][w] = ws.out8[m][w][j]
				}
			}
		}
		return
	}
	for j := 0; j < count; j++ {
		masks[j][0], masks[j][1], masks[j][2] = rankToMaskTriple168(*(*[8]uint64)(prf[8*j : 8*j+8]))
	}
}

// fillSuperblockRanks168 populates prf[0 : 8*n] for the n <= 8 consecutive
// 512-bit PRF groups (1 group = 1 chunk in 168-bit mode) starting at g.
func fillSuperblockRanks168(ws *interlockWorkerScratch168, g, n int, bp lockBatchPRF48) {
	buf, scratch, prf := &ws.buf, &ws.scratch, &ws.prf
	if n == 8 {
		if bp.fillRanksSuper32 != nil {
			bp.fillRanksSuper32(scratch, uint64(g), prf[0:64])
			return
		}
		if bp.fillRanksSuper != nil {
			bp.fillRanksSuper(scratch, uint64(g), prf[0:32])
			bp.fillRanksSuper(scratch, uint64(g+4), prf[32:64])
			return
		}
		if bp.fillRanksX4 != nil {
			bp.fillRanksX4(scratch, uint64(g), prf[0:32])
			bp.fillRanksX4(scratch, uint64(g+4), prf[32:64])
			return
		}
	}
	j := 0
	if n >= 4 {
		if bp.fillRanksSuper != nil {
			bp.fillRanksSuper(scratch, uint64(g), prf[0:32])
			j = 4
		} else if bp.fillRanksX4 != nil {
			bp.fillRanksX4(scratch, uint64(g), prf[0:32])
			j = 4
		}
	}
	for ; j < n; j++ {
		bp.fillRanks(buf[:], uint64(g+j), prf[8*j:8*j+8])
	}
}

// splitTriple168LockedBatchInto is the parallel batched 168-bit encode kernel.
func splitTriple168LockedBatchInto(src framedSrc168, p0, p1, p2 []byte, bp lockBatchPRF48, cfg *Config) {
	M := src.chunkCount()
	if M == 0 {
		return
	}
	p0, p1, p2 = p0[:7*M], p1[:7*M], p2[:7*M]

	// In 168-bit mode, 1 group (1 512-bit digest) = 1 chunk.
	numGroups := M
	G := configuredWorkerCount(cfg)
	if G > numGroups {
		G = numGroups
	}
	if G <= 1 {
		wipePixelCallStack([9][8]uint64{})
		splitTriple168WorkerBody(0, numGroups, M, src, p0, p1, p2, bp)
		wipePixelCallStack([9][8]uint64{})
		return
	}
	groupsPerWorker := (numGroups + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		gStart := w * groupsPerWorker
		gEnd := gStart + groupsPerWorker
		if gEnd > numGroups {
			gEnd = numGroups
		}
		if gStart >= gEnd {
			continue
		}
		wg.Add(1)
		go func(gs, ge int) {
			defer wg.Done()
			wipePixelCallStack([9][8]uint64{})
			splitTriple168WorkerBody(gs, ge, M, src, p0, p1, p2, bp)
			wipePixelCallStack([9][8]uint64{})
		}(gStart, gEnd)
	}
	wg.Wait()
}

//go:noinline
func splitTriple168WorkerBody(gs, ge, M int, src framedSrc168, p0, p1, p2 []byte, bp lockBatchPRF48) {
	ws := new(interlockWorkerScratch168)
	prf, masks := &ws.prf, &ws.masks
	for g := gs; g < ge; {
		n := superChunks168
		if ge-g < n {
			n = ge - g
		}
		fillSuperblockRanks168(ws, g, n, bp)
		fillLockMasksTriple168SuperWS(ws, prf, n, masks)
		if !chunk168lockBatch(src, M, g, n, masks[:], p0, p1, p2) {
			for j := 0; j < n; j++ {
				k := g + j
				if k >= M {
					break
				}
				m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
				x := src.chunk(k)
				l0, l1, l2 := chunk168lock(x, m0, m1, m2)
				writeLane56(p0, 7*k, l0)
				writeLane56(p1, 7*k, l1)
				writeLane56(p2, 7*k, l2)
			}
		}
		g += n
	}
	wipeInterlockWorker168(ws)
}

// interleaveTriple168LockedBatch is the inverse of [splitTriple168LockedBatchInto].
func interleaveTriple168LockedBatch(p0, p1, p2 []byte, bp lockBatchPRF48, cfg *Config) []byte {
	M := len(p0) / 7
	result := make([]byte, M*21)
	interleaveTriple168LockedBatchInto(result, p0, p1, p2, bp, cfg)
	return result
}

func interleaveTriple168LockedBatchInto(result, p0, p1, p2 []byte, bp lockBatchPRF48, cfg *Config) {
	M := len(p0) / 7
	if M == 0 {
		return
	}

	numGroups := M
	G := configuredWorkerCount(cfg)
	if G > numGroups {
		G = numGroups
	}
	if G <= 1 {
		wipePixelCallStack([9][8]uint64{})
		interleaveTriple168WorkerBody(0, numGroups, M, result, p0, p1, p2, bp)
		wipePixelCallStack([9][8]uint64{})
		return
	}
	groupsPerWorker := (numGroups + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		gStart := w * groupsPerWorker
		gEnd := gStart + groupsPerWorker
		if gEnd > numGroups {
			gEnd = numGroups
		}
		if gStart >= gEnd {
			continue
		}
		wg.Add(1)
		go func(gs, ge int) {
			defer wg.Done()
			wipePixelCallStack([9][8]uint64{})
			interleaveTriple168WorkerBody(gs, ge, M, result, p0, p1, p2, bp)
			wipePixelCallStack([9][8]uint64{})
		}(gStart, gEnd)
	}
	wg.Wait()
}

//go:noinline
func interleaveTriple168WorkerBody(gs, ge, M int, result, p0, p1, p2 []byte, bp lockBatchPRF48) {
	ws := new(interlockWorkerScratch168)
	prf, masks := &ws.prf, &ws.masks
	for g := gs; g < ge; {
		n := superChunks168
		if ge-g < n {
			n = ge - g
		}
		fillSuperblockRanks168(ws, g, n, bp)
		fillLockMasksTriple168SuperWS(ws, prf, n, masks)
		if !unchunk168lockBatch(result, M, g, n, masks[:], p0, p1, p2) {
			for j := 0; j < n; j++ {
				k := g + j
				if k >= M {
					break
				}
				m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
				l0 := readLane56(p0, 7*k)
				l1 := readLane56(p1, 7*k)
				l2 := readLane56(p2, 7*k)
				x := unchunk168lock(l0, l1, l2, m0, m1, m2)
				writeChunk168(result, 21*k, x)
			}
		}
		g += n
	}
	wipeInterlockWorker168(ws)
}

// splitForTriple168LockedInto dispatches plaintext splitting through the
// 168-bit interlock overlay path.
func splitForTriple168LockedInto(cfg *Config, data []byte, bp lockBatchPRF48, p0, p1, p2 []byte) {
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(data)))
	splitTriple168LockedBatchInto(framedSrc168{head: head[:], body: data}, p0, p1, p2, bp, cfg)
	clear(head[:])
	runtime.KeepAlive(&head)
}

// interleaveForTriple168LockedCfg is the inverse of [splitForTriple168LockedInto].
func interleaveForTriple168LockedCfg(cfg *Config, p0, p1, p2 []byte, bp lockBatchPRF48) []byte {
	return interleaveForTriple168LockedCfgInto(cfg, nil, p0, p1, p2, bp)
}

func interleaveForTriple168LockedCfgInto(cfg *Config, dst, p0, p1, p2 []byte, bp lockBatchPRF48) []byte {
	defer bp.wipe()
	origLen0, origLen1, origLen2 := len(p0), len(p1), len(p2)
	p0, p1, p2 = padLanesToEqualMult7(p0, p1, p2)
	if len(p0) != origLen0 {
		defer secureWipe(p0)
	}
	if len(p1) != origLen1 {
		defer secureWipe(p1)
	}
	if len(p2) != origLen2 {
		defer secureWipe(p2)
	}
	if cap(dst) > 0 {
		M := len(p0) / 7
		if M == 0 {
			return dst[:0]
		}
		if len(dst) == 1 && cap(dst) >= M*21 {
			framed := dst[:M*21]
			interleaveTriple168LockedBatchInto(framed, p0, p1, p2, bp, cfg)
			if len(framed) < 4 {
				return framed
			}
			length := binary.BigEndian.Uint32(framed[:4])
			end := uint64(length) + 4
			if end > uint64(len(framed)) {
				end = uint64(len(framed))
			}
			secureWipe(framed[:4])
			secureWipe(framed[int(end):])
			return framed[4:int(end)]
		}
		framedPtr, framed := acquireStage(M * 21)
		defer releaseStage(framedPtr, framed, len(framed))
		interleaveTriple168LockedBatchInto(framed, p0, p1, p2, bp, cfg)
		if len(framed) < 4 {
			if cap(dst) >= len(framed) {
				out := dst[:len(framed)]
				copy(out, framed)
				return out
			}
			out := make([]byte, len(framed))
			copy(out, framed)
			return out
		}
		length := binary.BigEndian.Uint32(framed[:4])
		end := uint64(length) + 4
		if end > uint64(len(framed)) {
			end = uint64(len(framed))
		}
		payloadLen := int(end) - 4
		var out []byte
		if cap(dst) >= payloadLen {
			out = dst[:payloadLen]
		} else {
			out = make([]byte, payloadLen)
		}
		copy(out, framed[4:int(end)])
		return out
	}
	framed := interleaveTriple168LockedBatch(p0, p1, p2, bp, cfg)
	if len(framed) < 4 {
		return framed
	}
	length := binary.BigEndian.Uint32(framed[:4])
	end := uint64(length) + 4
	if end > uint64(len(framed)) {
		end = uint64(len(framed))
	}
	secureWipe(framed[:4])
	secureWipe(framed[int(end):])
	return framed[4:int(end)]
}

// padLanesToEqualMult7 returns copies of p0/p1/p2 padded with trailing
// zero bytes to the largest multiple-of-7 length across the three.
func padLanesToEqualMult7(p0, p1, p2 []byte) ([]byte, []byte, []byte) {
	target := len(p0)
	if len(p1) > target {
		target = len(p1)
	}
	if len(p2) > target {
		target = len(p2)
	}
	if rem := target % 7; rem != 0 {
		target += 7 - rem
	}
	pad := func(p []byte) []byte {
		if len(p) == target {
			return p
		}
		out := make([]byte, target)
		copy(out, p)
		return out
	}
	return pad(p0), pad(p1), pad(p2)
}
