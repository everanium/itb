//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"encoding/binary"
	"math/bits"
)

// HasChunk168Batch caches whether the batched 168-bit chunk-apply entry
// points ([Chunk168LockBatch] / [Unchunk168LockBatch]) are selected. On
// arm64 the batched entry always has an arm: the SVE2 BEXT / BDEP
// kernel when [HasSVE2Interlock] is set, otherwise the constant-time
// 56-step set-bit-walk software PEXT / PDEP loop below.
// ITB_FORCE_INTERLOCK_TIER=scalar clears the flag so the per-chunk
// softPEXT168 / softPDEP168 path runs.
var HasChunk168Batch = true

// pext56 compresses the 56 bits of (x0, x1, x2) selected by mask m
// (total popcount 56 across the 3 words) into the low 56 bits of the
// returned uint64.
//
// Constant-time: iterates a fixed 56 steps across the 3-word tuple
// (m0, m1, m2) using branchless non-zero word selection so the secret
// individual word weights popcnt(m[w]) are never leaked via loop trip
// counts or branches.
func pext56(x0, x1, x2 uint64, m [3]uint64) uint64 {
	m0, m1, m2 := m[0], m[1], m[2]
	var r uint64
	for i := uint(0); i < 56; i++ {
		has0 := (m0 | -m0) >> 63
		has1 := ((m1 | -m1) >> 63) &^ has0
		has2 := 1 ^ has0 ^ has1
		mask0 := -has0
		mask1 := -has1
		mask2 := -has2
		mw := (m0 & mask0) | (m1 & mask1) | (m2 & mask2)
		xw := (x0 & mask0) | (x1 & mask1) | (x2 & mask2)
		b := uint(bits.TrailingZeros64(mw))
		r |= ((xw >> (b & 63)) & 1) << i
		m0 &= (m0 - 1) | ^mask0
		m1 &= (m1 - 1) | ^mask1
		m2 &= (m2 - 1) | ^mask2
	}
	return r
}

// pdep56 is the inverse of [pext56]: bit i of v (for i = 0..55) lands
// on the i-th set position of the 3-word mask m (ascending across
// m[0], m[1], m[2]). Uses the same constant-time 56-step walk.
func pdep56(v uint64, m [3]uint64) (x0, x1, x2 uint64) {
	m0, m1, m2 := m[0], m[1], m[2]
	for i := uint(0); i < 56; i++ {
		has0 := (m0 | -m0) >> 63
		has1 := ((m1 | -m1) >> 63) &^ has0
		has2 := 1 ^ has0 ^ has1
		mask0 := -has0
		mask1 := -has1
		mask2 := -has2
		mw := (m0 & mask0) | (m1 & mask1) | (m2 & mask2)
		b := uint(bits.TrailingZeros64(mw))
		bit := ((v >> i) & 1) << (b & 63)
		x0 |= bit & mask0
		x1 |= bit & mask1
		x2 |= bit & mask2
		m0 &= (m0 - 1) | ^mask0
		m1 &= (m1 - 1) | ^mask1
		m2 &= (m2 - 1) | ^mask2
	}
	return x0, x1, x2
}

// chunk168LockBatchGo is the software batched forward apply on arm64:
// for each of the n = len(masks) 21-byte chunks, the three 56-bit lane
// values are extracted via [pext56] and written as 7 little-endian
// bytes to p0[7j], p1[7j], p2[7j].
func chunk168LockBatchGo(src []byte, masks [][3][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	_ = src[21*n-1]
	_ = p0[7*n-1]
	_ = p1[7*n-1]
	_ = p2[7*n-1]
	for j := 0; j < n; j++ {
		s := src[21*j : 21*j+21 : 21*j+21]
		x0 := binary.LittleEndian.Uint64(s[0:8])
		x1 := binary.LittleEndian.Uint64(s[8:16])
		x2 := uint64(binary.LittleEndian.Uint32(s[16:20])) | uint64(s[20])<<32
		m := &masks[j]

		l0 := pext56(x0, x1, x2, m[0])
		d0 := p0[7*j : 7*j+7 : 7*j+7]
		binary.LittleEndian.PutUint32(d0[0:4], uint32(l0))
		binary.LittleEndian.PutUint16(d0[4:6], uint16(l0>>32))
		d0[6] = byte(l0 >> 48)

		l1 := pext56(x0, x1, x2, m[1])
		d1 := p1[7*j : 7*j+7 : 7*j+7]
		binary.LittleEndian.PutUint32(d1[0:4], uint32(l1))
		binary.LittleEndian.PutUint16(d1[4:6], uint16(l1>>32))
		d1[6] = byte(l1 >> 48)

		l2 := pext56(x0, x1, x2, m[2])
		d2 := p2[7*j : 7*j+7 : 7*j+7]
		binary.LittleEndian.PutUint32(d2[0:4], uint32(l2))
		binary.LittleEndian.PutUint16(d2[4:6], uint16(l2>>32))
		d2[6] = byte(l2 >> 48)
	}
}

// unchunk168LockBatchGo is the software batched inverse apply on arm64:
// the three 7-byte little-endian lane values of chunk j are deposited
// via [pdep56], OR-ed across the three lanes, and written as 21
// little-endian bytes to dst[21j].
func unchunk168LockBatchGo(p0, p1, p2 []byte, masks [][3][3]uint64, dst []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	_ = dst[21*n-1]
	_ = p0[7*n-1]
	_ = p1[7*n-1]
	_ = p2[7*n-1]
	for j := 0; j < n; j++ {
		s0 := p0[7*j : 7*j+7 : 7*j+7]
		l0 := uint64(binary.LittleEndian.Uint32(s0[0:4])) |
			uint64(binary.LittleEndian.Uint16(s0[4:6]))<<32 |
			uint64(s0[6])<<48

		s1 := p1[7*j : 7*j+7 : 7*j+7]
		l1 := uint64(binary.LittleEndian.Uint32(s1[0:4])) |
			uint64(binary.LittleEndian.Uint16(s1[4:6]))<<32 |
			uint64(s1[6])<<48

		s2 := p2[7*j : 7*j+7 : 7*j+7]
		l2 := uint64(binary.LittleEndian.Uint32(s2[0:4])) |
			uint64(binary.LittleEndian.Uint16(s2[4:6]))<<32 |
			uint64(s2[6])<<48

		m := &masks[j]
		a0, a1, a2 := pdep56(l0, m[0])
		b0, b1, b2 := pdep56(l1, m[1])
		c0, c1, c2 := pdep56(l2, m[2])
		x0, x1, x2 := a0|b0|c0, a1|b1|c1, a2|b2|c2

		d := dst[21*j : 21*j+21 : 21*j+21]
		binary.LittleEndian.PutUint64(d[0:8], x0)
		binary.LittleEndian.PutUint64(d[8:16], x1)
		binary.LittleEndian.PutUint32(d[16:20], uint32(x2))
		d[20] = byte(x2 >> 32)
	}
}

// Chunk168LockBatch applies the 168-bit interlock forward permutation
// to n = len(masks) consecutive 21-byte chunks in one call. Caller
// gates on [HasChunk168Batch]; the SVE2 kernel is taken when
// [HasSVE2Interlock] is set.
func Chunk168LockBatch(src []byte, masks [][3][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	_ = src[21*n-1]
	_ = p0[7*n-1]
	_ = p1[7*n-1]
	_ = p2[7*n-1]
	if HasSVE2Interlock {
		chunk168LockBatchSVE2(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
		return
	}
	chunk168LockBatchGo(src, masks, p0, p1, p2)
}

// Unchunk168LockBatch applies the inverse permutation to n = len(masks)
// consecutive chunks in one call. Caller gates on [HasChunk168Batch];
// the SVE2 kernel is taken when [HasSVE2Interlock] is set.
func Unchunk168LockBatch(p0, p1, p2 []byte, masks [][3][3]uint64, dst []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	_ = dst[21*n-1]
	_ = p0[7*n-1]
	_ = p1[7*n-1]
	_ = p2[7*n-1]
	if HasSVE2Interlock {
		unchunk168LockBatchSVE2(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
		return
	}
	unchunk168LockBatchGo(p0, p1, p2, masks, dst)
}
