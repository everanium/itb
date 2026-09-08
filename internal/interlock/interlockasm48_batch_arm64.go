//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"encoding/binary"
	"math/bits"
)

// HasChunk48Batch caches whether the batched chunk-apply entry points
// ([Chunk48LockBatch] / [Unchunk48LockBatch]) are selected. On arm64
// the batched entry always has an arm: the SVE2 BEXT / BDEP kernel when
// [HasSVE2Interlock] is set, otherwise the set-bit-walk software
// PEXT / PDEP loop below. Both amortise the per-chunk Go-loop overhead
// of the parent package's fallback; ITB_FORCE_INTERLOCK_TIER=scalar
// clears the flag so the per-chunk softPEXT48 / softPDEP48 path runs.
var HasChunk48Batch = true

// pext16 compresses the 16 bits of x selected by mask (popcount 16)
// into the low 16 bits of the result: a 16-step walk over the set bits
// of mask, each step locating the next set position with a trailing-
// zero count (RBIT + CLZ on arm64, fixed latency) and clearing it with
// mask &= mask - 1. Three times fewer steps than the 48-position
// bit-serial softPEXT48 of the parent package; the trip count is fixed
// and no step branches on secret data.
func pext16(x, mask uint64) uint16 {
	var r uint64
	for i := uint(0); i < 16; i++ {
		b := uint(bits.TrailingZeros64(mask))
		r |= ((x >> b) & 1) << i
		mask &= mask - 1
	}
	return uint16(r)
}

// pdep16 is the inverse of [pext16]: bit i of v lands on the i-th set
// position of mask (ascending). Same 16-step set-bit walk.
func pdep16(v uint16, mask uint64) uint64 {
	var r uint64
	x := uint64(v)
	for i := uint(0); i < 16; i++ {
		b := uint(bits.TrailingZeros64(mask))
		r |= ((x >> i) & 1) << b
		mask &= mask - 1
	}
	return r
}

// chunk48LockBatchGo is the software batched forward apply: for each of
// the n = len(masks) chunks, six little-endian source bytes are packed
// into a 48-bit word and the three lane values are extracted under the
// chunk's mask triple via [pext16], then stored little-endian at
// p_i[2j]. Bit-exact with n per-chunk softPEXT48 applications.
func chunk48LockBatchGo(src []byte, masks [][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	src = src[:6*n]
	p0, p1, p2 = p0[:2*n], p1[:2*n], p2[:2*n]
	for j := 0; j < n; j++ {
		s := src[6*j : 6*j+6 : 6*j+6]
		x := uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 |
			uint64(s[3])<<24 | uint64(s[4])<<32 | uint64(s[5])<<40
		m := &masks[j]
		binary.LittleEndian.PutUint16(p0[2*j:], pext16(x, m[0]))
		binary.LittleEndian.PutUint16(p1[2*j:], pext16(x, m[1]))
		binary.LittleEndian.PutUint16(p2[2*j:], pext16(x, m[2]))
	}
}

// unchunk48LockBatchGo is the software batched inverse apply: the three
// little-endian lane values of chunk j are deposited under the chunk's
// mask triple via [pdep16], OR-ed (the deposits land in disjoint
// positions) and written as six little-endian bytes at dst[6j].
// Bit-exact with n per-chunk softPDEP48 applications.
func unchunk48LockBatchGo(p0, p1, p2 []byte, masks [][3]uint64, dst []byte) {
	n := len(masks)
	dst = dst[:6*n]
	p0, p1, p2 = p0[:2*n], p1[:2*n], p2[:2*n]
	for j := 0; j < n; j++ {
		m := &masks[j]
		x := pdep16(binary.LittleEndian.Uint16(p0[2*j:]), m[0]) |
			pdep16(binary.LittleEndian.Uint16(p1[2*j:]), m[1]) |
			pdep16(binary.LittleEndian.Uint16(p2[2*j:]), m[2])
		d := dst[6*j : 6*j+6 : 6*j+6]
		d[0] = byte(x)
		d[1] = byte(x >> 8)
		d[2] = byte(x >> 16)
		d[3] = byte(x >> 24)
		d[4] = byte(x >> 32)
		d[5] = byte(x >> 40)
	}
}

// Chunk48LockBatch applies the 48-bit interlock forward permutation to
// n = len(masks) consecutive chunks in one call. Chunk j is the six
// little-endian bytes src[6j : 6j+6]; its lane outputs are stored
// little-endian at p0[2j : 2j+2], p1[2j : 2j+2], p2[2j : 2j+2].
// Bit-exact with n per-chunk softPEXT48 applications followed by the
// caller-side uint16 little-endian serialisation.
//
// Panics if src is shorter than 6n bytes or any lane buffer is shorter
// than 2n bytes. Reads exactly src[0 : 6n] and writes exactly
// p_i[0 : 2n]. Caller gates on [HasChunk48Batch]; the SVE2 kernel is
// taken when [HasSVE2Interlock] is set.
func Chunk48LockBatch(src []byte, masks [][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	if HasSVE2Interlock {
		src = src[:6*n]
		p0, p1, p2 = p0[:2*n], p1[:2*n], p2[:2*n]
		chunk48LockBatchSVE2(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
		return
	}
	chunk48LockBatchGo(src, masks, p0, p1, p2)
}

// Unchunk48LockBatch applies the inverse permutation to n = len(masks)
// consecutive chunks in one call. Lane values for chunk j are read
// little-endian from p0[2j : 2j+2], p1[2j : 2j+2], p2[2j : 2j+2]; the
// recovered chunk is written as six little-endian bytes to
// dst[6j : 6j+6]. Bit-exact with n per-chunk softPDEP48 applications
// followed by the caller-side six-byte little-endian store.
//
// Panics if dst is shorter than 6n bytes or any lane buffer is shorter
// than 2n bytes. Writes exactly dst[0 : 6n] and reads exactly
// p_i[0 : 2n]. Caller gates on [HasChunk48Batch]; the SVE2 kernel is
// taken when [HasSVE2Interlock] is set.
func Unchunk48LockBatch(p0, p1, p2 []byte, masks [][3]uint64, dst []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	if HasSVE2Interlock {
		dst = dst[:6*n]
		p0, p1, p2 = p0[:2*n], p1[:2*n], p2[:2*n]
		unchunk48LockBatchSVE2(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
		return
	}
	unchunk48LockBatchGo(p0, p1, p2, masks, dst)
}
