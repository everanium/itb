//go:build amd64 && !purego && !noitbasm

package interlock

import "golang.org/x/sys/cpu"

// HasChunk48Batch caches whether the batched chunk-apply kernels
// ([Chunk48LockBatch] / [Unchunk48LockBatch]) are selected. The kernels
// are plain BMI2 (PEXTQ / PDEPQ with memory mask operands, scalar
// loads and stores), so every BMI2-capable host benefits from the
// amortised Go-loop overhead removal.
var HasChunk48Batch = cpu.X86.HasBMI2

// Chunk48LockBatch applies [Chunk48Lock] to n = len(masks) consecutive
// chunks in one kernel call. Chunk j is the six little-endian bytes
// src[6j : 6j+6]; its lane outputs are stored little-endian at
// p0[2j : 2j+2], p1[2j : 2j+2], p2[2j : 2j+2]. Bit-exact with n
// per-chunk Chunk48Lock calls followed by the caller-side uint16
// little-endian serialisation.
//
// Panics if src is shorter than 6n bytes or any lane buffer is shorter
// than 2n bytes. The kernel reads exactly src[0 : 6n] and writes
// exactly p_i[0 : 2n]. Caller gates on [HasChunk48Batch].
func Chunk48LockBatch(src []byte, masks [][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	src = src[:6*n]
	p0, p1, p2 = p0[:2*n], p1[:2*n], p2[:2*n]
	chunk48LockBatch(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
}

// Unchunk48LockBatch applies [Unchunk48Lock] to n = len(masks)
// consecutive chunks in one kernel call. Lane values for chunk j are
// read little-endian from p0[2j : 2j+2], p1[2j : 2j+2], p2[2j : 2j+2];
// the recovered chunk is written as six little-endian bytes to
// dst[6j : 6j+6]. Bit-exact with n per-chunk Unchunk48Lock calls
// followed by the caller-side six-byte little-endian store.
//
// Panics if dst is shorter than 6n bytes or any lane buffer is shorter
// than 2n bytes. The kernel writes exactly dst[0 : 6n] and reads
// exactly p_i[0 : 2n]. Caller gates on [HasChunk48Batch].
func Unchunk48LockBatch(p0, p1, p2 []byte, masks [][3]uint64, dst []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	dst = dst[:6*n]
	p0, p1, p2 = p0[:2*n], p1[:2*n], p2[:2*n]
	unchunk48LockBatch(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
}

//go:noescape
func chunk48LockBatch(n int, src *byte, masks *[3]uint64, p0, p1, p2 *byte)

//go:noescape
func unchunk48LockBatch(n int, masks *[3]uint64, p0, p1, p2 *byte, dst *byte)
