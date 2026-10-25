//go:build amd64 && !purego && !noitbasm

package interlock

import "github.com/everanium/itb/internal/cpuid"

// HasChunk168Batch caches whether the batched 168-bit chunk-apply
// kernels ([Chunk168LockBatch] / [Unchunk168LockBatch]) are selected.
// The kernels use BMI2 PEXTQ / PDEPQ and POPCNTQ, so every BMI2-capable
// host benefits from the amortised loop overhead removal.
var HasChunk168Batch = cpuid.BMI2

// Chunk168LockBatch applies [Chunk168Lock] to n = len(masks)
// consecutive 21-byte chunks in one kernel call. Chunk j is read from
// src[21j : 21j+21]; its three 7-byte (56-bit) lane outputs are stored
// little-endian at p0[7j : 7j+7], p1[7j : 7j+7], p2[7j : 7j+7].
//
// Panics if src is shorter than 21n bytes or any lane buffer is shorter
// than 7n bytes. The kernel reads exactly src[0 : 21n] and writes
// exactly p_i[0 : 7n]. Caller gates on [HasChunk168Batch].
func Chunk168LockBatch(src []byte, masks [][3][3]uint64, p0, p1, p2 []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	_ = src[21*n-1]
	_ = p0[7*n-1]
	_ = p1[7*n-1]
	_ = p2[7*n-1]
	chunk168LockBatch(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
}

// Unchunk168LockBatch applies [Unchunk168Lock] to n = len(masks)
// consecutive chunks in one kernel call. Lane values for chunk j are
// read little-endian from p0[7j : 7j+7], p1[7j : 7j+7], p2[7j : 7j+7];
// the recovered 21-byte chunk is written little-endian to
// dst[21j : 21j+21].
//
// Panics if dst is shorter than 21n bytes or any lane buffer is shorter
// than 7n bytes. The kernel writes exactly dst[0 : 21n] and reads
// exactly p_i[0 : 7n]. Caller gates on [HasChunk168Batch].
func Unchunk168LockBatch(p0, p1, p2 []byte, masks [][3][3]uint64, dst []byte) {
	n := len(masks)
	if n == 0 {
		return
	}
	_ = dst[21*n-1]
	_ = p0[7*n-1]
	_ = p1[7*n-1]
	_ = p2[7*n-1]
	unchunk168LockBatch(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
}

//go:noescape
func chunk168LockBatch(n int, src *byte, masks *[3][3]uint64, p0, p1, p2 *byte)

//go:noescape
func unchunk168LockBatch(n int, masks *[3][3]uint64, p0, p1, p2 *byte, dst *byte)
