//go:build arm64 && !purego && !noitbasm

package interlock

import "github.com/everanium/itb/internal/cpuid"

// HasSVE2Interlock selects the SVE2 BEXT / BDEP batched chunk-apply
// kernels ([chunk48LockBatchSVE2] / [unchunk48LockBatchSVE2]). The two
// instructions belong to the optional SVE2 bit-permute extension
// (FEAT_SVE_BitPerm), so the gate ([cpuid.SVE2BitPerm]) requires both
// the SVE2 base flag and the Linux HWCAP2 bit-permute bit; hosts
// without either (Neoverse V1 with SVE only, NEON-only cores, non-Linux
// kernels) keep the software batched loop.
var HasSVE2Interlock = cpuid.SVE2BitPerm

//go:noescape
func chunk48LockBatchSVE2(n int, src *byte, masks *[3]uint64, p0, p1, p2 *byte)

//go:noescape
func unchunk48LockBatchSVE2(n int, masks *[3]uint64, p0, p1, p2 *byte, dst *byte)
