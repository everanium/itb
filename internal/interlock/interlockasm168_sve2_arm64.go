//go:build arm64 && !purego && !noitbasm

package interlock

//go:noescape
func chunk168LockBatchSVE2(n int, src *byte, masks *[3][3]uint64, p0, p1, p2 *byte)

//go:noescape
func unchunk168LockBatchSVE2(n int, masks *[3][3]uint64, p0, p1, p2 *byte, dst *byte)
