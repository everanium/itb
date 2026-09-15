//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/cpu"
)

// HasSVE2Interlock selects the SVE2 BEXT / BDEP batched chunk-apply
// kernels ([chunk48LockBatchSVE2] / [unchunk48LockBatchSVE2]). The two
// instructions belong to the optional SVE2 bit-permute extension
// (FEAT_SVE_BitPerm), so the gate requires both the SVE2 base flag and
// the Linux HWCAP2 bit-permute bit; hosts without either (Neoverse V1
// with SVE only, NEON-only cores, non-Linux kernels) keep the software
// batched loop.
var HasSVE2Interlock = cpu.ARM64.HasSVE2 && hasSVEBitPerm()

// hwcap2SVEBitPerm is the Linux AT_HWCAP2 bit for FEAT_SVE_BitPerm
// (arch/arm64/include/uapi/asm/hwcap.h: HWCAP2_SVEBITPERM).
const hwcap2SVEBitPerm = 1 << 4

// hasSVEBitPerm reads AT_HWCAP2 from the process auxiliary vector. Any
// failure (non-Linux host, unreadable auxv) reports false, which keeps
// the SVE2 arm deselected.
func hasSVEBitPerm() bool {
	const atHWCAP2 = 26
	buf, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return false
	}
	for i := 0; i+16 <= len(buf); i += 16 {
		if binary.LittleEndian.Uint64(buf[i:]) == atHWCAP2 {
			return binary.LittleEndian.Uint64(buf[i+8:])&hwcap2SVEBitPerm != 0
		}
	}
	return false
}

//go:noescape
func chunk48LockBatchSVE2(n int, src *byte, masks *[3]uint64, p0, p1, p2 *byte)

//go:noescape
func unchunk48LockBatchSVE2(n int, masks *[3]uint64, p0, p1, p2 *byte, dst *byte)
