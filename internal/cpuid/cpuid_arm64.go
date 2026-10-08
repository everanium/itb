//go:build arm64

package cpuid

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/cpu"
)

func init() {
	ASIMD = cpu.ARM64.HasASIMD
	ARMAES = cpu.ARM64.HasAES
	SVE2BitPerm = cpu.ARM64.HasSVE2 && hasSVEBitPerm()
}

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
